import {
  Inject,
  Injectable,
  Logger,
  type OnModuleDestroy,
  type OnModuleInit,
} from "@nestjs/common";
import { ConnectionManager, masterClient } from "@compliance-kit/db";
import {
  LocalKeyProvider,
  importSigningKey,
  importVerificationKey,
  publicJwkMatchesPrivateKey,
  toJwks,
  type EncryptionKeyResolver,
  type Jwks,
  type KeyProvider,
  type CryptoKey,
  type JWK,
  type SigningKeyResolver,
  type TokenMaterial,
} from "@compliance-kit/crypto";
import type { AppConfig } from "@compliance-kit/config";
import { CONFIG, CONNECTION_MANAGER } from "../core/tokens";

/**
 * Owns the key lifecycle: loads `config_keys` from the master database, unwraps the material with
 * the KEK, and hands the token codec what it needs.
 *
 * Everything here exists to keep two properties true at once.
 *
 * The codec's resolvers must be SYNCHRONOUS, because jose calls them with an attacker-controlled
 * `kid` before anything has been verified. So this service keeps an in-memory snapshot and the
 * resolvers only ever read it. No request path awaits a query or a KMS unwrap on the strength of an
 * unverified header.
 *
 * But a key added or revoked by an operator has to become effective without a restart. So the
 * snapshot is refreshed on a cooldown-limited miss: an unrecognised kid triggers at most one reload
 * per `REFRESH_COOLDOWN_MS`, which is the same shape jose's own `createRemoteJWKSet` uses for remote
 * JWKS. That bounds the amplification a forged kid can cause to one query per cooldown window,
 * rather than one per request.
 *
 * The refresh is deliberately NOT visible to the resolvers. `TokenService.verify` calls
 * `refreshIfStale()` itself, between a failed verification and its one retry, so the resolvers handed
 * to jose never await anything and stay synchronous.
 */

/** At most one reload per window, however many unknown kids arrive. */
const REFRESH_COOLDOWN_MS = 30_000;

/**
 * How often the snapshot is reloaded regardless of traffic.
 *
 * Refresh-on-miss alone is not enough, and this was found by rotating keys against a running server
 * rather than by reasoning: after `pnpm keys:rotate` the instance carried on signing with the key it
 * had loaded at boot and published a JWKS with only that key, because nothing had FAILED. A miss only
 * happens for a kid the snapshot does not know, and a stale-but-still-valid active key produces no
 * misses at all. So rotation silently did not take effect until a restart.
 *
 * A periodic reload bounds that staleness to one interval on every instance, with no operator action
 * and no coordination between instances. LISTEN/NOTIFY would make it immediate, at the cost of a
 * dedicated connection per instance and a reconnect path to get wrong; a minute of staleness on a
 * key rotation is an acceptable trade, and the retiring key stays valid for the whole overlap anyway.
 */
const REFRESH_INTERVAL_MS = 60_000;

interface LoadedSigningKey {
  kid: string;
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  publicJwk: JWK;
  state: masterClient.$Enums.KeyState;
  notAfter: Date | null;
}

interface LoadedEncryptionKey {
  kid: string;
  secret: Uint8Array;
  state: masterClient.$Enums.KeyState;
  notAfter: Date | null;
}

/** The columns of a `config_keys` row that loading reads. */
interface KeyRow {
  kid: string;
  purpose: masterClient.$Enums.KeyPurpose;
  state: masterClient.$Enums.KeyState;
  wrappedKey: Uint8Array | null;
  kekId: string;
  publicJwk: unknown;
  notAfter: Date | null;
}

interface Snapshot {
  signing: Map<string, LoadedSigningKey>;
  encryption: Map<string, LoadedEncryptionKey>;
  activeSigningKid: string | undefined;
  activeEncryptionKid: string | undefined;
}

const EMPTY: Snapshot = {
  signing: new Map(),
  encryption: new Map(),
  activeSigningKid: undefined,
  activeEncryptionKid: undefined,
};

export class NoActiveKeyError extends Error {
  constructor(purpose: string) {
    super(
      `No active ${purpose} key. Run \`pnpm keys:init\` to create the deployment's first key set.`,
    );
    this.name = "NoActiveKeyError";
  }
}

@Injectable()
export class KeyRegistryService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(KeyRegistryService.name);
  private readonly provider: KeyProvider;
  private snapshot: Snapshot = EMPTY;
  private lastRefreshAt = 0;
  private inFlight: Promise<void> | undefined;
  private timer: NodeJS.Timeout | undefined;

  constructor(
    @Inject(CONFIG) private readonly config: AppConfig,
    @Inject(CONNECTION_MANAGER) private readonly cm: ConnectionManager,
  ) {
    this.provider = new LocalKeyProvider(
      new Uint8Array(Buffer.from(config.keyEncryptionKey, "base64url")),
    );
  }

  /**
   * Load once at boot so the first request does not pay for it, and so a deployment with no keys
   * fails loudly at startup rather than on a user's first login.
   */
  async onModuleInit(): Promise<void> {
    await this.refresh();

    // unref so the interval never holds the process open: without it a CLI or a test that
    // constructs this service would hang for a minute at exit.
    this.timer = setInterval(() => {
      void this.refresh();
    }, REFRESH_INTERVAL_MS);
    this.timer.unref();

    if (!this.snapshot.activeSigningKid || !this.snapshot.activeEncryptionKid) {
      this.logger.error(
        "No active token keys in config_keys. Every login and every token verification will " +
          "fail until `pnpm keys:init` has been run against this deployment's master database.",
      );
    }
  }

  onModuleDestroy(): void {
    if (this.timer) clearInterval(this.timer);
  }

  /**
   * Resolvers for the codec. Synchronous, closed over the current snapshot. See the class comment
   * for why that is not negotiable.
   */
  resolvers(): { signing: SigningKeyResolver; encryption: EncryptionKeyResolver } {
    return {
      signing: (kid) => {
        const key = this.snapshot.signing.get(kid);
        return key && this.usable(key.state, key.notAfter) ? key.publicKey : undefined;
      },
      encryption: (kid) => {
        const key = this.snapshot.encryption.get(kid);
        return key && this.usable(key.state, key.notAfter) ? key.secret : undefined;
      },
    };
  }

  /** The material to sign and encrypt a new token with. Throws if the deployment has no keys. */
  activeMaterial(): TokenMaterial {
    const signingKid = this.snapshot.activeSigningKid;
    const encryptionKid = this.snapshot.activeEncryptionKid;
    if (!signingKid) throw new NoActiveKeyError("token_signing");
    if (!encryptionKid) throw new NoActiveKeyError("token_encryption");

    const signing = this.snapshot.signing.get(signingKid);
    const encryption = this.snapshot.encryption.get(encryptionKid);
    if (!signing) throw new NoActiveKeyError("token_signing");
    if (!encryption) throw new NoActiveKeyError("token_encryption");

    return {
      signing: { kid: signing.kid, key: signing.privateKey },
      encryption: { kid: encryption.kid, key: encryption.secret },
    };
  }

  /**
   * The public JWKS.
   *
   * Includes RETIRING keys, deliberately. During a rotation overlap, tokens signed by the previous
   * key are still valid until they expire, so a JWKS that dropped the old key the moment a new one
   * went active would invalidate every live token rather than rotating gracefully. Excludes pending
   * keys (nothing has been signed with them) and revoked keys (nothing signed with them should be
   * accepted).
   */
  jwks(): Jwks {
    const publishable = [...this.snapshot.signing.values()]
      .filter((k) => k.state === "active" || k.state === "retiring")
      .filter((k) => this.usable(k.state, k.notAfter))
      .map((k) => k.publicJwk);
    return toJwks(publishable);
  }

  /**
   * Reload if a kid was not recognised, at most once per cooldown window.
   *
   * Called by `TokenService.verify` after a verification failure and before its single retry. The
   * important part is not *when* but *where from*: never inside a resolver, because a resolver that
   * awaited would make an unverified `kid` able to trigger a query. Concurrent callers share one
   * in-flight reload rather than stampeding.
   *
   * Note that a failure is not the only thing that triggers a reload. It cannot be, because a stale
   * snapshot whose active key is still valid produces no failures at all; see REFRESH_INTERVAL_MS.
   */
  async refreshIfStale(): Promise<void> {
    if (this.inFlight) return this.inFlight;
    if (Date.now() - this.lastRefreshAt < REFRESH_COOLDOWN_MS) return;
    this.inFlight = this.refresh().finally(() => {
      this.inFlight = undefined;
    });
    return this.inFlight;
  }

  /** True when a key may still be used, honouring `not_after` at the point of use. */
  private usable(state: masterClient.$Enums.KeyState, notAfter: Date | null): boolean {
    if (state === "revoked" || state === "pending") return false;
    // Checked here rather than trusted to a sweeper. A sweeper that has not run yet, or that
    // failed, would otherwise leave an expired key verifying tokens indefinitely.
    if (notAfter && notAfter.getTime() <= Date.now()) return false;
    return true;
  }

  private async refresh(): Promise<void> {
    this.lastRefreshAt = Date.now();
    let rows: KeyRow[];
    try {
      rows = await this.cm.master.configKey.findMany({
        // Revoked rows are kept as evidence but hold no material, so there is nothing to load.
        where: { state: { in: ["active", "retiring"] } },
      });
    } catch (err) {
      // Keep serving with the previous snapshot rather than dropping every key because the database
      // blipped. Failing closed here would turn a transient master-database outage into a total
      // authentication outage, and the keys we already hold are still valid.
      this.logger.error(
        `Could not refresh the key registry, continuing with the previous snapshot: ` +
          `${err instanceof Error ? err.message : String(err)}`,
      );
      return;
    }

    const next: Snapshot = {
      signing: new Map(),
      encryption: new Map(),
      activeSigningKid: undefined,
      activeEncryptionKid: undefined,
    };

    // One row at a time, so a row that cannot be loaded costs that key and not every key. This used to
    // be one try around the whole loop, and one bad row (a key wrapped under a previous KEK, a corrupted
    // blob) threw out of it, so the refresh loaded NOTHING: at boot that is a deployment with no keys at
    // all, and at runtime a snapshot that stops following rotations. Unlike a database outage, a row
    // failing here is not transient (unwrapping is deterministic), so the snapshot is replaced without it
    // rather than kept: if that key was tampered with, it should stop being used, loudly.
    for (const row of rows) {
      if (!row.wrappedKey) continue;
      // `kek_id` exists so a deployment can tell which rows it is able to unwrap. Checked rather than
      // discovered by a failed unwrap, so the log names the actual cause.
      if (row.kekId !== this.provider.id) {
        this.logger.error(
          `Key ${row.kid} (${row.purpose}) was wrapped by key-encrypting key "${row.kekId}", and this ` +
            `process holds "${this.provider.id}", so the key is not loaded.`,
        );
        continue;
      }
      try {
        await this.loadRow(row, next);
      } catch (err) {
        this.logger.error(
          `Could not load key ${row.kid} (${row.purpose}), so it is not in use: ` +
            `${err instanceof Error ? err.message : String(err)}`,
        );
      }
    }

    this.snapshot = next;
    this.logger.log(
      `Loaded ${next.signing.size} signing and ${next.encryption.size} encryption key(s)`,
    );
  }

  /** Unwrap one row into `next`. Throws when the row cannot be trusted, which skips that key only. */
  private async loadRow(row: KeyRow, next: Snapshot): Promise<void> {
    const material = await this.provider.unwrap(new Uint8Array(row.wrappedKey ?? []), {
      purpose: row.purpose,
      kid: row.kid,
    });

    if (row.purpose === "token_signing") {
      if (!row.publicJwk) throw new Error("the signing key has no public JWK to verify with");
      const publicJwk = row.publicJwk as JWK;
      const privatePkcs8 = new TextDecoder().decode(material);
      // The public half verifies tokens and is published in the JWKS, but it is stored in the clear,
      // so it is only trusted once shown to belong to the private half the KEK protects. See
      // publicJwkMatchesPrivateKey for what skipping this would allow.
      if (!(await publicJwkMatchesPrivateKey(privatePkcs8, publicJwk))) {
        throw new Error(
          "its stored public JWK is not the public half of its wrapped private key, so the column " +
            "may have been replaced; refusing to verify or publish with it",
        );
      }
      next.signing.set(row.kid, {
        kid: row.kid,
        privateKey: await importSigningKey(privatePkcs8),
        publicKey: await importVerificationKey(publicJwk),
        publicJwk,
        state: row.state,
        notAfter: row.notAfter,
      });
      if (row.state === "active") next.activeSigningKid = row.kid;
    } else {
      next.encryption.set(row.kid, {
        kid: row.kid,
        secret: material,
        state: row.state,
        notAfter: row.notAfter,
      });
      if (row.state === "active") next.activeEncryptionKid = row.kid;
    }
  }
}
