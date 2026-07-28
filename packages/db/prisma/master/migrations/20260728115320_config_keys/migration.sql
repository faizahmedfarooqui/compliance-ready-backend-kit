-- CreateEnum
CREATE TYPE "key_purpose" AS ENUM ('token_signing', 'token_encryption');

-- CreateEnum
CREATE TYPE "key_state" AS ENUM ('pending', 'active', 'retiring', 'revoked');

-- CreateEnum
CREATE TYPE "key_algorithm" AS ENUM ('ES256', 'A256KW');

-- CreateTable
CREATE TABLE "config_keys" (
    "kid" TEXT NOT NULL,
    "purpose" "key_purpose" NOT NULL,
    "algorithm" "key_algorithm" NOT NULL,
    "state" "key_state" NOT NULL DEFAULT 'pending',
    "wrapped_key" BYTEA,
    "kek_id" TEXT NOT NULL,
    "public_jwk" JSONB,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "activated_at" TIMESTAMPTZ(6),
    "retiring_at" TIMESTAMPTZ(6),
    "not_after" TIMESTAMPTZ(6),
    "revoked_at" TIMESTAMPTZ(6),
    "revoked_reason" TEXT,
    "updated_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "config_keys_pkey" PRIMARY KEY ("kid")
);

-- CreateIndex
CREATE INDEX "config_keys_purpose_state_idx" ON "config_keys"("purpose", "state");

-- ---------------------------------------------------------------------------
-- Everything below is hand-written. Prisma's @@unique and @@index take no predicate and it has
-- no CHECK constraint syntax, so none of this is expressible in the schema. It lives here so
-- Prisma's shadow database reproduces it and it does not later read as drift.
--
-- These are the invariants that make config_keys a control instead of a convention. The same
-- reasoning as database-per-tenant: the database enforces it, so application code cannot forget.
-- ---------------------------------------------------------------------------

-- THE invariant of this table. "Only one active key per purpose" checked in application code is a
-- race between two operators, or two pods, in one maintenance window. As a partial unique index,
-- Postgres simply refuses the second row.
CREATE UNIQUE INDEX "config_keys_one_active_per_purpose"
  ON "config_keys" ("purpose") WHERE "state" = 'active';

-- purpose and algorithm are not independent, and a mismatched row is an algorithm-confusion
-- primitive: purpose='token_signing' with algorithm='A256KW' would offer 32 raw symmetric bytes to
-- a signature verification (RFC 8725 section 2.1). Neither a Prisma enum nor a foreign key can
-- express the pairing.
ALTER TABLE "config_keys" ADD CONSTRAINT "config_keys_purpose_algorithm_ck" CHECK (
  ("purpose" = 'token_signing'    AND "algorithm" = 'ES256') OR
  ("purpose" = 'token_encryption' AND "algorithm" = 'A256KW')
);

-- An asymmetric key must have a publishable half; a symmetric key must not have one. Belt and
-- braces for the JWKS filter: a NULL public_jwk on a signing key makes it unverifiable by anyone
-- but us, and a non-NULL one on an encryption key is a row the endpoint could accidentally publish.
ALTER TABLE "config_keys" ADD CONSTRAINT "config_keys_public_jwk_ck" CHECK (
  ("purpose" = 'token_signing'    AND "public_jwk" IS NOT NULL) OR
  ("purpose" = 'token_encryption' AND "public_jwk" IS NULL)
);

-- Usable key material exists exactly while the key is not revoked. Revoking is supposed to destroy
-- the material and keep the row as evidence, so a revoked row still holding its ciphertext means
-- the revocation did not actually happen.
ALTER TABLE "config_keys" ADD CONSTRAINT "config_keys_material_ck" CHECK (
  ("state" <> 'revoked' AND "wrapped_key" IS NOT NULL) OR
  ("state" =  'revoked' AND "wrapped_key" IS NULL AND "revoked_at" IS NOT NULL
                        AND "revoked_reason" IS NOT NULL)
);

-- A retiring key without an end to its overlap is a key that verifies forever, which is not a
-- rotation. Enforced here rather than trusted to the rotate command.
ALTER TABLE "config_keys" ADD CONSTRAINT "config_keys_retiring_not_after_ck" CHECK (
  "state" <> 'retiring' OR ("not_after" IS NOT NULL AND "retiring_at" IS NOT NULL)
);
