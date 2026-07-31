-- Integrity rules for audit_events, in Postgres rather than in application code: append-only
-- enforcement, plus the constraints that keep a row well formed enough to verify.
--
-- Applied to EVERY database that carries a chain: each tenant database at provisioning time, and the
-- master database by its migration. Written once and used in both places, because two copies of a
-- security control eventually disagree and the drift is invisible until someone tries to modify a row
-- and succeeds.
--
-- THREE LAYERS, and each covers a hole the others leave.
--
--   1. A row-level trigger on UPDATE and DELETE. Fires for every role including superusers, which is
--      what makes it the strongest of the three in this kit's default setup, where the service and the
--      migrations connect as the same privileged role.
--
--   2. A STATEMENT-level trigger on TRUNCATE. Row triggers do not fire for TRUNCATE at all: it is a
--      DDL-ish operation that deallocates the underlying files without visiting rows. Relying on the
--      row trigger alone would leave `TRUNCATE audit_events` as a one-statement way to erase the
--      entire log, which is precisely the operation an attacker covering their tracks would reach for.
--
--   3. REVOKE of UPDATE, DELETE and TRUNCATE. Belt to the trigger's braces, and the layer that keeps
--      working if a trigger is ever dropped. It only bites for a role that is not the table owner and
--      not a superuser, so in the default single-role setup it is documentation of intent; in a
--      deployment that runs the service as a restricted role, which is what the comments in
--      ConnectionManager recommend, it becomes the real boundary.
--
-- WHAT THIS DOES NOT DO, stated plainly because COMPLIANCE.md must not overclaim it. A superuser can
-- `ALTER TABLE ... DISABLE TRIGGER ALL`, or set `session_replication_role = 'replica'` to skip triggers
-- for their session, or simply `DROP TRIGGER`. So this is enforcement against the application, against
-- an ordinary compromise of the service, and against an operator's mistake. It is NOT enforcement
-- against someone holding superuser on the database.
--
-- Two things close that remaining gap, and neither belongs in this file: restrict who holds superuser,
-- and ship the head hash off the box, so that a rewrite which succeeds locally still fails to match
-- the value recorded elsewhere. See `pnpm audit:verify` and the roadmap note on external anchoring.

CREATE OR REPLACE FUNCTION audit_events_reject_mutation() RETURNS trigger AS $$
BEGIN
  -- The message names the table and the operation, because this fires at the moment someone is
  -- surprised, and "permission denied" without a reason sends them looking in the wrong place.
  RAISE EXCEPTION
    'audit_events is append-only: % is not permitted', TG_OP
    USING
      ERRCODE = 'restrict_violation',
      HINT = 'Audit events are immutable evidence. Append a correcting event instead of editing one; '
             'the hash chain is verified by `pnpm audit:verify` and any edit breaks it.';
END;
$$ LANGUAGE plpgsql;

-- FOR EACH ROW so the exception names the operation for the row that triggered it. BEFORE, so the
-- statement is refused rather than performed and rolled back.
DROP TRIGGER IF EXISTS audit_events_no_update ON audit_events;
CREATE TRIGGER audit_events_no_update
  BEFORE UPDATE ON audit_events
  FOR EACH ROW EXECUTE FUNCTION audit_events_reject_mutation();

DROP TRIGGER IF EXISTS audit_events_no_delete ON audit_events;
CREATE TRIGGER audit_events_no_delete
  BEFORE DELETE ON audit_events
  FOR EACH ROW EXECUTE FUNCTION audit_events_reject_mutation();

-- FOR EACH STATEMENT is not a style choice here: TRUNCATE triggers cannot be per-row, because TRUNCATE
-- never visits rows. This is the layer that stops the whole log being erased in one statement.
DROP TRIGGER IF EXISTS audit_events_no_truncate ON audit_events;
CREATE TRIGGER audit_events_no_truncate
  BEFORE TRUNCATE ON audit_events
  FOR EACH STATEMENT EXECUTE FUNCTION audit_events_reject_mutation();

-- INSERT and SELECT remain, which is the entire intended surface: append and read.
REVOKE UPDATE, DELETE, TRUNCATE ON audit_events FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- Constraints that make the chain's construction rules self-enforcing.
--
-- The application already refuses to build a malformed event: computeAuditHash throws on a prev_hash
-- that is not 32 bytes, and the AuditMetadata type restricts metadata to string values. Neither of
-- those reaches the database, so until now a writer bug, a migration, or a hand-written INSERT could
-- store a row that no amount of care elsewhere would catch.
--
-- That failure mode is worse than it first looks, because it does not present as corruption. It
-- presents as TAMPERING: a 16-byte prev_hash makes the verifier throw rather than report, and metadata
-- containing a number comes back from jsonb rewritten (1e2 as 100), so the recomputed hash differs and
-- the chain reads as broken. Someone investigating a genuine incident would be handed a false positive
-- at exactly the moment they most need to trust the tool. Same reasoning as the CHECK constraints on
-- config_keys: an invariant the application believes in belongs where it cannot be bypassed.

-- Exactly SHA-256 width, on both links. Not "at most": a shorter value is not a truncated hash, it is
-- a value that was never a hash.
ALTER TABLE audit_events DROP CONSTRAINT IF EXISTS audit_events_hash_width_ck;
ALTER TABLE audit_events ADD CONSTRAINT audit_events_hash_width_ck
  CHECK (octet_length(prev_hash) = 32 AND octet_length(hash) = 32);

/*
 * Metadata must be a flat object whose every value is a string.
 *
 * A function because a CHECK constraint cannot contain a subquery, and detecting a non-string value
 * requires iterating the object. Marked IMMUTABLE, which is what makes it legal in a CHECK: the result
 * depends only on the argument, so Postgres may cache and inline it.
 *
 * Rejecting nesting as well as non-string scalars is deliberate. A nested object would serialise into
 * the hash as whatever the canonical form happened to do with it, which is a rule nobody wrote down;
 * refusing it keeps the hashed shape exactly the shape the code describes.
 */
CREATE OR REPLACE FUNCTION audit_metadata_is_flat_strings(m jsonb) RETURNS boolean AS $fn$
  SELECT jsonb_typeof(m) = 'object'
     AND NOT EXISTS (
       SELECT 1 FROM jsonb_each(m) AS entry(key, value)
       WHERE jsonb_typeof(entry.value) <> 'string'
     );
$fn$ LANGUAGE sql IMMUTABLE;

ALTER TABLE audit_events DROP CONSTRAINT IF EXISTS audit_events_metadata_flat_ck;
ALTER TABLE audit_events ADD CONSTRAINT audit_events_metadata_flat_ck
  CHECK (audit_metadata_is_flat_strings(metadata));

/*
 * The actor_type and actor_id pairing, which encodes an honesty requirement rather than a data shape.
 *
 * A `user` event with no actor_id is evidence that records nothing about who acted, so it is refused.
 *
 * `control_plane` and `anonymous` are the reverse: they must carry NO actor_id. The control-plane
 * credential authenticates the BEARER and not a person, so any identifier written there would imply an
 * attribution the credential cannot support, and an audit trail that implies attribution it does not
 * have is worse than one that admits the gap. `anonymous` has nobody to name by definition.
 *
 * `system` is left free. The service acting on its own may reasonably identify a job or a migration.
 */
ALTER TABLE audit_events DROP CONSTRAINT IF EXISTS audit_events_actor_ck;
ALTER TABLE audit_events ADD CONSTRAINT audit_events_actor_ck
  CHECK (
    (actor_type = 'user' AND actor_id IS NOT NULL)
    OR (actor_type IN ('control_plane', 'anonymous') AND actor_id IS NULL)
    OR actor_type = 'system'
  );

-- An event with no action name is not queryable and not evidence of anything.
ALTER TABLE audit_events DROP CONSTRAINT IF EXISTS audit_events_action_ck;
ALTER TABLE audit_events ADD CONSTRAINT audit_events_action_ck
  CHECK (length(action) > 0);
