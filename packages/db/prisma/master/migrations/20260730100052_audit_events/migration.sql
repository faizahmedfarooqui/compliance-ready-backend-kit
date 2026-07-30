-- CreateEnum
CREATE TYPE "audit_actor_type" AS ENUM ('user', 'control_plane', 'system', 'anonymous');

-- CreateTable
CREATE TABLE "audit_events" (
    "seq" BIGSERIAL NOT NULL,
    "occurred_at" TIMESTAMPTZ(6) NOT NULL,
    "action" TEXT NOT NULL,
    "actor_type" "audit_actor_type" NOT NULL,
    "actor_id" TEXT,
    "resource_type" TEXT,
    "resource_id" TEXT,
    "trace_id" TEXT,
    "source_ip" TEXT,
    "metadata" JSONB NOT NULL DEFAULT '{}',
    "prev_hash" BYTEA NOT NULL,
    "hash" BYTEA NOT NULL,

    CONSTRAINT "audit_events_pkey" PRIMARY KEY ("seq")
);

-- CreateIndex
CREATE INDEX "audit_events_resource_idx" ON "audit_events"("resource_type", "resource_id", "seq" DESC);

-- CreateIndex
CREATE INDEX "audit_events_action_idx" ON "audit_events"("action", "occurred_at" DESC);

-- CreateIndex
CREATE UNIQUE INDEX "audit_events_prev_hash_unique" ON "audit_events"("prev_hash");

-- CreateIndex
CREATE UNIQUE INDEX "audit_events_hash_unique" ON "audit_events"("hash");

-- ---------------------------------------------------------------------------
-- Append-only enforcement.
--
-- INLINED rather than read from sql/audit-immutability.sql, even though that file is the source of
-- truth applied to every tenant database. A migration is replayed into a shadow database to detect
-- drift and must be self-contained: a migration that read a file from the working tree would produce
-- different results depending on what that file said at the time, which is the opposite of what a
-- migration is for. Keep the two in step when either changes; the master:migrate drift check will not
-- catch a divergence here because triggers are invisible to .
-- ---------------------------------------------------------------------------

-- Append-only enforcement for audit_events, in Postgres rather than in application code.
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
