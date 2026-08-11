-- Grants for the RESTRICTED role the service should connect as in a real deployment.
--
-- WHAT THIS IS FOR. `audit-immutability.sql` installs three layers, and its own comments admit that
-- the third one is inert in the default setup: `REVOKE UPDATE, DELETE, TRUNCATE ... FROM PUBLIC` only
-- bites for a role that is neither a superuser nor the table's owner, and out of the box the service
-- connects as the role that owns everything. The immutability probe says the same thing about its own
-- REVOKE check, in as many words: it catches a stray GRANT and does not confirm the REVOKE. This file
-- is what turns that layer from documentation of intent into an enforced boundary.
--
-- With this applied and the service connecting as `crbk_app`, an UPDATE on audit_events fails with
-- SQLSTATE 42501 (insufficient_privilege) BEFORE the trigger is consulted. Two independent mechanisms
-- then have to be defeated instead of one, and the privilege layer keeps working if a trigger is ever
-- dropped, which is the scenario the trigger cannot defend against by construction.
--
-- WHAT IT DELIBERATELY DOES NOT DO: create the role. `CREATE ROLE crbk_app LOGIN PASSWORD '...'` needs
-- a credential, and no file in this repository is allowed to contain one. Create the role and set its
-- password out of band (your secret manager, your provisioning tool), then run this. See
-- docs/deployment.md.
--
-- Apply as the OWNER of the tables, once per database: the master, and each tenant database.
--   psql "$MASTER_DATABASE_URL" -f packages/db/sql/restricted-role.sql
--
-- The role name is fixed rather than parameterised, because a SQL file cannot take an argument without
-- either psql-specific syntax or string interpolation, and interpolating an identifier into GRANT is
-- how injection gets into an operational script. If you need a different name, change it here.

-- ---------------------------------------------------------------------------
-- Fail loudly if the role does not exist yet, rather than granting nothing and reporting success.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'crbk_app') THEN
    RAISE EXCEPTION
      'role crbk_app does not exist. Create it first (CREATE ROLE crbk_app LOGIN, then \password '
      'crbk_app in psql so the secret never reaches your shell history). See docs/deployment.md.';
  END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- Refuse to run at all if the grants below would be decorative.
--
-- This is the check that keeps the file honest, and it was missing until review pointed it out. A
-- table OWNER implicitly keeps UPDATE, DELETE and TRUNCATE no matter what is revoked, and a superuser
-- ignores privileges entirely. In either case every statement here would succeed, the operator would
-- see a clean run, and the privilege boundary would not exist. A script that reports success while
-- enforcing nothing is worse than one that fails, because the failure is the only signal available.
--
-- Owning `audit_events` is not a hypothetical for this role either: it is what happens if crbk_app is
-- ever handed CREATEDB and allowed to provision a tenant, since whoever creates the tables owns them.
-- That is the exact trade-off documented in docs/deployment.md, and this is where it gets caught.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
  owner_name text;
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'crbk_app' AND rolsuper) THEN
    RAISE EXCEPTION
      'crbk_app is a SUPERUSER, so privileges do not apply to it and every grant in this file would '
      'be decorative. Recreate it without SUPERUSER.';
  END IF;

  IF to_regclass('public.audit_events') IS NOT NULL THEN
    SELECT pg_get_userbyid(relowner) INTO owner_name
      FROM pg_class WHERE oid = 'public.audit_events'::regclass;

    IF owner_name = 'crbk_app' THEN
      RAISE EXCEPTION
        'crbk_app OWNS audit_events in this database, and an owner keeps UPDATE, DELETE and TRUNCATE '
        'regardless of REVOKE. The append-only boundary cannot be enforced against the owner. Apply '
        'this file as a different role that owns the tables, or reassign ownership. See '
        'docs/deployment.md on why provisioning and serving want different privileges.';
    END IF;
  END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO crbk_app;

-- ---------------------------------------------------------------------------
-- The ordinary tables: full DML, because the service legitimately mutates them.
--
-- Listed one by one rather than with GRANT ... ON ALL TABLES, and that is the entire point of this
-- file. `ON ALL TABLES` would include audit_events and hand it UPDATE and DELETE, producing a setup
-- that looks restricted, passes a casual review, and enforces nothing on the one table where it
-- matters. A new table added later gets no privileges until someone adds it here, which is the correct
-- failure direction: a query that errors is louder than an audit log that can be rewritten.
-- ---------------------------------------------------------------------------

-- Master (control plane). Guarded so this same file can be applied to a tenant database, where these
-- tables do not exist.
DO $$
BEGIN
  IF to_regclass('public.tenants') IS NOT NULL THEN
    GRANT SELECT, INSERT, UPDATE, DELETE ON public.tenants TO crbk_app;
  END IF;
  IF to_regclass('public.global_config') IS NOT NULL THEN
    GRANT SELECT, INSERT, UPDATE, DELETE ON public.global_config TO crbk_app;
  END IF;
  -- config_keys holds WRAPPED key material. The service reads it on every registry refresh and writes
  -- it during rotation, so DML is required; the protection on this table is the KEK, the CHECK
  -- constraints and the partial unique index, not the grant.
  IF to_regclass('public.config_keys') IS NOT NULL THEN
    GRANT SELECT, INSERT, UPDATE, DELETE ON public.config_keys TO crbk_app;
  END IF;

  -- Tenant (data plane).
  IF to_regclass('public.users') IS NOT NULL THEN
    GRANT SELECT, INSERT, UPDATE, DELETE ON public.users TO crbk_app;
  END IF;
  IF to_regclass('public.roles') IS NOT NULL THEN
    GRANT SELECT, INSERT, UPDATE, DELETE ON public.roles TO crbk_app;
  END IF;
  IF to_regclass('public.permissions') IS NOT NULL THEN
    GRANT SELECT, INSERT, UPDATE, DELETE ON public.permissions TO crbk_app;
  END IF;
  IF to_regclass('public.role_permissions') IS NOT NULL THEN
    GRANT SELECT, INSERT, UPDATE, DELETE ON public.role_permissions TO crbk_app;
  END IF;
  IF to_regclass('public.user_roles') IS NOT NULL THEN
    GRANT SELECT, INSERT, UPDATE, DELETE ON public.user_roles TO crbk_app;
  END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- audit_events: APPEND AND READ ONLY. This is the line the whole file exists for.
-- ---------------------------------------------------------------------------
GRANT SELECT, INSERT ON public.audit_events TO crbk_app;

-- Explicit, even though the GRANT above never included them. A previous operator running
-- `GRANT ALL ON ALL TABLES`, which is the most natural way to get an application working in a hurry,
-- would have handed over exactly these three. Revoking unconditionally makes this file idempotent and
-- safe to re-run over a database whose history nobody remembers.
REVOKE UPDATE, DELETE, TRUNCATE ON public.audit_events FROM crbk_app;

-- The seq column is a serial, so INSERT needs its sequence. USAGE covers nextval and is the narrowest
-- privilege that works: SELECT and UPDATE on a sequence are not required to append.
--
-- Scoped to THAT ONE SEQUENCE rather than `ON ALL SEQUENCES IN SCHEMA public`, which review flagged as
-- broader than necessary and which would silently pick up every sequence added later. Every other id
-- in both schemas is a gen_random_uuid() default, so audit_events.seq is the only sequence in play.
-- pg_get_serial_sequence resolves the name rather than hardcoding audit_events_seq_seq, so a rename
-- upstream cannot leave this granting nothing while still reporting success.
DO $$
DECLARE
  seq_name text;
BEGIN
  IF to_regclass('public.audit_events') IS NOT NULL THEN
    seq_name := pg_get_serial_sequence('public.audit_events', 'seq');
    IF seq_name IS NULL THEN
      RAISE EXCEPTION
        'audit_events.seq has no owned sequence, so INSERT would fail for crbk_app. The column type '
        'changed and this file needs updating.';
    END IF;
    EXECUTE format('GRANT USAGE ON SEQUENCE %s TO crbk_app', seq_name);
  END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- NOT GRANTED, each for a reason worth reading before "fixing" it.
--
--   CREATEDB    The service calls CREATE DATABASE at runtime to provision a tenant, so a role without
--               CREATEDB cannot provision. That is a genuine conflict rather than an oversight, and it
--               is discussed in docs/deployment.md: provisioning and serving want different privileges,
--               and this kit currently reaches both through one TENANT_CLUSTER_URL. Granting CREATEDB
--               here would resolve the conflict by discarding the control.
--   DDL         No CREATE on the schema. The role cannot add, alter or drop a table, which is what
--               makes it unable to drop the immutability triggers. Migrations run as the owner, from
--               the migrator image.
--   TRUNCATE    On any table. It is the one DML-shaped statement that row triggers cannot see.
-- ---------------------------------------------------------------------------
