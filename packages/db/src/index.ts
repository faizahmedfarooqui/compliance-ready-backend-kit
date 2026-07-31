export {
  ConnectionManager,
  type ManagerOptions,
  type MasterDb,
  type ProvisionTenantInput,
  type TenantDb,
} from "./connection-manager";

export {
  seedTenantAdmin,
  type SeedTenantAdminInput,
  type SeedTenantAdminResult,
} from "./seed/seed-tenant-admin";

// The generated Prisma clients. Callers need these for model and input types, and for
// the `Prisma` namespace when narrowing known request errors.
export * as masterClient from "./generated/master/client";
export * as tenantClient from "./generated/tenant/client";

export {
  appendAuditEvent,
  type AppendAuditEvent,
  type AppendedAuditEvent,
  type AuditChainClient,
} from "./audit/audit-writer";
