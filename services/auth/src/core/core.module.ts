import { Global, Logger, Module, type OnApplicationShutdown, Inject } from "@nestjs/common";
import { APP_FILTER, APP_INTERCEPTOR } from "@nestjs/core";
import { loadConfig, type AppConfig } from "@compliance-kit/config";
import { ConnectionManager } from "@compliance-kit/db";
import { ProblemDetailsFilter } from "../common/problem-details.filter";
import { ResponseEnvelopeInterceptor } from "../common/response-envelope.interceptor";
import { CONFIG, CONNECTION_MANAGER } from "./tokens";

// NOTE: the tokens are deliberately NOT re-exported from this module. Import them from
// ./tokens instead. Re-exporting them here would let a provider satisfy `@Inject(CONFIG)` by
// importing this module, and since this module imports those providers, that is a cycle: the
// token evaluates to `undefined` at decorator time and Nest reports it as an unresolvable
// dependency at index [0] rather than as a circular import. Keeping the only path to a token
// through a file with no imports of its own is what makes that unrepresentable.

@Global()
@Module({
  providers: [
    { provide: CONFIG, useFactory: (): AppConfig => loadConfig() },
    {
      provide: CONNECTION_MANAGER,
      inject: [CONFIG],
      useFactory: (config: AppConfig) => {
        const logger = new Logger("ConnectionManager");
        return new ConnectionManager({
          masterUrl: config.masterDatabaseUrl,
          tenantClusterUrl: config.tenantClusterUrl,
          // Each live tenant holds its own pool, so this bound is per database, not
          // per process. Size it against the cluster's max_connections and the number
          // of tenants a single instance is expected to serve.
          maxConnectionsPerDatabase: 10,
          onPoolError: (err, databaseName) =>
            logger.error(`Idle connection error on "${databaseName}": ${err.message}`, err.stack),
        });
      },
    },
    // Registered through DI rather than app.useGlobalFilters(new ...) because the filter needs
    // CONFIG injected for the RFC 9457 `type` base URI.
    { provide: APP_FILTER, useClass: ProblemDetailsFilter },
    { provide: APP_INTERCEPTOR, useClass: ResponseEnvelopeInterceptor },
  ],
  exports: [CONFIG, CONNECTION_MANAGER],
})
export class CoreModule implements OnApplicationShutdown {
  constructor(@Inject(CONNECTION_MANAGER) private readonly cm: ConnectionManager) {}

  async onApplicationShutdown(): Promise<void> {
    await this.cm.close();
  }
}
