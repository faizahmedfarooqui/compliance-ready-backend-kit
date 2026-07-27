import {
  type CallHandler,
  type ExecutionContext,
  Injectable,
  type NestInterceptor,
} from "@nestjs/common";
import { hasMeta, type ResponseMeta, type SuccessEnvelope } from "@compliance-kit/common";
import { map, type Observable } from "rxjs";

/**
 * Wraps every successful response as `{ success, data, meta }`.
 *
 * Handlers return bare resources and this adds the envelope, so no controller has to remember
 * the shape and none of them can get it wrong. A handler that needs to say more returns
 * `withMeta(payload, { ... })`.
 *
 * Errors never pass through here. A thrown exception bypasses interceptors and is rendered by
 * ProblemDetailsFilter as RFC 9457 Problem Details, which is why `success` is typed `true`
 * rather than `boolean`.
 */
@Injectable()
export class ResponseEnvelopeInterceptor<T> implements NestInterceptor<T, SuccessEnvelope<unknown>> {
  intercept(
    context: ExecutionContext,
    next: CallHandler<T>,
  ): Observable<SuccessEnvelope<unknown>> {
    return next.handle().pipe(
      map((payload) => {
        if (hasMeta(payload)) {
          return { success: true as const, data: payload.data, meta: payload.meta };
        }
        return { success: true as const, data: payload ?? null, meta: defaultMeta(payload) };
      }),
    );
  }
}

/**
 * `meta` is always present, even when empty, so clients never have to test for its existence.
 * A list response gets `totalCount` for free, since returning a bare array and separately
 * counting it is the most common reason a handler would have reached for `withMeta`.
 *
 * Note this is the length of the page returned, which equals the total only while no endpoint
 * paginates. The first paginated route must pass a real total via `withMeta`.
 */
function defaultMeta(payload: unknown): ResponseMeta {
  return Array.isArray(payload) ? { totalCount: payload.length } : {};
}
