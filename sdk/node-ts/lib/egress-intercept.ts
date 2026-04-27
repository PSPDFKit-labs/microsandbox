/**
 * High-level egress interception API with Gondolin/mitmproxy-style hooks.
 *
 * Wraps the low-level `EgressStream` (from native Rust binding) with
 * `onRequest`/`onResponse` callback hooks.
 *
 * @example
 * ```ts
 * import { Sandbox } from 'microsandbox';
 * import { egressIntercept } from 'microsandbox/egress-intercept';
 *
 * const handle = await egressIntercept(sandbox, {
 *   onRequest: async (request, ctx) => {
 *     console.log(`→ ${request.method} ${request.uri} [${ctx.sni}]`);
 *     request.headers.push(["X-Trace-Id", "abc123"]);
 *     return request; // forward modified
 *   },
 *   onResponse: async (response, request, ctx) => {
 *     console.log(`← ${response.status} [${ctx.sni}]`);
 *     return undefined; // pass through
 *   },
 * });
 *
 * // ... do other work while interception is active ...
 *
 * await handle.stop();  // graceful shutdown
 * ```
 */

import type { EgressEvent, EgressHttpRequest, EgressHttpResponse } from "../index.d.cts";

/**
 * Connection metadata extracted from an {@link EgressEvent}.
 *
 * This is a convenience type — not a duplicate of a Rust binding type.
 * It groups the per-event metadata fields so hook signatures stay clean.
 */
export interface EgressContext {
  sni: string;
  dst: string;
  connectionId: number;
  timestampMs: number;
}

export interface EgressInterceptOptions {
  /**
   * Called for each outbound HTTP request.
   *
   * Return values:
   * - `undefined` → pass through unchanged
   * - `EgressHttpRequest` → forward modified request to server
   * - `EgressHttpResponse` → short-circuit (return response to guest, skip server)
   * - throw → block the connection
   */
  onRequest?: (
    request: EgressHttpRequest,
    ctx: EgressContext
  ) => Promise<EgressHttpRequest | EgressHttpResponse | undefined> | EgressHttpRequest | EgressHttpResponse | undefined;

  /**
   * Called for each server response.
   *
   * Return values:
   * - `undefined` → pass through unchanged
   * - `EgressHttpResponse` → forward modified response to guest
   * - throw → block the connection
   */
  onResponse?: (
    response: EgressHttpResponse,
    request: EgressHttpRequest | undefined,
    ctx: EgressContext
  ) => Promise<EgressHttpResponse | undefined> | EgressHttpResponse | undefined;
}

/**
 * Handle for a running egress interception loop.
 *
 * Returned by {@link egressIntercept}. The event loop runs in the
 * background. Use {@link stop} for graceful shutdown or await {@link done}
 * to wait for natural completion (e.g., sandbox stopped).
 */
export class EgressInterceptHandle {
  private _done: Promise<void>;
  private _stopped = false;

  /** @internal */
  constructor(donePromise: Promise<void>) {
    this._done = donePromise;
  }

  /** Promise that resolves when the intercept loop ends (sandbox stopped or {@link stop} called). */
  get done(): Promise<void> {
    return this._done;
  }

  /** Signal the intercept loop to stop after the current event. */
  stop(): Promise<void> {
    this._stopped = true;
    return this._done;
  }

  /** @internal */
  get stopped(): boolean {
    return this._stopped;
  }
}

/**
 * Check if a return value is a response (has `status` field) vs a request (has `method` field).
 */
function isResponse(value: any): value is EgressHttpResponse {
  return value && typeof value.status === "number";
}

/**
 * Start egress interception with callback hooks.
 *
 * Connects to the sandbox's egress socket and starts processing events
 * in the background. Returns an {@link EgressInterceptHandle} immediately.
 *
 * @param sandbox - A running `Sandbox` instance with `egressInterceptHosts` configured.
 * @param options - `onRequest` and/or `onResponse` callback hooks.
 * @returns A handle to control the interception loop.
 */
export async function egressIntercept(
  sandbox: any, // Sandbox type from native binding
  options: EgressInterceptOptions
): Promise<EgressInterceptHandle> {
  const stream = await sandbox.egressConnection();
  const lastRequests = new Map<number, EgressHttpRequest>();

  let resolveLoop!: () => void;
  const donePromise = new Promise<void>((resolve) => { resolveLoop = resolve; });
  const handle = new EgressInterceptHandle(donePromise);

  (async () => {
    try {
      while (!handle.stopped) {
        const event: EgressEvent | null = await stream.recv();
        if (event === null) break;

        const ctx: EgressContext = {
          sni: event.sni,
          dst: event.dst,
          connectionId: event.connectionId,
          timestampMs: event.timestampMs,
        };

        try {
          if (event.kind === "request" && event.request) {
            const request: EgressHttpRequest = event.request;
            lastRequests.set(event.connectionId, request);

            if (options.onRequest) {
              const result = await options.onRequest(request, ctx);

              if (result === undefined) {
                await stream.passThrough(event.id);
              } else if (isResponse(result)) {
                await stream.shortCircuit(event.id, result);
              } else {
                // Modified request
                lastRequests.set(event.connectionId, result);
                await stream.modifyRequest(event.id, result);
              }
            } else {
              await stream.passThrough(event.id);
            }
          } else if (event.kind === "response" && event.response) {
            const response: EgressHttpResponse = event.response;
            const originalRequest = lastRequests.get(event.connectionId);
            lastRequests.delete(event.connectionId);

            if (options.onResponse) {
              const result = await options.onResponse(response, originalRequest, ctx);

              if (result === undefined) {
                await stream.passThrough(event.id);
              } else {
                await stream.modifyResponse(event.id, result);
              }
            } else {
              await stream.passThrough(event.id);
            }
          } else {
            await stream.passThrough(event.id);
          }
        } catch {
          // Hook threw — block the connection
          await stream.block(event.id);
        }
      }
    } finally {
      resolveLoop();
    }
  })();

  return handle;
}
