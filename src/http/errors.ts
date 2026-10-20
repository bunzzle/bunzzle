import { RpcError } from "../ipc/rpc.ts";

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly kind: string,
    message: string,
    readonly headers: Record<string, string> = {},
  ) {
    super(message);
  }
}

export function errorResponse(err: ApiError): Response {
  return Response.json(
    { statusCode: err.status, name: err.kind, message: err.message },
    { status: err.status, headers: err.headers },
  );
}

const FROM_RPC: Record<string, [number, string]> = {
  unauthenticated: [403, "invalid_api_key"],
  forbidden: [403, "restricted_api_key"],
  invalid: [422, "validation_error"],
  "unverified-domain": [403, "validation_error"],
  "idempotency-conflict": [409, "invalid_idempotent_request"],
  "not-found": [404, "not_found"],
  held: [403, "sending_paused"],
  started: [409, "invalid_state"],
  refused: [422, "refused"],
};

const RETRY_LATER: Record<string, [number, string, string]> = {
  "storage-low": [503, "insufficient_storage", "60"],
  "hook-failed": [503, "hook_unavailable", "5"],
};

export function fromRpc(err: unknown): ApiError {
  if (err instanceof ApiError) return err;
  if (err instanceof RpcError) {
    const mapped = FROM_RPC[err.code];
    if (mapped) return new ApiError(mapped[0], mapped[1], err.message);
    const later = RETRY_LATER[err.code];
    if (later) {
      return new ApiError(later[0], later[1], err.message, { "Retry-After": later[2] });
    }
    if (err.code === "unavailable" || err.code === "lost" || err.code === "timeout") {
      return new ApiError(
        503,
        "application_error",
        "Bunzzle is restarting a component; try again.",
        {
          "Retry-After": "1",
        },
      );
    }
  }
  return new ApiError(500, "application_error", "Internal server error");
}
