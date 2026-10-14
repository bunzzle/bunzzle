import type { Database } from "bun:sqlite";
import type { Logger } from "../core/log.ts";
import { healthRoute } from "./routes/health.ts";

export interface ServerDeps {
  db: Database;
  log: Logger;
  host: string;
  port: number;
}

export function startServer({ db, log, host, port }: ServerDeps) {
  const startedAt = Date.now();

  return Bun.serve({
    hostname: host,
    port,
    routes: {
      "/health": { GET: healthRoute(db, startedAt) },
    },
    fetch() {
      return Response.json({ error: { code: "not_found", message: "Not found" } }, { status: 404 });
    },
    error(err) {
      log.error("unhandled request error", { error: err.message, stack: err.stack });
      return Response.json(
        { error: { code: "internal_error", message: "Internal server error" } },
        { status: 500 },
      );
    },
  });
}
