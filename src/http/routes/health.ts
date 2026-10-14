import type { Database } from "bun:sqlite";
import { VERSION } from "../../version.ts";

export function healthRoute(db: Database, startedAt: number) {
  const ping = db.query<{ ok: number }, []>("SELECT 1 AS ok");

  return (): Response => {
    let dbOk = false;
    try {
      dbOk = ping.get()?.ok === 1;
    } catch {
      dbOk = false;
    }
    return Response.json(
      {
        ok: dbOk,
        version: VERSION,
        uptime_s: Math.floor((Date.now() - startedAt) / 1000),
        db: dbOk ? "ok" : "unavailable",
      },
      { status: dbOk ? 200 : 503 },
    );
  };
}
