import { z } from "zod";
import type { Config } from "../config.ts";
import type { Logger } from "../core/log.ts";
import { RpcClient } from "../ipc/rpc.ts";
import { VERSION } from "../version.ts";
import { onStop, ready } from "./runtime.ts";
import { sockets } from "./wire.ts";

export async function runApi(config: Config, log: Logger) {
  const core = new RpcClient(sockets(config.runDir).core);
  const startedAt = Date.now();
  const server = Bun.serve({
    hostname: config.host,
    port: config.port,
    routes: {
      "/health": {
        GET: async () => {
          let ok = false;
          try {
            const r = await core.call(
              "health",
              {},
              {
                timeoutMs: 2_000,
                result: z.object({ ok: z.boolean() }),
              },
            );
            ok = r.ok;
          } catch {
            ok = false;
          }
          return Response.json(
            {
              ok,
              version: VERSION,
              uptime_s: Math.floor((Date.now() - startedAt) / 1000),
              core: ok ? "ok" : "unavailable",
            },
            { status: ok ? 200 : 503 },
          );
        },
      },
    },
    fetch() {
      return Response.json({ error: { code: "not_found", message: "Not found" } }, { status: 404 });
    },
    error(err) {
      log.error("unhandled request error", { error: err.message });
      return Response.json(
        { error: { code: "internal_error", message: "Internal server error" } },
        { status: 500 },
      );
    },
  });
  onStop(log, async () => {
    await server.stop();
    core.close();
  });
  ready({ url: server.url.href });
}
