import { z } from "zod";
import type { Config } from "../config.ts";
import type { Logger } from "../core/log.ts";
import { classifyReport, type Report } from "../inbound/parse.ts";
import { startInboundServer } from "../inbound/server.ts";
import { RpcClient, RpcError } from "../ipc/rpc.ts";
import { onStop, ready } from "./runtime.ts";
import { sockets } from "./wire.ts";

export async function runInbound(config: Config, log: Logger) {
  const core = new RpcClient(sockets(config.runDir).core);
  const port = config.inboundPort;
  const server =
    port === null
      ? null
      : startInboundServer({
          hostname: config.inboundHost,
          port,
          name: config.inboundHostname ?? "bunzzle",
          handlers: {
            recipient: async (address) =>
              (
                await core.call(
                  "inboundRecipient",
                  { address },
                  { result: z.object({ accept: z.boolean() }), timeoutMs: 10_000 },
                )
              ).accept,
            message: async (recipients, raw) => {
              let report: Report;
              try {
                report = classifyReport(raw);
              } catch {
                report = { kind: "unknown", ref: null };
              }
              try {
                await core.call(
                  "inboundReport",
                  { recipients, report, raw },
                  { timeoutMs: 30_000 },
                );
                return "ok";
              } catch (err) {
                if (err instanceof RpcError && err.code === "invalid") return "reject";
                log.warn("could not hand a report to core", { error: (err as Error).message });
                return "retry";
              }
            },
          },
        });
  const idle = server ? null : setInterval(() => {}, 1 << 30);
  onStop(log, () => {
    server?.stop();
    if (idle) clearInterval(idle);
    core.close();
  });
  ready(server ? { port: server.port } : {});
}
