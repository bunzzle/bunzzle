import type { Config } from "../config.ts";
import type { Logger } from "../core/log.ts";
import { startApp } from "../http/app.ts";
import { RpcClient } from "../ipc/rpc.ts";
import { onStop, ready } from "./runtime.ts";
import { sockets } from "./wire.ts";

export async function runApi(config: Config, log: Logger) {
  const core = new RpcClient(sockets(config.runDir).core);
  const server = startApp({ core, log, hostname: config.host, port: config.port });
  onStop(log, async () => {
    await server.stop();
    core.close();
  });
  ready({ url: server.url.href });
}
