import type { Config } from "../config.ts";
import type { Logger } from "../core/log.ts";
import { onStop, ready } from "./runtime.ts";

const REFUSAL = "554 5.3.2 This Bunzzle server does not accept incoming mail yet\r\n";

export async function runInbound(config: Config, log: Logger) {
  const port = config.inboundPort;
  const listener =
    port === null
      ? null
      : Bun.listen({
          hostname: config.inboundHost,
          port,
          socket: {
            open(s) {
              s.write(REFUSAL);
              s.end();
            },
            data() {},
          },
        });
  const idle = listener ? null : setInterval(() => {}, 1 << 30);
  onStop(log, () => {
    listener?.stop(true);
    if (idle) clearInterval(idle);
  });
  ready(listener ? { port: listener.port } : {});
}
