import type { Socket, UnixSocketListener } from "bun";
import type { Config } from "../config.ts";
import type { Logger } from "../core/log.ts";
import { familyOf } from "../dns/ip.ts";
import { pipeTo, refuse } from "../ipc/pipe.ts";
import type { StreamHandler } from "../ipc/rpc.ts";
import { b } from "../validate/schema.ts";
import { onStop, ready } from "./runtime.ts";
import { sockets } from "./wire.ts";

const HEADER_MAX = 512;

const request = b.object({
  host: b.string().max(64),
  port: b.number().int().min(1024).max(65535),
});

function open(down: Socket<undefined>, line: string, log: Logger): StreamHandler {
  let params: unknown;
  try {
    params = JSON.parse(line);
  } catch {
    params = null;
  }
  const p = request.safeParse(params);
  if (!p.success || !familyOf(p.data.host)) {
    return refuse(down, "invalid", "a link needs an IP address and a port from 1024 to 65535");
  }
  return pipeTo(down, p.data, log, "link");
}

export async function runLink(config: Config, log: Logger): Promise<UnixSocketListener<undefined>> {
  const path = sockets(config.runDir).link;
  const heads = new Map<Socket<undefined>, string>();
  const pipes = new Map<Socket<undefined>, StreamHandler>();
  const drop = (s: Socket<undefined>) => {
    heads.delete(s);
    pipes.get(s)?.close();
    pipes.delete(s);
  };
  await Bun.$`rm -f ${path}`.quiet();
  const listener = Bun.listen({
    unix: path,
    socket: {
      data(s, chunk) {
        const pipe = pipes.get(s);
        if (pipe) {
          pipe.data(chunk);
          return;
        }
        const head = (heads.get(s) ?? "") + new TextDecoder().decode(chunk);
        const end = head.indexOf("\n");
        if (end < 0 && head.length <= HEADER_MAX) {
          heads.set(s, head);
          return;
        }
        heads.delete(s);
        pipes.set(
          s,
          end < 0 ? refuse(s, "invalid", "bad link request") : open(s, head.slice(0, end), log),
        );
      },
      drain(s) {
        pipes.get(s)?.drain();
      },
      close: drop,
      error: drop,
    },
  });
  await Bun.$`chmod 660 ${path}`.quiet();
  onStop(log, () => listener.stop(true));
  log.info("link ready", { socket: path });
  ready();
  return listener;
}
