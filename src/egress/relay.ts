import type { Socket } from "bun";
import type { Logger } from "../core/log.ts";
import { familyOf } from "../dns/ip.ts";
import { Outbox, type StreamHandler } from "../ipc/rpc.ts";
import { b } from "../validate/schema.ts";

const CONNECT_MS = 30_000;
const enc = new TextEncoder();

const request = b.object({
  host: b.string().max(64),
  port: b.number().int().min(1).max(65535),
  source: b.string().max(64),
});

export interface RelayOptions {
  port: number;
  log: Logger;
}

const answer = (s: Socket<undefined>, value: unknown) =>
  s.write(enc.encode(`${JSON.stringify(value)}\n`));

function refuse(s: Socket<undefined>, code: string, message: string): StreamHandler {
  answer(s, { error: { code, message } });
  s.end();
  return { data() {}, drain() {}, close() {} };
}

export function relayStream(o: RelayOptions) {
  return (params: unknown, down: Socket<undefined>): StreamHandler => {
    const p = request.safeParse(params);
    if (!p.success) return refuse(down, "invalid", "bad stream request");
    const { host, port, source } = p.data;
    if (port !== o.port) return refuse(down, "invalid", `only port ${o.port} is allowed`);
    const family = familyOf(host);
    if (!family || familyOf(source) !== family) {
      return refuse(down, "invalid", "host and source must be IP addresses of the same family");
    }
    const toDown = new Outbox(down);
    let toUp: Outbox | null = null;
    let up: Socket<undefined> | null = null;
    const early: Uint8Array[] = [];
    let ended = false;
    const end = () => {
      if (ended) return;
      ended = true;
      up?.end();
      down.end();
    };
    const timer = setTimeout(() => {
      if (up) return;
      answer(down, { error: { code: "timeout", message: `connect to ${host}:${port} timed out` } });
      end();
    }, CONNECT_MS);
    const options = {
      hostname: host,
      port,
      localAddress: source,
      socket: {
        open(s: Socket<undefined>) {
          clearTimeout(timer);
          if (ended) {
            s.end();
            return;
          }
          up = s;
          s.setNoDelay(true);
          toUp = new Outbox(s);
          answer(down, { ok: true });
          for (const chunk of early.splice(0)) toUp.write(chunk);
        },
        data(_s: Socket<undefined>, chunk: Uint8Array) {
          toDown.write(chunk.slice());
        },
        drain() {
          toUp?.flush();
        },
        close: end,
        error: end,
        connectError(_s: Socket<undefined>, err: Error) {
          clearTimeout(timer);
          if (ended) return;
          answer(down, {
            error: { code: "network", message: `connect to ${host}:${port}: ${err.message}` },
          });
          end();
        },
      },
    };
    Bun.connect(options).catch((err: Error) => {
      clearTimeout(timer);
      if (ended) return;
      o.log.warn("egress connect failed", { host, port, source, error: err.message });
      answer(down, {
        error: { code: "network", message: `connect to ${host}:${port}: ${err.message}` },
      });
      end();
    });
    return {
      data(chunk) {
        if (toUp) toUp.write(chunk.slice());
        else early.push(chunk.slice());
      },
      drain() {
        toDown.flush();
      },
      close: end,
    };
  };
}
