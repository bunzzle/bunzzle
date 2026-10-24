import type { Socket } from "bun";
import type { Logger } from "../core/log.ts";
import { Outbox, type StreamHandler } from "./rpc.ts";

const CONNECT_MS = 30_000;
const enc = new TextEncoder();

export const answer = (s: Socket<undefined>, value: unknown) =>
  s.write(enc.encode(`${JSON.stringify(value)}\n`));

export function refuse(s: Socket<undefined>, code: string, message: string): StreamHandler {
  answer(s, { error: { code, message } });
  s.end();
  return { data() {}, drain() {}, close() {} };
}

export interface Target {
  host: string;
  port: number;
  source?: string;
}

export function pipeTo(
  down: Socket<undefined>,
  { host, port, source }: Target,
  log: Logger,
  what: string,
): StreamHandler {
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
    ...(source ? { localAddress: source } : {}),
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
    log.warn(`${what} connect failed`, { host, port, error: err.message });
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
}
