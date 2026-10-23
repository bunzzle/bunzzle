import type { Logger } from "../core/log.ts";
import type { RpcClient } from "../ipc/rpc.ts";
import { cpuSeconds } from "../metrics/usage.ts";

export function ready(info: Record<string, unknown> = {}) {
  process.send?.({ type: "ready", ...info });
}

export function onStop(
  log: Logger,
  stop: () => Promise<void> | void,
): (reason: string) => Promise<void> {
  let stopping = false;
  const handler = async (signal: string) => {
    if (stopping) return;
    stopping = true;
    log.info("stopping", { signal });
    try {
      await stop();
    } finally {
      process.exit(0);
    }
  };
  process.on("SIGTERM", () => void handler("SIGTERM"));
  process.on("SIGINT", () => void handler("SIGINT"));
  return handler;
}

async function fingerprint(path: string): Promise<string | null> {
  const f = Bun.file(path);
  if (!(await f.exists())) return null;
  const h = new Bun.CryptoHasher("sha256");
  h.update(await f.bytes());
  return h.digest("hex");
}

export async function watchFile(
  path: string,
  everyMs: number,
  changed: () => void,
): Promise<() => void> {
  let last = await fingerprint(path);
  return every(everyMs, async () => {
    const now = await fingerprint(path);
    if (now !== null && now !== last) changed();
    last = now;
  });
}

export async function privateDir(path: string, mode = "700") {
  await Bun.$`mkdir -p ${path} && chmod ${mode} ${path}`.quiet();
}

export function every(ms: number, fn: () => Promise<unknown> | unknown): () => void {
  let running = false;
  const timer = setInterval(async () => {
    if (running) return;
    running = true;
    try {
      await fn();
    } finally {
      running = false;
    }
  }, ms);
  return () => clearInterval(timer);
}

export function reportUsage(core: RpcClient, role: "api" | "inbound"): () => void {
  const send = () =>
    core
      .call("roleUsage", { role, cpuSeconds: cpuSeconds() }, { timeoutMs: 5_000 })
      .catch(() => {});
  void send();
  return every(15_000, send);
}
