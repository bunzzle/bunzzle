import type { Logger } from "../core/log.ts";

export function ready(info: Record<string, unknown> = {}) {
  process.send?.({ type: "ready", ...info });
}

export function onStop(log: Logger, stop: () => Promise<void> | void) {
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
