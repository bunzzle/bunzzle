import type { Subprocess } from "bun";
import { type Config, ConfigError } from "../config.ts";
import type { Logger } from "../core/log.ts";
import { readMasterKeyText } from "../crypto/load.ts";
import { masterKeyFrom } from "../crypto/master.ts";
import { roleEnv } from "./env.ts";
import { privateDir } from "./runtime.ts";
import { ROLES, type Role } from "./wire.ts";

const READY_TIMEOUT_MS = 20_000;
const STOP_TIMEOUT_MS = 10_000;
const STABLE_MS = 30_000;

interface Child {
  role: Role;
  proc: Subprocess;
  startedAt: number;
  ready: Promise<Record<string, unknown>>;
}

function roleCommand(role: Role): string[] {
  const compiled = Bun.main.startsWith("/$bunfs/");
  return compiled ? [process.execPath, "role", role] : [process.execPath, Bun.main, "role", role];
}

export async function runSupervisor(
  config: Config,
  log: Logger,
  env: Record<string, string | undefined> = Bun.env,
) {
  const masterText = await readMasterKeyText(config);
  if (!masterText) {
    throw new ConfigError(
      "bunzzle serve needs a master key: set BUNZZLE_MASTER_KEY or BUNZZLE_MASTER_KEY_FILE (create one with `bunzzle master-key`)",
    );
  }
  await masterKeyFrom(masterText);
  if (config.acme && !config.cloudflareToken && !config.cloudflareTokenFile && !config.dnsUpdate) {
    throw new ConfigError(
      "BUNZZLE_ACME_EMAIL needs a DNS provider (Cloudflare or DNS updates) for the DNS-01 challenge",
    );
  }
  await privateDir(config.runDir, "750");
  await privateDir(config.dataDir);
  await privateDir(config.keysDir);

  const children = new Map<Role, Child>();
  const failures = new Map<Role, number>();
  let stopping = false;

  const spawn = (role: Role): Child => {
    const { promise, resolve, reject } = Promise.withResolvers<Record<string, unknown>>();
    const proc = Bun.spawn(roleCommand(role), {
      env: roleEnv(role, env),
      stdin: role === "signer" ? "pipe" : "ignore",
      stdout: "inherit",
      stderr: "inherit",
      ipc(message) {
        const m = message as { type?: unknown } | null;
        if (m && m.type === "ready") resolve(m as Record<string, unknown>);
      },
    });
    if (role === "signer" && proc.stdin && typeof proc.stdin !== "number") {
      proc.stdin.write(masterText);
      void proc.stdin.end();
    }
    const timer = setTimeout(
      () => reject(new Error(`${role} did not become ready in time`)),
      READY_TIMEOUT_MS,
    );
    const child: Child = { role, proc, startedAt: Date.now(), ready: promise };
    void proc.exited.then((code) => {
      clearTimeout(timer);
      reject(new Error(`${role} exited with code ${code} before it was ready`));
      if (children.get(role) !== child || stopping) return;
      const ranFor = Date.now() - child.startedAt;
      const n = ranFor > STABLE_MS ? 0 : (failures.get(role) ?? 0) + 1;
      failures.set(role, n);
      const delay = Math.min(5_000, 100 * 2 ** n);
      log.warn("role exited, restarting", {
        role,
        code,
        signal: proc.signalCode,
        restartInMs: delay,
      });
      setTimeout(() => {
        if (stopping) return;
        const next = spawn(role);
        children.set(role, next);
        next.ready.then(
          () => log.info("role restarted", { role, pid: next.proc.pid }),
          (err: Error) => log.error("role failed to restart", { role, error: err.message }),
        );
      }, delay);
    });
    promise.then(
      () => clearTimeout(timer),
      () => clearTimeout(timer),
    );
    log.info("role started", { role, pid: proc.pid });
    return child;
  };

  const stopAll = async () => {
    stopping = true;
    for (const role of [...ROLES].reverse()) {
      const child = children.get(role);
      if (!child || child.proc.exitCode !== null) continue;
      child.proc.kill("SIGTERM");
      const done = await Promise.race([
        child.proc.exited.then(() => true),
        Bun.sleep(STOP_TIMEOUT_MS).then(() => false),
      ]);
      if (!done) child.proc.kill("SIGKILL");
    }
  };

  let url: unknown = null;
  let inboundPort: unknown = null;
  let submissionPorts: unknown = null;
  let trackPort: unknown = null;
  for (const role of ROLES) {
    const child = spawn(role);
    children.set(role, child);
    try {
      const info = await child.ready;
      if (role === "api") {
        url = info["url"];
        submissionPorts = info["submissionPorts"] ?? null;
        trackPort = info["trackPort"] ?? null;
      }
      if (role === "inbound") inboundPort = info["port"] ?? null;
    } catch (err) {
      log.error("could not start", { role, error: (err as Error).message });
      await stopAll();
      process.exit(1);
    }
  }
  log.info("listening", {
    url,
    inboundPort,
    ...(submissionPorts ? { submissionPorts } : {}),
    ...(trackPort ? { trackPort } : {}),
    roles: Object.fromEntries([...children].map(([r, c]) => [r, c.proc.pid])),
  });

  const shutdown = async (signal: string) => {
    if (stopping) return;
    log.info("shutting down", { signal });
    await stopAll();
    process.exit(0);
  };
  process.on("SIGINT", () => void shutdown("SIGINT"));
  process.on("SIGTERM", () => void shutdown("SIGTERM"));
  process.on("SIGHUP", () => {
    log.info("reloading the configuration in every role");
    for (const child of children.values()) child.proc.kill("SIGHUP");
  });
}
