import type { RpcClient } from "../ipc/rpc.ts";
import { b } from "../validate/schema.ts";

const POLL_MS = 15_000;
const USER_HZ = 100;
const usageWire = b.object({ cpuSeconds: b.number().nullable() });

export async function cpuSeconds(): Promise<number | null> {
  const stat = await Bun.file("/proc/self/stat")
    .text()
    .catch(() => "");
  const fields = stat.slice(stat.lastIndexOf(")") + 2).split(" ");
  const ticks = Number(fields[11]) + Number(fields[12]);
  return Number.isFinite(ticks) ? ticks / USER_HZ : null;
}

export interface UsageTarget {
  role: string;
  node: string | null;
  client: RpcClient | null;
}

export interface RoleSample {
  role: string;
  node: string | null;
  up: boolean;
  cpuSeconds: number | null;
}

export interface RoleUsageDeps {
  targets: () => UsageTarget[];
  pushed: string[];
  now?: () => number;
  pollMs?: number;
}

const keyOf = (role: string, node: string | null) => `${role}\u0000${node ?? ""}`;

export class RoleUsage {
  readonly #d: RoleUsageDeps;
  readonly #now: () => number;
  readonly #seen = new Map<string, { cpuSeconds: number | null; at: number }>();
  readonly pollMs: number;

  constructor(deps: RoleUsageDeps) {
    this.#d = deps;
    this.#now = deps.now ?? Date.now;
    this.pollMs = deps.pollMs ?? POLL_MS;
  }

  async poll(): Promise<void> {
    this.#seen.set(keyOf("core", null), { cpuSeconds: await cpuSeconds(), at: this.#now() });
    await Promise.all(
      this.#d.targets().map(async (t) => {
        if (!t.client) return;
        try {
          const u = await t.client.call("usage", {}, { result: usageWire, timeoutMs: 5_000 });
          this.#seen.set(keyOf(t.role, t.node), { cpuSeconds: u.cpuSeconds, at: this.#now() });
        } catch {}
      }),
    );
  }

  report(role: string, cpu: number | null): void {
    this.#seen.set(keyOf(role, null), { cpuSeconds: cpu, at: this.#now() });
  }

  samples(): RoleSample[] {
    const expected = [
      ...this.#d.targets(),
      ...this.#d.pushed.map((role) => ({ role, node: null })),
    ];
    return [
      {
        role: "core",
        node: null,
        up: true,
        cpuSeconds: this.#seen.get(keyOf("core", null))?.cpuSeconds ?? null,
      },
      ...expected.map((t) => {
        const s = this.#seen.get(keyOf(t.role, t.node));
        return {
          role: t.role,
          node: t.node,
          up: s !== undefined && this.#now() - s.at <= 3 * this.pollMs,
          cpuSeconds: s?.cpuSeconds ?? null,
        };
      }),
    ];
  }
}
