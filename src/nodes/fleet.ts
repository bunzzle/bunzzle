import type { Logger } from "../core/log.ts";
import type { RpcClient } from "../ipc/rpc.ts";
import { b } from "../validate/schema.ts";
import type { NodeLinks } from "./links.ts";

export const LOCAL = "local";
const CHECK_MS = 10_000;
const DOWN_AFTER = 3;

const ipList = b.array(b.object({ ip: b.string() }));

export interface NodeHealth {
  name: string;
  up: boolean;
  lastSeen: number | null;
  ips: string[];
  error: string | null;
}

interface State {
  up: boolean;
  lastSeen: number | null;
  failures: number;
  ips: string[];
  error: string | null;
}

export interface FleetDeps {
  local: RpcClient;
  links: NodeLinks;
  log: Logger;
  now?: () => number;
  checkMs?: number;
}

export class DeliveryFleet {
  readonly #d: FleetDeps;
  readonly #now: () => number;
  readonly #state = new Map<string, State>();
  readonly checkMs: number;

  constructor(deps: FleetDeps) {
    this.#d = deps;
    this.#now = deps.now ?? Date.now;
    this.checkMs = deps.checkMs ?? CHECK_MS;
    this.#state.set(LOCAL, { up: true, lastSeen: null, failures: 0, ips: [], error: null });
  }

  #names(): string[] {
    return [LOCAL, ...this.#d.links.names()];
  }

  client(name: string): RpcClient | null {
    return name === LOCAL ? this.#d.local : this.#d.links.client(name);
  }

  #stateOf(name: string): State {
    let s = this.#state.get(name);
    if (!s) {
      s = { up: false, lastSeen: null, failures: 0, ips: [], error: null };
      this.#state.set(name, s);
    }
    return s;
  }

  async check(): Promise<void> {
    this.#d.links.sync();
    const names = this.#names();
    for (const name of [...this.#state.keys()]) if (!names.includes(name)) this.#state.delete(name);
    await Promise.all(
      names.map(async (name) => {
        const client = this.client(name);
        const s = this.#stateOf(name);
        try {
          const ips = await (client as RpcClient).call(
            "ips",
            {},
            { result: ipList, timeoutMs: this.checkMs },
          );
          if (!s.up) this.#d.log.info("delivery node up", { name });
          Object.assign(s, {
            up: true,
            lastSeen: this.#now(),
            failures: 0,
            ips: ips.map((x) => x.ip),
            error: null,
          });
        } catch (err) {
          s.failures++;
          s.error = (err as Error).message;
          if (s.up && s.failures >= DOWN_AFTER) this.markDown(name, s.error);
        }
      }),
    );
  }

  markDown(name: string, error: string): void {
    const s = this.#stateOf(name);
    if (!s.up) return;
    s.up = false;
    s.error = error;
    this.#d.log.warn("delivery node down", { name, error });
  }

  #owners(ip: string): string[] {
    return [...this.#state.entries()].filter(([, s]) => s.ips.includes(ip)).map(([n]) => n);
  }

  ownerOf(ip: string): string | null {
    const owners = this.#owners(ip);
    return owners.length === 1 ? (owners[0] as string) : null;
  }

  conflicts(): { ip: string; nodes: string[] }[] {
    const all = new Set([...this.#state.values()].flatMap((s) => s.ips));
    return [...all]
      .map((ip) => ({ ip, nodes: this.#owners(ip) }))
      .filter((c) => c.nodes.length > 1);
  }

  ready(ip: string): boolean {
    const owner = this.ownerOf(ip);
    return owner !== null && this.#stateOf(owner).up;
  }

  clientFor(source: string): { name: string; client: RpcClient } {
    const owner = this.ownerOf(source);
    const name = owner ?? LOCAL;
    return { name, client: this.client(name) ?? this.#d.local };
  }

  health(): NodeHealth[] {
    return this.#names().map((name) => {
      const s = this.#stateOf(name);
      return { name, up: s.up, lastSeen: s.lastSeen, ips: [...s.ips], error: s.error };
    });
  }
}
