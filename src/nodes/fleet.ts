import type { Logger } from "../core/log.ts";
import type { RpcClient } from "../ipc/rpc.ts";
import type { IpDown } from "../ips/warmup.ts";
import { b } from "../validate/schema.ts";
import type { NodeLinks } from "./links.ts";
import type { NodeKind } from "./registry.ts";

export const LOCAL = "local";
const CHECK_MS = 10_000;
const DOWN_AFTER = 3;

const ipList = b.array(b.object({ ip: b.string() }));

export interface NodeHealth {
  name: string;
  kind: NodeKind;
  up: boolean;
  lastSeen: number | null;
  ips: string[];
  error: string | null;
  delivered: number;
}

interface State {
  up: boolean;
  downSince: number | null;
  lastSeen: number | null;
  failures: number;
  ips: string[];
  error: string | null;
  delivered: number;
}

export interface FleetDeps {
  local: RpcClient;
  links: NodeLinks;
  log: Logger;
  now?: () => number;
  checkMs?: number;
  onUp?: (name: string) => void;
}

export class DeliveryFleet {
  readonly #d: FleetDeps;
  readonly #now: () => number;
  readonly #state = new Map<string, State>();
  readonly #unowned = new Map<string, number>();
  readonly checkMs: number;

  constructor(deps: FleetDeps) {
    this.#d = deps;
    this.#now = deps.now ?? Date.now;
    this.checkMs = deps.checkMs ?? CHECK_MS;
    this.#state.set(LOCAL, {
      up: true,
      downSince: null,
      lastSeen: null,
      failures: 0,
      ips: [],
      error: null,
      delivered: 0,
    });
  }

  #names(): string[] {
    return [LOCAL, ...this.#d.links.names("delivery"), ...this.#d.links.names("egress")];
  }

  client(name: string): RpcClient | null {
    return name === LOCAL ? this.#d.local : this.#d.links.client(name);
  }

  #stateOf(name: string): State {
    let s = this.#state.get(name);
    if (!s) {
      s = {
        up: false,
        downSince: this.#now(),
        lastSeen: null,
        failures: 0,
        ips: [],
        error: null,
        delivered: 0,
      };
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
          const back = !s.up;
          if (back) this.#d.log.info("delivery node up", { name });
          Object.assign(s, {
            up: true,
            downSince: null,
            lastSeen: this.#now(),
            failures: 0,
            ips: ips.map((x) => x.ip),
            error: null,
          });
          if (back) this.#d.onUp?.(name);
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
    s.downSince = this.#now();
    s.error = error;
    this.#d.log.warn("delivery node down", { name, error });
  }

  delivered(name: string, n: number): void {
    const s = this.#state.get(name);
    if (s) s.delivered += n;
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

  down(ip: string): IpDown | null {
    const owners = this.#owners(ip);
    if (owners.length === 1) {
      this.#unowned.delete(ip);
      const name = owners[0] as string;
      const s = this.#stateOf(name);
      if (s.up) return null;
      const what = this.#d.links.kindOf(name) === "egress" ? "egress" : "node";
      return {
        reason: `${what} ${name} is down (${ip})`,
        since: s.downSince ?? this.#now(),
        node: name,
      };
    }
    let since = this.#unowned.get(ip);
    if (since === undefined) {
      since = this.#now();
      this.#unowned.set(ip, since);
    }
    return {
      reason:
        owners.length === 0 ? `no delivery role has ${ip}` : `${ip} is on ${owners.join(" and ")}`,
      since,
    };
  }

  ready(ip: string): boolean {
    return this.down(ip) === null;
  }

  nodeOf(source: string): string | null {
    const owner = this.ownerOf(source);
    return owner === LOCAL ? null : owner;
  }

  clientFor(source: string): {
    name: string;
    client: RpcClient;
    egress: { name: string; address: string; pin: string } | null;
  } {
    const owner = this.ownerOf(source);
    const egress = owner ? this.#d.links.egress(owner) : null;
    if (egress) return { name: LOCAL, client: this.#d.local, egress };
    const name = owner ?? LOCAL;
    return { name, client: this.client(name) ?? this.#d.local, egress: null };
  }

  health(): NodeHealth[] {
    return this.#names().map((name) => {
      const s = this.#stateOf(name);
      return {
        name,
        kind: this.#d.links.kindOf(name) ?? ("delivery" as const),
        up: s.up,
        lastSeen: s.lastSeen,
        ips: [...s.ips],
        error: s.error,
        delivered: s.delivered,
      };
    });
  }
}
