import type { Socket, TCPSocketListener, udp } from "bun";
import { type Kind, respond } from "./answer.ts";
import { DEFAULT_LIMITS, type LimitOptions, ResponseLimiter } from "./limits.ts";
import { buildZone, type Zone, type ZoneWire } from "./zone.ts";

export interface TcpLimits {
  perIp: number;
  total: number;
  idleSec: number;
  readMs: number;
  queriesPerConnection: number;
  maxQuery: number;
}

export const DEFAULT_TCP: TcpLimits = {
  perIp: 8,
  total: 256,
  idleSec: 10,
  readMs: 2_000,
  queriesPerConnection: 100,
  maxQuery: 4096,
};

export interface NsOptions {
  apex: string;
  names: string[];
  limits?: LimitOptions;
  tcp?: TcpLimits;
  now?: () => number;
}

export interface NsStats {
  serial: number | null;
  loadedAt: number | null;
  names: number;
  queries: { udp: number; tcp: number };
  responses: Record<Kind, number>;
  dropped: { malformed: number; slipped: number; limited: number; global: number };
  tcp: { open: number; refused: number; timeouts: number };
}

interface Conn {
  ip: string;
  buf: Uint8Array;
  queries: number;
  timer: ReturnType<typeof setTimeout> | null;
}

export class NsServer {
  readonly apex: string;
  readonly names: string[];
  readonly #limiter: ResponseLimiter;
  readonly #tcp: TcpLimits;
  #zone: Zone | null = null;
  #loadedAt: number | null = null;
  readonly #conns = new Map<Socket<undefined>, Conn>();
  readonly #perIp = new Map<string, number>();
  readonly #udp: udp.Socket<"uint8array">[] = [];
  readonly #listeners: TCPSocketListener<undefined>[] = [];
  readonly stats: Omit<NsStats, "serial" | "loadedAt" | "names"> = {
    queries: { udp: 0, tcp: 0 },
    responses: { answer: 0, negative: 0, error: 0 },
    dropped: { malformed: 0, slipped: 0, limited: 0, global: 0 },
    tcp: { open: 0, refused: 0, timeouts: 0 },
  };

  constructor(opts: NsOptions) {
    this.apex = opts.apex;
    this.names = opts.names;
    this.#limiter = new ResponseLimiter(opts.limits ?? DEFAULT_LIMITS, opts.now);
    this.#tcp = opts.tcp ?? DEFAULT_TCP;
  }

  get serial(): number | null {
    return this.#zone?.serial ?? null;
  }

  load(wire: ZoneWire): Zone {
    const zone = buildZone(this.apex, this.names, wire);
    this.#zone = zone;
    this.#loadedAt = Date.now();
    return zone;
  }

  snapshot(): NsStats {
    return {
      serial: this.serial,
      loadedAt: this.#loadedAt,
      names: this.#zone?.names.size ?? 0,
      ...structuredClone(this.stats),
      tcp: { ...this.stats.tcp, open: this.#conns.size },
    };
  }

  answerUdp(data: Uint8Array, address: string): Uint8Array | null {
    this.stats.queries.udp++;
    const reply = respond(data, this.apex, this.#zone, false);
    if (!reply) {
      this.stats.dropped.malformed++;
      return null;
    }
    const verdict = this.#limiter.check(address, reply.kind);
    if (verdict === "drop") {
      this.stats.dropped.limited++;
      return null;
    }
    if (verdict === "global") {
      this.stats.dropped.global++;
      return null;
    }
    if (verdict === "slip") {
      this.stats.dropped.slipped++;
      return reply.truncated;
    }
    this.stats.responses[reply.kind]++;
    return reply.bytes;
  }

  answerTcp(data: Uint8Array): Uint8Array | null {
    this.stats.queries.tcp++;
    const reply = respond(data, this.apex, this.#zone, true);
    if (!reply) {
      this.stats.dropped.malformed++;
      return null;
    }
    this.stats.responses[reply.kind]++;
    return reply.bytes;
  }

  async listen(hostname: string, port: number): Promise<number> {
    const sock = await Bun.udpSocket({
      hostname,
      port,
      binaryType: "uint8array",
      socket: {
        data: (s, data, rport, address) => {
          const out = this.answerUdp(data, address);
          if (out) s.send(out, rport, address);
        },
      },
    });
    this.#udp.push(sock);
    try {
      this.#listeners.push(this.#listenTcp(hostname, sock.port));
    } catch (err) {
      sock.close();
      throw err;
    }
    return sock.port;
  }

  stop() {
    for (const s of this.#udp) s.close();
    for (const l of this.#listeners) l.stop(true);
    this.#udp.length = 0;
    this.#listeners.length = 0;
  }

  #drop(s: Socket<undefined>) {
    const c = this.#conns.get(s);
    if (!c) return;
    if (c.timer) clearTimeout(c.timer);
    this.#conns.delete(s);
    const n = (this.#perIp.get(c.ip) ?? 1) - 1;
    if (n <= 0) this.#perIp.delete(c.ip);
    else this.#perIp.set(c.ip, n);
  }

  #frames(s: Socket<undefined>, c: Conn) {
    const t = this.#tcp;
    while (c.buf.length >= 2) {
      const len = ((c.buf[0] as number) << 8) | (c.buf[1] as number);
      if (len < 12 || len > t.maxQuery) {
        s.end();
        return;
      }
      if (c.buf.length < len + 2) break;
      const query = c.buf.slice(2, len + 2);
      c.buf = c.buf.slice(len + 2);
      const out = this.answerTcp(query);
      c.queries++;
      if (!out) {
        s.end();
        return;
      }
      const framed = new Uint8Array(out.length + 2);
      framed[0] = out.length >> 8;
      framed[1] = out.length & 0xff;
      framed.set(out, 2);
      if (s.write(framed) < framed.length || c.queries >= t.queriesPerConnection) {
        s.end();
        return;
      }
    }
    if (c.timer) clearTimeout(c.timer);
    c.timer =
      c.buf.length > 0
        ? setTimeout(() => {
            this.stats.tcp.timeouts++;
            s.end();
          }, t.readMs)
        : null;
  }

  #listenTcp(hostname: string, port: number): TCPSocketListener<undefined> {
    const t = this.#tcp;
    return Bun.listen({
      hostname,
      port,
      socket: {
        open: (s) => {
          const ip = s.remoteAddress;
          const n = this.#perIp.get(ip) ?? 0;
          if (n >= t.perIp || this.#conns.size >= t.total) {
            this.stats.tcp.refused++;
            s.end();
            return;
          }
          this.#perIp.set(ip, n + 1);
          this.#conns.set(s, { ip, buf: new Uint8Array(0), queries: 0, timer: null });
          s.timeout(t.idleSec);
        },
        data: (s, chunk) => {
          const c = this.#conns.get(s);
          if (!c) return;
          const next = new Uint8Array(c.buf.length + chunk.length);
          next.set(c.buf);
          next.set(chunk, c.buf.length);
          c.buf = next;
          this.#frames(s, c);
        },
        timeout: (s) => {
          this.stats.tcp.timeouts++;
          s.end();
        },
        close: (s) => this.#drop(s),
        error: (s) => this.#drop(s),
      },
    });
  }
}

export type LimitSummary = NsStats["dropped"] & { refused: number; timeouts: number };

export function limitSummary(prev: NsStats, next: NsStats): LimitSummary | null {
  const d = {
    malformed: next.dropped.malformed - prev.dropped.malformed,
    slipped: next.dropped.slipped - prev.dropped.slipped,
    limited: next.dropped.limited - prev.dropped.limited,
    global: next.dropped.global - prev.dropped.global,
    refused: next.tcp.refused - prev.tcp.refused,
    timeouts: next.tcp.timeouts - prev.tcp.timeouts,
  };
  return d.slipped + d.limited + d.global + d.refused > 0 ? d : null;
}
