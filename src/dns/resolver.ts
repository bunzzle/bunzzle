import {
  type DnsMessage,
  DnsWireError,
  decodeMessage,
  encodeQuery,
  normalizeName,
  Rcode,
  type ResourceRecord,
  RRType,
  type RRTypeName,
} from "./wire.ts";

export type QueryType = "A" | "AAAA" | "MX" | "TXT" | "PTR" | "TLSA";

export interface DnsAnswer {
  name: string;
  type: QueryType;
  rcode: number;
  authenticated: boolean;
  records: ResourceRecord[];
  ttl: number;
}

export interface Resolver {
  query(name: string, type: QueryType): Promise<DnsAnswer>;
}

export class DnsError extends Error {
  constructor(
    readonly code: "timeout" | "network" | "malformed",
    message: string,
  ) {
    super(message);
  }
}

export interface Server {
  host: string;
  port: number;
}

export interface ResolverOptions {
  servers: Server[];
  timeoutMs?: number;
  attempts?: number;
}

const DEFAULT_NEGATIVE_TTL = 60;
const MAX_RESPONSE = 65535;

export function parseServer(spec: string): Server {
  const s = spec.trim();
  const bracket = /^\[([^\]]+)\](?::(\d+))?$/.exec(s);
  if (bracket) return { host: bracket[1] as string, port: Number(bracket[2] ?? 53) };
  const colons = s.split(":").length - 1;
  if (colons === 1) {
    const [host, port] = s.split(":") as [string, string];
    return { host, port: Number(port) };
  }
  return { host: s, port: 53 };
}

export async function systemServers(path = "/etc/resolv.conf"): Promise<Server[]> {
  const file = Bun.file(path);
  if (!(await file.exists())) return [];
  const servers: Server[] = [];
  for (const line of (await file.text()).split("\n")) {
    const m = /^\s*nameserver\s+(\S+)/.exec(line);
    if (m) servers.push({ host: (m[1] as string).replace(/%.*$/, ""), port: 53 });
  }
  return servers;
}

function randomId(): number {
  return crypto.getRandomValues(new Uint16Array(1))[0] as number;
}

function matches(msg: DnsMessage, id: number, name: string, type: number): boolean {
  return msg.id === id && msg.question?.name === name && msg.question.type === type;
}

function udpExchange(
  server: Server,
  packet: Uint8Array,
  id: number,
  name: string,
  type: number,
  timeoutMs: number,
): Promise<DnsMessage> {
  return new Promise((resolve, reject) => {
    let done = false;
    let sock: { close(): void } | null = null;
    const finish = (fn: () => void) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      sock?.close();
      fn();
    };
    const timer = setTimeout(
      () => finish(() => reject(new DnsError("timeout", `no answer from ${server.host}`))),
      timeoutMs,
    );
    Bun.udpSocket({
      hostname: server.host.includes(":") ? "::" : "0.0.0.0",
      binaryType: "uint8array",
      socket: {
        data(_s, data) {
          let msg: DnsMessage;
          try {
            msg = decodeMessage(data);
          } catch {
            return;
          }
          if (matches(msg, id, name, type)) finish(() => resolve(msg));
        },
        error(_s, err) {
          finish(() => reject(new DnsError("network", err.message)));
        },
      },
    }).then(
      (s) => {
        sock = s;
        if (done) s.close();
        else s.send(packet, server.port, server.host);
      },
      (err: Error) => finish(() => reject(new DnsError("network", err.message))),
    );
  });
}

function tcpExchange(
  server: Server,
  packet: Uint8Array,
  id: number,
  name: string,
  type: number,
  timeoutMs: number,
): Promise<DnsMessage> {
  return new Promise((resolve, reject) => {
    let done = false;
    let buf = new Uint8Array(0);
    let sock: { end(): void } | null = null;
    const finish = (fn: () => void) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      sock?.end();
      fn();
    };
    const timer = setTimeout(
      () => finish(() => reject(new DnsError("timeout", `no TCP answer from ${server.host}`))),
      timeoutMs,
    );
    const framed = new Uint8Array(packet.length + 2);
    new DataView(framed.buffer).setUint16(0, packet.length);
    framed.set(packet, 2);
    Bun.connect({
      hostname: server.host,
      port: server.port,
      socket: {
        open(s) {
          sock = s;
          s.write(framed);
        },
        data(_s, chunk) {
          const next = new Uint8Array(buf.length + chunk.length);
          next.set(buf);
          next.set(chunk, buf.length);
          buf = next;
          if (buf.length > MAX_RESPONSE + 2) {
            finish(() => reject(new DnsError("malformed", "TCP answer too large")));
            return;
          }
          if (buf.length < 2) return;
          const len = ((buf[0] as number) << 8) | (buf[1] as number);
          if (buf.length < len + 2) return;
          try {
            const msg = decodeMessage(buf.subarray(2, len + 2));
            if (!matches(msg, id, name, type)) throw new DnsWireError("answer does not match");
            finish(() => resolve(msg));
          } catch (err) {
            finish(() => reject(new DnsError("malformed", (err as Error).message)));
          }
        },
        close() {
          finish(() => reject(new DnsError("network", "TCP connection closed early")));
        },
        error(_s, err) {
          finish(() => reject(new DnsError("network", err.message)));
        },
      },
    }).catch((err: Error) => finish(() => reject(new DnsError("network", err.message))));
  });
}

function chainRecords(msg: DnsMessage, name: string, type: QueryType): ResourceRecord[] {
  const names = new Set([name]);
  for (let changed = true; changed; ) {
    changed = false;
    for (const r of msg.answers) {
      if (r.type === "CNAME" && names.has(r.name) && !names.has(r.target)) {
        names.add(r.target);
        changed = true;
      }
    }
  }
  return msg.answers.filter((r) => r.type === type && names.has(r.name));
}

function negativeTtl(msg: DnsMessage): number {
  for (const r of msg.authority) {
    if (r.type === "SOA") return Math.min(r.ttl, r.soa.minimum);
  }
  return DEFAULT_NEGATIVE_TTL;
}

export function createResolver(opts: ResolverOptions): Resolver {
  if (opts.servers.length === 0) throw new Error("no DNS servers configured");
  const timeoutMs = opts.timeoutMs ?? 2000;
  const attempts = opts.attempts ?? 2;

  return {
    async query(rawName, type) {
      const name = normalizeName(rawName);
      const code = RRType[type as RRTypeName];
      let lastError: DnsError = new DnsError("timeout", "no DNS answer");
      let lastFailure: DnsAnswer | null = null;
      for (let a = 0; a < attempts; a++) {
        for (const server of opts.servers) {
          const id = randomId();
          const packet = encodeQuery(id, name, code);
          try {
            let msg = await udpExchange(server, packet, id, name, code, timeoutMs);
            if (msg.truncated) msg = await tcpExchange(server, packet, id, name, code, timeoutMs);
            const records = chainRecords(msg, name, type);
            const ttl =
              records.length > 0 ? Math.min(...records.map((r) => r.ttl)) : negativeTtl(msg);
            const answer = {
              name,
              type,
              rcode: msg.rcode,
              authenticated: msg.authenticated,
              records,
              ttl,
            };
            if (msg.rcode !== Rcode.SERVFAIL && msg.rcode !== Rcode.REFUSED) return answer;
            lastFailure = answer;
          } catch (err) {
            if (!(err instanceof DnsError)) throw err;
            lastError = err;
          }
        }
      }
      if (lastFailure) return lastFailure;
      throw lastError;
    },
  };
}
