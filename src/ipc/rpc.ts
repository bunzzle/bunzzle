import type { Socket, SocketHandler, SocketListener, TLSOptions, UnixSocketListener } from "bun";
import { cpuSeconds } from "../metrics/usage.ts";
import { b } from "../validate/schema.ts";
import { parseCertificate } from "../x509/cert.ts";

const MAX_FRAME = 64 * 1024 * 1024;
const NL = 0x0a;
const enc = new TextEncoder();
const dec = new TextDecoder();

const TLS13_ONLY = 0x04000000 | 0x08000000 | 0x10000000;
const SERVER_AUTH = "1.3.6.1.5.5.7.3.1";
const CLIENT_AUTH = "1.3.6.1.5.5.7.3.2";
const P256_SPKI = Uint8Array.fromHex("3059301306072a8648ce3d020106082a8648ce3d030107034200");

export type RpcErrorCode = "unavailable" | "lost" | "timeout" | "invalid" | "failed";

export class RpcError extends Error {
  constructor(
    readonly code: RpcErrorCode | (string & {}),
    message: string,
    readonly retryAfter?: number,
  ) {
    super(message);
  }
}

export interface CallContext {
  progress(value: unknown): void;
}

export interface Method {
  params: b.Schema;
  handle(params: unknown, ctx?: CallContext): unknown;
}

const quiet: CallContext = { progress: () => {} };

export function method<P, R>(
  params: b.Schema<P>,
  handle: (params: P, ctx: CallContext) => Promise<R> | R,
): Method {
  return { params, handle: (p, ctx = quiet) => handle(p as P, ctx) };
}

export type Methods = Record<string, Method>;

const request = b.object({ id: b.number().int(), method: b.string(), params: b.unknown() });
const progress = b.object({ id: b.number().int(), progress: b.unknown() });
const response = b.union([
  b.object({ id: b.number().int(), result: b.unknown() }),
  b.object({
    id: b.number().int(),
    error: b.object({
      code: b.string(),
      message: b.string(),
      retryAfter: b.number().int().positive().optional(),
    }),
  }),
]);

function concat(parts: Uint8Array[]): Uint8Array {
  if (parts.length === 1) return parts[0] as Uint8Array;
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

export class Outbox {
  #out: Uint8Array[] = [];

  constructor(private readonly socket: Socket<undefined>) {}

  write(bytes: Uint8Array) {
    if (bytes.length === 0) return;
    this.#out.push(bytes);
    this.flush();
  }

  get pending(): number {
    return this.#out.length;
  }

  flush() {
    while (this.#out.length > 0) {
      const head = this.#out[0] as Uint8Array;
      const n = this.socket.write(head);
      if (n < 0) return;
      if (n < head.length) {
        this.#out[0] = head.subarray(n);
        return;
      }
      this.#out.shift();
    }
  }
}

const BIN = 0x00;
const MARK = "\u0000";
const SECTION_MIN = 4096;

const toJson = (_key: string, v: unknown) => (v instanceof Uint8Array ? v.toBase64() : v);

function encodeBinary(value: unknown): Uint8Array | null {
  const sections: Uint8Array[] = [];
  let clash = false;
  const json = JSON.stringify(value, function (this: unknown, _key: string, v: unknown) {
    if (v instanceof Uint8Array) {
      sections.push(v);
      return { [MARK]: sections.length - 1 };
    }
    if (typeof v === "string" && v.length >= SECTION_MIN && v.isWellFormed()) {
      sections.push(enc.encode(v));
      return { [MARK]: -sections.length };
    }
    if (v !== null && typeof v === "object" && Object.hasOwn(v, MARK)) clash = true;
    return v;
  });
  if (clash || sections.length === 0 || sections.length > 0xffff) return null;
  const head = enc.encode(json);
  const fixed = 4 + 2 + 4 * sections.length;
  let size = 1 + 4 + fixed + head.length;
  for (const sec of sections) size += sec.length;
  const out = new Uint8Array(size);
  const view = new DataView(out.buffer);
  out[0] = BIN;
  view.setUint32(1, size - 5);
  view.setUint32(5, head.length);
  view.setUint16(9, sections.length);
  let at = 11;
  for (const sec of sections) {
    view.setUint32(at, sec.length);
    at += 4;
  }
  out.set(head, at);
  at += head.length;
  for (const sec of sections) {
    out.set(sec, at);
    at += sec.length;
  }
  return out;
}

function decodeBinary(frame: Uint8Array): unknown {
  const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
  const jsonLength = view.getUint32(5);
  const count = view.getUint16(9);
  let at = 11 + 4 * count;
  const head = frame.subarray(at, at + jsonLength);
  at += jsonLength;
  const sections: Uint8Array[] = [];
  for (let k = 0; k < count; k++) {
    const length = view.getUint32(11 + 4 * k);
    if (at + length > frame.length) throw new Error("section past the end of the frame");
    sections.push(frame.subarray(at, at + length));
    at += length;
  }
  if (at !== frame.length) throw new Error("frame length mismatch");
  return JSON.parse(dec.decode(head), (_key, v: unknown) => {
    if (v === null || typeof v !== "object" || !Object.hasOwn(v, MARK)) return v;
    const ref = (v as Record<string, unknown>)[MARK];
    if (typeof ref !== "number" || Object.keys(v).length !== 1) throw new Error("bad section mark");
    const sec = ref >= 0 ? sections[ref] : sections[-ref - 1];
    if (!sec) throw new Error("unknown section");
    return ref >= 0 ? sec.slice() : dec.decode(sec);
  });
}

class Framer {
  #chunks: Uint8Array[] = [];
  #size = 0;
  #scanned = 0;
  #need = 0;
  readonly #out: Outbox;
  rest: Uint8Array | null = null;

  constructor(
    private readonly socket: Socket<undefined>,
    private readonly onFrame: (frame: unknown) => boolean | undefined,
    private readonly binary = false,
  ) {
    this.#out = new Outbox(socket);
  }

  #take(n: number): Uint8Array {
    const out = new Uint8Array(n);
    let at = 0;
    while (at < n) {
      const head = this.#chunks[0] as Uint8Array;
      const part = Math.min(head.length, n - at);
      out.set(head.subarray(0, part), at);
      at += part;
      if (part === head.length) this.#chunks.shift();
      else this.#chunks[0] = head.subarray(part);
    }
    this.#size -= n;
    return out;
  }

  #byte(i: number): number {
    for (const c of this.#chunks) {
      if (i < c.length) return c[i] as number;
      i -= c.length;
    }
    return -1;
  }

  #newline(): number {
    let base = 0;
    for (const c of this.#chunks) {
      if (this.#scanned < base + c.length) {
        const i = c.indexOf(NL, Math.max(0, this.#scanned - base));
        if (i !== -1) return base + i;
      }
      base += c.length;
    }
    this.#scanned = this.#size;
    return -1;
  }

  push(chunk: Uint8Array) {
    if (chunk.length === 0) return;
    this.#chunks.push(chunk.slice());
    this.#size += chunk.length;
    while (this.#size > 0 && this.rest === null) {
      let parsed: unknown;
      if (this.#byte(0) === BIN) {
        if (this.#need === 0) {
          if (this.#size < 11) return;
          const len =
            ((this.#byte(1) << 24) >>> 0) +
            (this.#byte(2) << 16) +
            (this.#byte(3) << 8) +
            this.#byte(4);
          if (len + 5 > MAX_FRAME || len < 6) {
            this.socket.end();
            return;
          }
          this.#need = len + 5;
        }
        if (this.#size < this.#need) return;
        const frame = this.#take(this.#need);
        this.#need = 0;
        try {
          parsed = decodeBinary(frame);
        } catch {
          this.socket.end();
          return;
        }
      } else {
        const nl = this.#newline();
        if (nl === -1) {
          if (this.#size > MAX_FRAME) this.socket.end();
          return;
        }
        const frame = this.#take(nl + 1);
        this.#scanned = 0;
        try {
          parsed = JSON.parse(dec.decode(frame.subarray(0, nl)));
        } catch {
          this.socket.end();
          return;
        }
      }
      if (this.onFrame(parsed) === true) {
        this.rest = this.#size > 0 ? this.#take(this.#size) : new Uint8Array(0);
        return;
      }
    }
  }

  send(value: unknown) {
    const frame = this.binary ? encodeBinary(value) : null;
    this.#out.write(frame ?? enc.encode(`${JSON.stringify(value, toJson)}\n`));
  }

  flush() {
    this.#out.flush();
  }
}

export interface LinkTls {
  cert: string;
  key: string;
  ca: string;
  pins: string[];
  name?: string;
}

export interface TcpEndpoint {
  hostname: string;
  port: number;
  tls: LinkTls;
  via?: string;
}

export type Endpoint = string | TcpEndpoint;

const label = (e: Endpoint) => (typeof e === "string" ? e : `${e.hostname}:${e.port}`);

export function pinOf(spki: Uint8Array): string {
  return `sha256/${new Bun.CryptoHasher("sha256").update(spki).digest("base64")}`;
}

function isP256(spki: Uint8Array): boolean {
  return spki.length === P256_SPKI.length + 65 && P256_SPKI.every((byte, i) => spki[i] === byte);
}

export function peerRefusal(
  socket: Socket<undefined>,
  tls: LinkTls,
  peer: "client" | "server",
  authorizationError: Error | null,
  now = Date.now(),
): string | null {
  const failed = authorizationError ?? socket.getAuthorizationError();
  if (failed)
    return `peer certificate refused: ${(failed as Error & { code?: string }).code ?? failed.message}`;
  const raw = (socket.getPeerCertificate() as { raw?: Uint8Array } | null)?.raw;
  if (!raw) return "peer sent no certificate";
  let cert: ReturnType<typeof parseCertificate>;
  try {
    cert = parseCertificate(new Uint8Array(raw));
  } catch {
    return "peer certificate unreadable";
  }
  if (now < cert.notBefore || now > cert.notAfter) return "peer certificate outside its validity";
  if (!isP256(cert.spki)) return "peer key is not ECDSA P-256";
  const want = peer === "client" ? CLIENT_AUTH : SERVER_AUTH;
  const other = peer === "client" ? SERVER_AUTH : CLIENT_AUTH;
  const eku = cert.extKeyUsage ?? [];
  if (!eku.includes(want) || eku.includes(other)) return `peer certificate is not for ${peer} use`;
  if (!tls.pins.includes(pinOf(cert.spki))) return "peer key is not pinned";
  return null;
}

function tlsOptions(tls: LinkTls) {
  return { cert: tls.cert, key: tls.key, ca: tls.ca, secureOptions: TLS13_ONLY };
}

export interface RpcServer {
  stop(): void;
  reload(tls: LinkTls): void;
}

export interface StreamHandler {
  data(chunk: Uint8Array): void;
  drain(): void;
  close(): void;
}

export interface ServeOptions {
  mode?: "600" | "660";
  onRefused?(reason: string, remote: string): void;
  allow?(pin: string, method: string): boolean;
  stream?(params: unknown, socket: Socket<undefined>): StreamHandler;
}

const streamFrame = b.object({ stream: b.unknown() });

function peerPin(socket: Socket<undefined>): string {
  const raw = (socket.getPeerCertificate() as { raw?: Uint8Array } | null)?.raw;
  return raw ? pinOf(parseCertificate(new Uint8Array(raw)).spki) : "";
}

const usage = method(b.object({}), async () => ({ cpuSeconds: await cpuSeconds() }));

export async function serveRpc(
  endpoint: Endpoint,
  served: Methods,
  opts: ServeOptions = {},
): Promise<RpcServer> {
  const methods: Methods = { usage, ...served };
  const framers = new Map<Socket<undefined>, Framer>();
  const streams = new Map<Socket<undefined>, StreamHandler>();
  const respond = async (framer: Framer, frame: unknown, pin: string | null) => {
    const req = request.safeParse(frame);
    if (!req.success) return;
    const { id } = req.data;
    if (pin !== null && opts.allow && !opts.allow(pin, req.data.method)) {
      framer.send({
        id,
        error: { code: "forbidden", message: `${req.data.method} is not allowed for this peer` },
      });
      return;
    }
    const m = methods[req.data.method];
    if (!m) {
      framer.send({ id, error: { code: "invalid", message: `unknown method ${req.data.method}` } });
      return;
    }
    const params = m.params.safeParse(req.data.params);
    if (!params.success) {
      const issue = params.error.issues[0];
      framer.send({
        id,
        error: {
          code: "invalid",
          message: `invalid params: ${issue?.path.join(".")} ${issue?.message ?? ""}`.trim(),
        },
      });
      return;
    }
    let done = false;
    const ctx: CallContext = {
      progress: (value) => {
        if (!done) framer.send({ id, progress: value ?? null });
      },
    };
    try {
      const result = await m.handle(params.data, ctx);
      done = true;
      framer.send({ id, result: result ?? null });
    } catch (err) {
      done = true;
      const code = err instanceof RpcError ? err.code : "failed";
      const retryAfter = err instanceof RpcError ? err.retryAfter : undefined;
      framer.send({
        id,
        error: {
          code,
          message: (err as Error)?.message ?? String(err),
          ...(retryAfter !== undefined ? { retryAfter } : {}),
        },
      });
    }
  };
  const startStream = (s: Socket<undefined>, framer: Framer, frame: unknown, pin: string) => {
    if (!opts.stream || (opts.allow && !opts.allow(pin, "stream"))) {
      framer.send({
        error: { code: "forbidden", message: "streams are not allowed for this peer" },
      });
      s.end();
      return true;
    }
    const handler = opts.stream((frame as { stream: unknown }).stream, s);
    framers.delete(s);
    streams.set(s, handler);
    queueMicrotask(() => {
      if (framer.rest?.length) handler.data(framer.rest);
    });
    return true;
  };
  const accept = (s: Socket<undefined>, pin: string | null = null) => {
    let first = true;
    const framer = new Framer(
      s,
      (frame) => {
        const opening = first && pin !== null && streamFrame.safeParse(frame).success;
        first = false;
        if (opening) return startStream(s, framer, frame, pin);
        void respond(framer, frame, pin);
        return undefined;
      },
      pin === null,
    );
    framers.set(s, framer);
  };
  const closed = (s: Socket<undefined>) => {
    framers.delete(s);
    const stream = streams.get(s);
    streams.delete(s);
    stream?.close();
  };
  const handlers = {
    data(s: Socket<undefined>, chunk: Uint8Array) {
      const stream = streams.get(s);
      if (stream) stream.data(chunk);
      else framers.get(s)?.push(chunk);
    },
    drain(s: Socket<undefined>) {
      const stream = streams.get(s);
      if (stream) stream.drain();
      else framers.get(s)?.flush();
    },
    close: closed,
    error: closed,
  };
  if (typeof endpoint !== "string") {
    let tls = endpoint.tls;
    const listen = (): SocketListener<undefined> =>
      Bun.listen({
        hostname: endpoint.hostname,
        port: endpoint.port,
        tls: { ...tlsOptions(tls), requestCert: true, rejectUnauthorized: true },
        socket: {
          ...handlers,
          handshake(s, _success, authorizationError) {
            const refused = peerRefusal(s, tls, "client", authorizationError);
            if (refused) {
              opts.onRefused?.(refused, s.remoteAddress);
              s.end();
              return;
            }
            s.setKeepAlive(true, 15_000);
            accept(s, peerPin(s));
          },
        },
      });
    let listener = listen();
    const previous: SocketListener<undefined>[] = [];
    return {
      stop: () => {
        listener.stop(true);
        for (const l of previous.splice(0)) l.stop(true);
      },
      reload: (next) => {
        const before = tls;
        listener.stop(false);
        previous.push(listener);
        tls = next;
        try {
          listener = listen();
        } catch (err) {
          tls = before;
          listener = listen();
          throw err;
        }
      },
    };
  }
  await Bun.$`rm -f ${endpoint}`.quiet();
  const listener: UnixSocketListener<undefined> = Bun.listen({
    unix: endpoint,
    socket: { ...handlers, open: accept },
  });
  await Bun.$`chmod ${opts.mode ?? "660"} ${endpoint}`.quiet();
  return {
    stop: () => listener.stop(true),
    reload: () => {
      throw new RpcError("invalid", `${endpoint} is not a TLS listener`);
    },
  };
}

interface Pending {
  resolve(value: unknown): void;
  reject(err: RpcError): void;
  progress?: ((value: unknown) => void) | undefined;
  timer: ReturnType<typeof setTimeout>;
}

export interface CallOptions<R, P = unknown> {
  timeoutMs?: number;
  result?: b.Schema<R>;
  progress?: b.Schema<P>;
  onProgress?: (value: P) => void;
}

const BACKOFF_MIN = 250;
const BACKOFF_MAX = 30_000;

async function throughLink(
  via: string,
  to: TcpEndpoint,
  tls: TLSOptions,
  secured: SocketHandler<undefined>,
): Promise<Socket<undefined>> {
  const { promise, resolve, reject } = Promise.withResolvers<Socket<undefined>>();
  let head = "";
  let upgraded = false;
  const raw = await Bun.connect({
    unix: via,
    socket: {
      data(s, chunk) {
        if (upgraded) return;
        head += new TextDecoder().decode(chunk);
        const end = head.indexOf("\n");
        if (end < 0) return;
        upgraded = true;
        let answer: unknown;
        try {
          answer = JSON.parse(head.slice(0, end));
        } catch {
          answer = null;
        }
        const reply = streamReply.safeParse(answer);
        if (!reply.success) {
          reject(new RpcError("invalid", `${via}: bad answer to the link request`));
          s.end();
          return;
        }
        if ("error" in reply.data) {
          reject(new RpcError("unavailable", `${via}: ${reply.data.error.message}`));
          s.end();
          return;
        }
        const pair = s.upgradeTLS({ tls, socket: secured });
        if (pair) resolve(pair[1]);
        else reject(new RpcError("unavailable", "TLS over the link failed"));
      },
      close() {
        if (!upgraded) reject(new RpcError("unavailable", `${via}: closed`));
      },
      error(_s, err) {
        if (!upgraded) reject(new RpcError("unavailable", `${via}: ${err.message}`));
      },
    },
  });
  raw.write(`${JSON.stringify({ host: to.hostname, port: to.port })}\n`);
  return promise;
}

export class RpcClient {
  readonly #endpoint: Endpoint;
  #failures = 0;
  #retryAt = 0;
  #socket: Socket<undefined> | null = null;
  #framer: Framer | null = null;
  #connecting: Promise<Framer> | null = null;
  #nextId = 1;
  readonly #pending = new Map<number, Pending>();

  constructor(endpoint: Endpoint) {
    this.#endpoint = endpoint;
  }

  get path(): string {
    return label(this.#endpoint);
  }

  async #connect(): Promise<Framer> {
    if (this.#framer) return this.#framer;
    const wait = this.#retryAt - Date.now();
    if (wait > 0) {
      throw new RpcError(
        "unavailable",
        `${this.path}: waiting to reconnect`,
        Math.ceil(wait / 1000),
      );
    }
    this.#connecting ??= (async () => {
      try {
        const framer = await this.#open();
        this.#failures = 0;
        this.#retryAt = 0;
        return framer;
      } catch (err) {
        if (typeof this.#endpoint !== "string") {
          this.#failures++;
          this.#retryAt =
            Date.now() + Math.min(BACKOFF_MAX, BACKOFF_MIN * 2 ** (this.#failures - 1));
        }
        throw err instanceof RpcError
          ? err
          : new RpcError("unavailable", `${this.path}: ${(err as Error).message}`);
      } finally {
        this.#connecting = null;
      }
    })();
    return this.#connecting;
  }

  async #open(): Promise<Framer> {
    let framer: Framer | null = null;
    const handlers = {
      data: (_s: Socket<undefined>, chunk: Uint8Array) => framer?.push(chunk),
      drain: () => framer?.flush(),
      close: (s: Socket<undefined>) => this.#lost(s),
      error: (s: Socket<undefined>) => this.#lost(s),
    };
    const endpoint = this.#endpoint;
    if (typeof endpoint === "string") {
      const socket = await Bun.connect({ unix: endpoint, socket: handlers });
      framer = new Framer(socket, (frame) => void this.#onFrame(frame), true);
      this.#socket = socket;
      this.#framer = framer;
      return framer;
    }
    const { promise, resolve, reject } = Promise.withResolvers<void>();
    promise.catch(() => {});
    const timer = setTimeout(
      () => reject(new RpcError("unavailable", `${this.path}: handshake timed out`)),
      10_000,
    );
    let socket: Socket<undefined> | null = null;
    const tls = {
      ...tlsOptions(endpoint.tls),
      rejectUnauthorized: true,
      ...(endpoint.tls.name ? { serverName: endpoint.tls.name } : {}),
    };
    const secured: SocketHandler<undefined> = {
      ...handlers,
      close: (s) => {
        reject(new RpcError("unavailable", `${this.path}: closed during handshake`));
        this.#lost(s);
      },
      error: (s, err) => {
        reject(new RpcError("unavailable", `${this.path}: ${err.message}`));
        this.#lost(s);
      },
      handshake: (s, _success, authorizationError) => {
        const refused = peerRefusal(s, endpoint.tls, "server", authorizationError);
        if (refused) {
          reject(new RpcError("unavailable", `${this.path}: ${refused}`));
          s.end();
          return;
        }
        resolve();
      },
    };
    try {
      socket = endpoint.via
        ? await throughLink(endpoint.via, endpoint, tls, secured)
        : await Bun.connect({
            hostname: endpoint.hostname,
            port: endpoint.port,
            tls,
            socket: secured,
          });
      await promise;
    } catch (err) {
      socket?.end();
      throw err;
    } finally {
      clearTimeout(timer);
    }
    socket.setKeepAlive(true, 15_000);
    framer = new Framer(socket, (frame) => void this.#onFrame(frame));
    this.#socket = socket;
    this.#framer = framer;
    return framer;
  }

  #lost(s: Socket<undefined>) {
    if (s !== this.#socket) return;
    this.#socket = null;
    this.#framer = null;
    for (const [id, p] of this.#pending) {
      clearTimeout(p.timer);
      p.reject(new RpcError("lost", `connection to ${this.path} lost`));
      this.#pending.delete(id);
    }
  }

  #onFrame(frame: unknown) {
    const step = progress.safeParse(frame);
    if (step.success) {
      this.#pending.get(step.data.id)?.progress?.(step.data.progress);
      return;
    }
    const res = response.safeParse(frame);
    if (!res.success) return;
    const p = this.#pending.get(res.data.id);
    if (!p) return;
    this.#pending.delete(res.data.id);
    clearTimeout(p.timer);
    if ("error" in res.data) {
      const e = res.data.error;
      p.reject(new RpcError(e.code, e.message, e.retryAfter));
    } else p.resolve(res.data.result);
  }

  async call<R = unknown, P = unknown>(
    method: string,
    params: unknown,
    opts: CallOptions<R, P> = {},
  ): Promise<R> {
    const framer = await this.#connect();
    const id = this.#nextId++;
    const timeoutMs = opts.timeoutMs ?? 30_000;
    const raw = await new Promise<unknown>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.#pending.delete(id);
        reject(new RpcError("timeout", `${method} timed out after ${timeoutMs} ms`));
      }, timeoutMs);
      const onProgress = opts.onProgress;
      const schema = opts.progress;
      const progress = onProgress
        ? (value: unknown) => {
            if (!schema) return onProgress(value as P);
            const checked = schema.safeParse(value);
            if (checked.success) onProgress(checked.data);
          }
        : undefined;
      this.#pending.set(id, { resolve, reject, progress, timer });
      framer.send({ id, method, params });
    });
    if (!opts.result) return raw as R;
    const checked = opts.result.safeParse(raw);
    if (!checked.success) {
      throw new RpcError("invalid", `${method} returned an invalid result`);
    }
    return checked.data;
  }

  close() {
    const s = this.#socket;
    if (s) {
      this.#lost(s);
      s.end();
    }
  }
}

const streamReply = b.union([
  b.object({ ok: b.literal(true) }),
  b.object({ error: b.object({ code: b.string(), message: b.string() }) }),
]);

export class RawStream {
  #socket: Socket<undefined> | null = null;
  #out: Outbox | null = null;
  #queued: Uint8Array[] = [];
  #reader: ((chunk: Uint8Array) => void) | null = null;
  #onClose: (() => void) | null = null;
  #closed = false;

  attach(socket: Socket<undefined>) {
    this.#socket = socket;
    this.#out = new Outbox(socket);
  }

  read(reader: (chunk: Uint8Array) => void, onClose: () => void) {
    this.#reader = reader;
    this.#onClose = onClose;
    for (const chunk of this.#queued.splice(0)) reader(chunk);
    if (this.#closed) onClose();
  }

  push(chunk: Uint8Array) {
    if (this.#reader) this.#reader(chunk);
    else this.#queued.push(chunk);
  }

  closed() {
    if (this.#closed) return;
    this.#closed = true;
    this.#onClose?.();
  }

  write(bytes: Uint8Array) {
    this.#out?.write(bytes);
  }

  flush() {
    this.#out?.flush();
  }

  end() {
    this.#socket?.end();
  }
}

export async function openStream(
  endpoint: TcpEndpoint,
  params: unknown,
  timeoutMs = 10_000,
): Promise<RawStream> {
  const at = label(endpoint);
  const stream = new RawStream();
  let head: Uint8Array = new Uint8Array(0);
  let open = false;
  const { promise, resolve, reject } = Promise.withResolvers<void>();
  promise.catch(() => {});
  const timer = setTimeout(
    () => reject(new RpcError("timeout", `${at}: no answer to the stream request`)),
    timeoutMs,
  );
  let socket: Socket<undefined> | null = null;
  try {
    socket = await Bun.connect({
      hostname: endpoint.hostname,
      port: endpoint.port,
      tls: {
        ...tlsOptions(endpoint.tls),
        rejectUnauthorized: true,
        ...(endpoint.tls.name ? { serverName: endpoint.tls.name } : {}),
      },
      socket: {
        handshake(s, _success, authorizationError) {
          const refused = peerRefusal(s, endpoint.tls, "server", authorizationError);
          if (refused) {
            reject(new RpcError("unavailable", `${at}: ${refused}`));
            s.end();
            return;
          }
          stream.attach(s);
          stream.write(enc.encode(`${JSON.stringify({ stream: params })}\n`));
        },
        data(s, chunk) {
          if (open) {
            stream.push(chunk);
            return;
          }
          head = concat([head, chunk]);
          const i = head.indexOf(NL);
          if (i < 0) {
            if (head.length > MAX_FRAME) s.end();
            return;
          }
          let answer: unknown;
          try {
            answer = JSON.parse(dec.decode(head.subarray(0, i)));
          } catch {
            answer = null;
          }
          const reply = streamReply.safeParse(answer);
          if (!reply.success) {
            reject(new RpcError("invalid", `${at}: bad answer to the stream request`));
            s.end();
            return;
          }
          if ("error" in reply.data) {
            reject(new RpcError(reply.data.error.code, reply.data.error.message));
            s.end();
            return;
          }
          open = true;
          const rest = head.slice(i + 1);
          if (rest.length > 0) stream.push(rest);
          resolve();
        },
        drain() {
          stream.flush();
        },
        close() {
          reject(new RpcError("lost", `${at}: closed`));
          stream.closed();
        },
        error(_s, err) {
          reject(new RpcError("lost", `${at}: ${err.message}`));
          stream.closed();
        },
      },
    });
    await promise;
  } catch (err) {
    socket?.end();
    throw err instanceof RpcError
      ? err
      : new RpcError("unavailable", `${at}: ${(err as Error).message}`);
  } finally {
    clearTimeout(timer);
  }
  socket.setKeepAlive(true, 15_000);
  return stream;
}
