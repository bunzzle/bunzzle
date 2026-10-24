import type { Socket, SocketListener, UnixSocketListener } from "bun";
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

class Framer {
  #chunks: Uint8Array[] = [];
  #size = 0;
  #out: Uint8Array[] = [];

  constructor(
    private readonly socket: Socket<undefined>,
    private readonly onFrame: (frame: unknown) => void,
  ) {}

  push(chunk: Uint8Array) {
    let start = 0;
    for (let i = 0; i < chunk.length; i++) {
      if (chunk[i] !== NL) continue;
      this.#chunks.push(chunk.subarray(start, i));
      const frame = concat(this.#chunks);
      this.#chunks = [];
      this.#size = 0;
      start = i + 1;
      let parsed: unknown;
      try {
        parsed = JSON.parse(dec.decode(frame));
      } catch {
        this.socket.end();
        return;
      }
      this.onFrame(parsed);
    }
    if (start < chunk.length) {
      this.#size += chunk.length - start;
      if (this.#size > MAX_FRAME) {
        this.socket.end();
        return;
      }
      this.#chunks.push(chunk.slice(start));
    }
  }

  send(value: unknown) {
    this.#out.push(enc.encode(`${JSON.stringify(value)}\n`));
    this.flush();
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

export interface ServeOptions {
  mode?: "600" | "660";
  onRefused?(reason: string, remote: string): void;
}

const usage = method(b.object({}), async () => ({ cpuSeconds: await cpuSeconds() }));

export async function serveRpc(
  endpoint: Endpoint,
  served: Methods,
  opts: ServeOptions = {},
): Promise<RpcServer> {
  const methods: Methods = { usage, ...served };
  const framers = new Map<Socket<undefined>, Framer>();
  const respond = async (framer: Framer, frame: unknown) => {
    const req = request.safeParse(frame);
    if (!req.success) return;
    const { id } = req.data;
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
  const accept = (s: Socket<undefined>) => {
    const framer = new Framer(s, (frame) => void respond(framer, frame));
    framers.set(s, framer);
  };
  const handlers = {
    data(s: Socket<undefined>, chunk: Uint8Array) {
      framers.get(s)?.push(chunk);
    },
    drain(s: Socket<undefined>) {
      framers.get(s)?.flush();
    },
    close(s: Socket<undefined>) {
      framers.delete(s);
    },
    error(s: Socket<undefined>) {
      framers.delete(s);
    },
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
            accept(s);
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
      framer = new Framer(socket, (frame) => this.#onFrame(frame));
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
        },
      });
      await promise;
    } catch (err) {
      socket?.end();
      throw err;
    } finally {
      clearTimeout(timer);
    }
    socket.setKeepAlive(true, 15_000);
    framer = new Framer(socket, (frame) => this.#onFrame(frame));
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
