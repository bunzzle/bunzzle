import type { Socket, UnixSocketListener } from "bun";
import { b } from "../validate/schema.ts";

const MAX_FRAME = 64 * 1024 * 1024;
const NL = 0x0a;
const enc = new TextEncoder();
const dec = new TextDecoder();

export type RpcErrorCode = "unavailable" | "lost" | "timeout" | "invalid" | "failed";

export class RpcError extends Error {
  constructor(
    readonly code: RpcErrorCode | (string & {}),
    message: string,
  ) {
    super(message);
  }
}

export interface Method {
  params: b.Schema;
  handle(params: unknown): unknown;
}

export function method<P, R>(params: b.Schema<P>, handle: (params: P) => Promise<R> | R): Method {
  return { params, handle: handle as (params: unknown) => unknown };
}

export type Methods = Record<string, Method>;

const request = b.object({ id: b.number().int(), method: b.string(), params: b.unknown() });
const response = b.union([
  b.object({ id: b.number().int(), result: b.unknown() }),
  b.object({
    id: b.number().int(),
    error: b.object({ code: b.string(), message: b.string() }),
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

export interface RpcServer {
  stop(): void;
}

export interface ServeOptions {
  mode?: "600" | "660";
}

export async function serveRpc(
  path: string,
  methods: Methods,
  opts: ServeOptions = {},
): Promise<RpcServer> {
  await Bun.$`rm -f ${path}`.quiet();
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
    try {
      framer.send({ id, result: (await m.handle(params.data)) ?? null });
    } catch (err) {
      const code = err instanceof RpcError ? err.code : "failed";
      framer.send({ id, error: { code, message: (err as Error)?.message ?? String(err) } });
    }
  };
  const listener: UnixSocketListener<undefined> = Bun.listen({
    unix: path,
    socket: {
      open(s) {
        const framer = new Framer(s, (frame) => void respond(framer, frame));
        framers.set(s, framer);
      },
      data(s, chunk) {
        framers.get(s)?.push(chunk);
      },
      drain(s) {
        framers.get(s)?.flush();
      },
      close(s) {
        framers.delete(s);
      },
      error(s) {
        framers.delete(s);
      },
    },
  });
  await Bun.$`chmod ${opts.mode ?? "660"} ${path}`.quiet();
  return { stop: () => listener.stop(true) };
}

interface Pending {
  resolve(value: unknown): void;
  reject(err: RpcError): void;
  timer: ReturnType<typeof setTimeout>;
}

export interface CallOptions<R> {
  timeoutMs?: number;
  result?: b.Schema<R>;
}

export class RpcClient {
  readonly #path: string;
  #socket: Socket<undefined> | null = null;
  #framer: Framer | null = null;
  #connecting: Promise<Framer> | null = null;
  #nextId = 1;
  readonly #pending = new Map<number, Pending>();

  constructor(path: string) {
    this.#path = path;
  }

  get path(): string {
    return this.#path;
  }

  async #connect(): Promise<Framer> {
    if (this.#framer) return this.#framer;
    this.#connecting ??= (async () => {
      try {
        let framer: Framer | null = null;
        const socket = await Bun.connect({
          unix: this.#path,
          socket: {
            data: (_s, chunk) => framer?.push(chunk),
            drain: () => framer?.flush(),
            close: (s) => this.#lost(s),
            error: (s) => this.#lost(s),
          },
        });
        framer = new Framer(socket, (frame) => this.#onFrame(frame));
        this.#socket = socket;
        this.#framer = framer;
        return framer;
      } catch (err) {
        throw new RpcError("unavailable", `${this.#path}: ${(err as Error).message}`);
      } finally {
        this.#connecting = null;
      }
    })();
    return this.#connecting;
  }

  #lost(s: Socket<undefined>) {
    if (s !== this.#socket) return;
    this.#socket = null;
    this.#framer = null;
    for (const [id, p] of this.#pending) {
      clearTimeout(p.timer);
      p.reject(new RpcError("lost", `connection to ${this.#path} lost`));
      this.#pending.delete(id);
    }
  }

  #onFrame(frame: unknown) {
    const res = response.safeParse(frame);
    if (!res.success) return;
    const p = this.#pending.get(res.data.id);
    if (!p) return;
    this.#pending.delete(res.data.id);
    clearTimeout(p.timer);
    if ("error" in res.data) p.reject(new RpcError(res.data.error.code, res.data.error.message));
    else p.resolve(res.data.result);
  }

  async call<R = unknown>(method: string, params: unknown, opts: CallOptions<R> = {}): Promise<R> {
    const framer = await this.#connect();
    const id = this.#nextId++;
    const timeoutMs = opts.timeoutMs ?? 30_000;
    const raw = await new Promise<unknown>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.#pending.delete(id);
        reject(new RpcError("timeout", `${method} timed out after ${timeoutMs} ms`));
      }, timeoutMs);
      this.#pending.set(id, { resolve, reject, timer });
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
