import type { Socket } from "bun";
import type { Via } from "../egress/tunnel.ts";

export interface Reply {
  code: number;
  enhanced: string | null;
  lines: string[];
}

export interface TlsInfo {
  authorized: boolean;
  error: string | null;
  version: string | null;
  cipher: string | null;
}

export class SmtpError extends Error {
  constructor(
    readonly kind: "timeout" | "closed" | "network" | "protocol" | "tls",
    message: string,
  ) {
    super(message);
  }
}

export interface ConnectOptions {
  host: string;
  port: number;
  localAddress?: string;
  timeoutMs: number;
  via?: Via | undefined;
}

const MAX_LINE = 4096;
const MAX_REPLY_LINES = 200;
const TLS_1_2 = 0x0303;

const dec = new TextDecoder();
const enc = new TextEncoder();

export function replyText(r: Reply): string {
  return `${r.code} ${r.lines.join(" ")}`.trim();
}

export type TranscriptLine = [ms: number, who: "C" | "S" | "-", text: string];

export interface Transcript {
  start: number;
  lines: TranscriptLine[];
}

const MAX_TRANSCRIPT_LINES = 300;
const MAX_TRANSCRIPT_TEXT = 1000;

const redact = (line: string) => line.replace(/^(AUTH\s+\S+)\s+\S.*$/i, "$1 [hidden]");

export class SmtpConnection {
  transcript: Transcript | null = null;
  private socket!: Socket<undefined>;
  private buffer = "";
  private waiter: (() => void) | null = null;
  private drainWaiter: (() => void) | null = null;
  private closedError: SmtpError | null = null;
  private tlsHandshake: ((ok: boolean, err: Error | null) => void) | null = null;
  readonly remoteAddress: string;

  private constructor(remoteAddress: string) {
    this.remoteAddress = remoteAddress;
  }

  private handlers() {
    return {
      data: (s: Socket<undefined>, chunk: Uint8Array) => {
        if (s !== this.socket) return;
        this.buffer += dec.decode(chunk, { stream: true });
        this.wake();
      },
      drain: (s: Socket<undefined>) => {
        if (s !== this.socket) return;
        const w = this.drainWaiter;
        this.drainWaiter = null;
        w?.();
      },
      close: () => this.fail(new SmtpError("closed", "connection closed by remote server")),
      end: () => this.fail(new SmtpError("closed", "connection closed by remote server")),
      error: (_s: Socket<undefined>, err: Error) =>
        this.fail(new SmtpError("network", err.message)),
      handshake: (_s: Socket<undefined>, ok: boolean, err: Error | null) => {
        const h = this.tlsHandshake;
        this.tlsHandshake = null;
        h?.(ok, err);
      },
    };
  }

  private wake() {
    const w = this.waiter;
    this.waiter = null;
    w?.();
    const d = this.drainWaiter;
    if (this.closedError) {
      this.drainWaiter = null;
      d?.();
    }
  }

  private fail(err: SmtpError) {
    if (!this.closedError) this.closedError = err;
    this.wake();
    const h = this.tlsHandshake;
    this.tlsHandshake = null;
    h?.(false, err);
  }

  get closed(): boolean {
    return this.closedError !== null;
  }

  static async connect(opts: ConnectOptions): Promise<SmtpConnection> {
    const via = opts.via;
    const unix = via
      ? await via
          .open(opts.host, opts.port, opts.localAddress ?? "", opts.timeoutMs)
          .catch((err) => {
            const timedOut = (err as { code?: string }).code === "timeout";
            throw new SmtpError(
              timedOut ? "timeout" : "network",
              `connect to ${opts.host}:${opts.port} through ${via.name}: ${(err as Error).message}`,
            );
          })
      : null;
    const conn = new SmtpConnection(opts.host);
    return new Promise((resolve, reject) => {
      let settled = false;
      const settle = (fn: () => void) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        fn();
      };
      const timer = setTimeout(
        () =>
          settle(() =>
            reject(new SmtpError("timeout", `connect to ${opts.host}:${opts.port} timed out`)),
          ),
        opts.timeoutMs,
      );
      const h = conn.handlers();
      const socket = {
        ...h,
        open(s: Socket<undefined>) {
          conn.socket = s;
          s.setNoDelay(true);
          if (settled) s.end();
          else settle(() => resolve(conn));
        },
        connectError(_s: Socket<undefined>, err: Error) {
          settle(() =>
            reject(
              new SmtpError("network", `connect to ${opts.host}:${opts.port}: ${err.message}`),
            ),
          );
        },
      };
      const tcp = {
        hostname: opts.host,
        port: opts.port,
        ...(opts.localAddress ? { localAddress: opts.localAddress } : {}),
        socket,
      };
      (unix ? Bun.connect({ unix, socket }) : Bun.connect(tcp)).catch((err: Error) =>
        settle(() =>
          reject(new SmtpError("network", `connect to ${opts.host}:${opts.port}: ${err.message}`)),
        ),
      );
    });
  }

  private takeLine(): string | null {
    const i = this.buffer.indexOf("\n");
    if (i < 0) {
      if (this.buffer.length > MAX_LINE) throw new SmtpError("protocol", "reply line too long");
      return null;
    }
    const line = this.buffer.slice(0, i).replace(/\r$/, "");
    this.buffer = this.buffer.slice(i + 1);
    if (line.length > MAX_LINE) throw new SmtpError("protocol", "reply line too long");
    return line;
  }

  note(who: "C" | "S" | "-", text: string) {
    const t = this.transcript;
    if (!t || t.lines.length >= MAX_TRANSCRIPT_LINES) return;
    t.lines.push([Date.now() - t.start, who, text.slice(0, MAX_TRANSCRIPT_TEXT)]);
  }

  async readReply(timeoutMs: number): Promise<Reply> {
    const deadline = Date.now() + timeoutMs;
    const lines: string[] = [];
    const raw: string[] = [];
    let code = 0;
    for (;;) {
      const line = this.takeLine();
      if (line === null) {
        if (this.closedError) throw this.closedError;
        const left = deadline - Date.now();
        if (left <= 0) throw new SmtpError("timeout", "timed out waiting for server reply");
        await new Promise<void>((resolve) => {
          const t = setTimeout(resolve, left);
          this.waiter = () => {
            clearTimeout(t);
            resolve();
          };
        });
        continue;
      }
      raw.push(line);
      const m = /^([2-5]\d\d)([ -]|$)(.*)$/.exec(line);
      if (!m) {
        this.note("S", raw.join("\n"));
        throw new SmtpError("protocol", `malformed reply: ${line.slice(0, 100)}`);
      }
      const c = Number(m[1]);
      if (code && c !== code) throw new SmtpError("protocol", "reply code changed mid-reply");
      code = c;
      lines.push(m[3] as string);
      if (lines.length > MAX_REPLY_LINES) throw new SmtpError("protocol", "reply too long");
      if (m[2] !== "-") break;
    }
    this.note("S", raw.join("\n"));
    const em = /^([245]\.\d{1,3}\.\d{1,3})(\s|$)/.exec(lines[0] ?? "");
    let enhanced: string | null = null;
    if (em && (em[1] as string)[0] === String(code)[0]) {
      enhanced = em[1] as string;
      for (let i = 0; i < lines.length; i++) {
        lines[i] = (lines[i] as string).replace(/^[245]\.\d{1,3}\.\d{1,3}\s?/, "");
      }
    }
    return { code, enhanced, lines };
  }

  hasBufferedData(): boolean {
    return this.buffer.length > 0;
  }

  async write(
    data: string | Uint8Array,
    timeoutMs: number,
    o: { content?: boolean } = {},
  ): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    let bytes = typeof data === "string" ? enc.encode(data) : data;
    if (o.content) this.note("C", `[message content, ${bytes.length} bytes]`);
    else if (typeof data === "string") {
      for (const line of data.split("\r\n")) if (line) this.note("C", redact(line));
    }
    while (bytes.length > 0) {
      if (this.closedError) throw this.closedError;
      const n = this.socket.write(bytes);
      if (n < 0) throw new SmtpError("closed", "connection closed while writing");
      bytes = bytes.subarray(n);
      if (bytes.length === 0) break;
      const left = deadline - Date.now();
      if (left <= 0) throw new SmtpError("timeout", "timed out while sending data");
      await new Promise<void>((resolve) => {
        const t = setTimeout(resolve, left);
        this.drainWaiter = () => {
          clearTimeout(t);
          resolve();
        };
      });
    }
  }

  startTls(serverName: string, timeoutMs: number, ca?: string): Promise<TlsInfo> {
    if (this.buffer.length > 0) {
      return Promise.reject(new SmtpError("protocol", "server sent data before the TLS handshake"));
    }
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.tlsHandshake = null;
        reject(new SmtpError("timeout", "TLS handshake timed out"));
      }, timeoutMs);
      this.tlsHandshake = (ok, err) => {
        clearTimeout(timer);
        if (this.closedError && !ok && err === this.closedError) {
          reject(new SmtpError("tls", `TLS handshake failed: ${err.message}`));
          return;
        }
        const s = this.socket;
        const version = s.getTLSVersion() || null;
        if (!version || (!ok && !s.getCipher()?.name)) {
          reject(new SmtpError("tls", `TLS handshake failed: ${err?.message ?? "no session"}`));
          return;
        }
        const authErr = s.getAuthorizationError();
        this.note(
          "-",
          `TLS ${version} ${s.getCipher()?.name ?? ""}, certificate ${ok && !authErr ? "verified" : `not verified (${authErr ? ((authErr as Error & { code?: string }).code ?? authErr.message) : "handshake"})`}`,
        );
        resolve({
          authorized: ok && !authErr,
          error: authErr ? ((authErr as Error & { code?: string }).code ?? authErr.message) : null,
          version,
          cipher: s.getCipher()?.name ?? null,
        });
      };
      const tls = {
        serverName,
        rejectUnauthorized: false,
        minVersion: TLS_1_2,
        ...(ca ? { ca } : {}),
      };
      const [, tlsSocket] = this.socket.upgradeTLS({ tls, socket: this.handlers() });
      this.socket = tlsSocket;
    });
  }

  peerChain(): Uint8Array[] {
    type Peer = { raw?: Uint8Array; issuerCertificate?: Peer };
    const out: Uint8Array[] = [];
    try {
      const getPeer = this.socket.getPeerCertificate as unknown as (abbreviated: boolean) => Peer;
      let cert: Peer | undefined = getPeer.call(this.socket, false);
      const seen = new Set<Peer>();
      while (cert?.raw && !seen.has(cert) && out.length < 16) {
        seen.add(cert);
        out.push(new Uint8Array(cert.raw));
        cert = cert.issuerCertificate;
      }
    } catch {
      return out;
    }
    return out;
  }

  close() {
    this.closedError ??= new SmtpError("closed", "connection closed");
    this.socket.end();
  }
}
