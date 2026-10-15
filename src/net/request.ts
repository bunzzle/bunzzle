import type { Socket } from "bun";
import { familyOf, forbiddenReason, sameAddress } from "../dns/ip.ts";
import type { PostOptions } from "./post.ts";

export interface RequestInput {
  method: "GET" | "POST" | "PUT" | "DELETE";
  url: string;
  headers?: Record<string, string>;
  body?: string;
  maxBody?: number;
}

export type RequestResult =
  | { ok: true; status: number; headers: Map<string, string>; body: string }
  | { ok: false; error: string };

const enc = new TextEncoder();
const dec = new TextDecoder();

function concat(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

function indexOf(hay: Uint8Array, needle: number[], from = 0): number {
  outer: for (let i = from; i <= hay.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) if (hay[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
}

const CRLF = [13, 10];
const CRLFCRLF = [13, 10, 13, 10];

function dechunk(bytes: Uint8Array): Uint8Array | null {
  const parts: Uint8Array[] = [];
  let at = 0;
  for (;;) {
    const end = indexOf(bytes, CRLF, at);
    if (end < 0) return null;
    const size = Number.parseInt(dec.decode(bytes.subarray(at, end)).split(";")[0] ?? "", 16);
    if (Number.isNaN(size)) return null;
    if (size === 0) return concat(parts);
    const start = end + 2;
    if (start + size > bytes.length) return null;
    parts.push(bytes.subarray(start, start + size));
    at = start + size + 2;
  }
}

export async function resolveSafe(
  host: string,
  o: PostOptions,
): Promise<{ ip: string } | { error: string }> {
  const candidates: string[] = [];
  if (familyOf(host)) candidates.push(host);
  else {
    for (const family of o.families ?? [4]) {
      try {
        const answer = await o.resolver.query(host, family === 4 ? "A" : "AAAA");
        for (const r of answer.records) {
          if (r.type === "A" || r.type === "AAAA") candidates.push(r.address);
        }
      } catch {}
    }
  }
  if (candidates.length === 0) return { error: `cannot resolve ${host}` };
  const allowed = candidates.filter(
    (ip) =>
      (o.allowPrivate || forbiddenReason(ip) === null) &&
      !(o.ownAddresses ?? []).some((own) => sameAddress(own, ip)),
  );
  if (allowed.length === 0) return { error: `${host} points to a private or forbidden network` };
  return { ip: allowed[0] as string };
}

export async function guardedRequest(req: RequestInput, o: PostOptions): Promise<RequestResult> {
  let u: URL;
  try {
    u = new URL(req.url);
  } catch {
    return { ok: false, error: "invalid URL" };
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") {
    return { ok: false, error: "only http and https URLs" };
  }
  if (u.username || u.password) return { ok: false, error: "credentials in URLs are not allowed" };
  const host = u.hostname.replace(/^\[|\]$/g, "");
  const tls = u.protocol === "https:";
  const port = Number(u.port || (tls ? 443 : 80));
  const target = await resolveSafe(host, o);
  if ("error" in target) return { ok: false, error: target.error };
  const payload = enc.encode(req.body ?? "");
  const lines = [
    `${req.method} ${u.pathname || "/"}${u.search} HTTP/1.1`,
    `Host: ${u.host}`,
    "User-Agent: Bunzzle/1",
    "Connection: close",
    ...(req.method === "POST" || req.method === "PUT" ? [`Content-Length: ${payload.length}`] : []),
    ...Object.entries(req.headers ?? {}).map(([k, v]) => `${k}: ${v}`),
  ];
  const request = concat([enc.encode(`${lines.join("\r\n")}\r\n\r\n`), payload]);
  const timeoutMs = o.timeoutMs ?? 10_000;
  const maxBody = req.maxBody ?? 64 * 1024;

  return new Promise<RequestResult>((resolve) => {
    const chunks: Uint8Array[] = [];
    let size = 0;
    let settled = false;
    let socket: Socket<undefined> | null = null;
    let pending = request;
    const parse = (final: boolean): RequestResult | null => {
      const all = concat(chunks);
      const headEnd = indexOf(all, CRLFCRLF);
      if (headEnd < 0) return final ? { ok: false, error: "invalid HTTP response" } : null;
      const head = dec.decode(all.subarray(0, headEnd)).split("\r\n");
      const m = /^HTTP\/1\.[01] (\d{3})/.exec(head[0] ?? "");
      if (!m) return { ok: false, error: "invalid HTTP response" };
      const headers = new Map<string, string>();
      for (const line of head.slice(1)) {
        const c = line.indexOf(":");
        if (c > 0) headers.set(line.slice(0, c).trim().toLowerCase(), line.slice(c + 1).trim());
      }
      const rest = all.subarray(headEnd + 4);
      const status = Number(m[1]);
      if (req.method === "POST" && req.maxBody === undefined && !final) {
        return { ok: true, status, headers, body: "" };
      }
      let body: Uint8Array | null;
      if (headers.get("transfer-encoding")?.toLowerCase().includes("chunked")) {
        body = dechunk(rest);
        if (!body) return final ? { ok: false, error: "truncated chunked body" } : null;
      } else if (headers.has("content-length")) {
        const n = Number(headers.get("content-length"));
        if (n > maxBody) return { ok: false, error: "response too large" };
        if (rest.length < n) return final ? { ok: false, error: "truncated body" } : null;
        body = rest.subarray(0, n);
      } else {
        if (!final) return null;
        body = rest;
      }
      return { ok: true, status, headers, body: dec.decode(body) };
    };
    const finish = (r: RequestResult) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket?.end();
      resolve(r);
    };
    const timer = setTimeout(
      () => finish({ ok: false, error: `timed out after ${timeoutMs} ms` }),
      timeoutMs,
    );
    const flush = (s: Socket<undefined>) => {
      while (pending.length > 0) {
        const n = s.write(pending);
        if (n <= 0) return;
        pending = pending.subarray(n);
      }
    };
    Bun.connect({
      hostname: target.ip,
      port,
      ...(tls
        ? { tls: { serverName: host, rejectUnauthorized: true, ...(o.ca ? { ca: o.ca } : {}) } }
        : {}),
      socket: {
        open(s) {
          socket = s;
          flush(s);
        },
        drain(s) {
          flush(s);
        },
        data(_s, chunk) {
          chunks.push(chunk);
          size += chunk.length;
          if (size > maxBody + 16 * 1024) return finish({ ok: false, error: "response too large" });
          const r = parse(false);
          if (r) finish(r);
        },
        close() {
          finish(parse(true) ?? { ok: false, error: "connection closed before a response" });
        },
        error(_s, err) {
          finish({ ok: false, error: err.message });
        },
        connectError(_s, err) {
          finish({ ok: false, error: err.message });
        },
      },
    }).catch((err: Error) => finish({ ok: false, error: err.message }));
  });
}
