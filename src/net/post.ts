import type { Socket } from "bun";
import { type Family, familyOf, forbiddenReason, sameAddress } from "../dns/ip.ts";
import type { Resolver } from "../dns/resolver.ts";

export interface PostOptions {
  resolver: Resolver;
  allowPrivate?: boolean;
  ownAddresses?: string[];
  families?: Family[];
  timeoutMs?: number;
  ca?: string;
}

export type PostResult = { ok: true; status: number } | { ok: false; error: string };

const MAX_RESPONSE = 64 * 1024;
const enc = new TextEncoder();
const dec = new TextDecoder();

async function addressesOf(host: string, o: PostOptions): Promise<string[]> {
  if (familyOf(host)) return [host];
  const out: string[] = [];
  for (const family of o.families ?? [4]) {
    try {
      const answer = await o.resolver.query(host, family === 4 ? "A" : "AAAA");
      for (const r of answer.records) {
        if (r.type === "A" || r.type === "AAAA") out.push(r.address);
      }
    } catch {}
  }
  return out;
}

export async function guardedPost(
  url: string,
  headers: Record<string, string>,
  body: string,
  o: PostOptions,
): Promise<PostResult> {
  let u: URL;
  try {
    u = new URL(url);
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
  const candidates = await addressesOf(host, o);
  if (candidates.length === 0) return { ok: false, error: `cannot resolve ${host}` };
  const allowed = candidates.filter(
    (ip) =>
      (o.allowPrivate || forbiddenReason(ip) === null) &&
      !(o.ownAddresses ?? []).some((own) => sameAddress(own, ip)),
  );
  if (allowed.length === 0) {
    return { ok: false, error: `${host} points to a private or forbidden network` };
  }
  const ip = allowed[0] as string;
  const payload = enc.encode(body);
  const lines = [
    `POST ${u.pathname || "/"}${u.search} HTTP/1.1`,
    `Host: ${u.host}`,
    "User-Agent: Bunzzle-Webhooks/1",
    "Content-Type: application/json",
    `Content-Length: ${payload.length}`,
    "Connection: close",
    ...Object.entries(headers).map(([k, v]) => `${k}: ${v}`),
  ];
  const request = new Uint8Array([...enc.encode(`${lines.join("\r\n")}\r\n\r\n`), ...payload]);
  const timeoutMs = o.timeoutMs ?? 10_000;

  return new Promise<PostResult>((resolve) => {
    let received = "";
    let settled = false;
    let socket: Socket<undefined> | null = null;
    let pending = request;
    const finish = (r: PostResult) => {
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
    const onData = (chunk: Uint8Array) => {
      received += dec.decode(chunk, { stream: true });
      if (received.length > MAX_RESPONSE) received = received.slice(0, MAX_RESPONSE);
      const m = /^HTTP\/1\.[01] (\d{3})/.exec(received);
      if (m) finish({ ok: true, status: Number(m[1]) });
      else if (received.includes("\r\n")) finish({ ok: false, error: "invalid HTTP response" });
    };
    Bun.connect({
      hostname: ip,
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
          onData(chunk);
        },
        close() {
          finish({ ok: false, error: "connection closed before a response" });
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
