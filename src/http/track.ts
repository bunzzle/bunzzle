import type { Logger } from "../core/log.ts";
import type { RpcClient } from "../ipc/rpc.ts";
import { domainOf, parseAddress } from "../mime/address.ts";
import { PIXEL, rewriteHtml, trackableLinks } from "../tracking/html.ts";
import { b } from "../validate/schema.ts";
import { ApiError, fromRpc } from "./errors.ts";
import type { SendRequest } from "./send.ts";

export const trackResult = b
  .object({
    host: b.string(),
    opens: b.boolean(),
    clicks: b.boolean(),
    open: b.string().nullable(),
    links: b.array(b.string()),
  })
  .nullable();

export type TrackTokens = NonNullable<b.infer<typeof trackResult>>;

export type Track = (p: {
  domain: string;
  id: string;
  urls: string[];
  opens?: boolean;
  clicks?: boolean;
}) => Promise<TrackTokens | null>;

export interface Tracked {
  req: SendRequest;
  id?: string;
  tracking?: { opens: boolean; clicks: boolean };
}

const TOKEN = /^[a-z2-7]{20,80}$/;
const ENCODED = /^[A-Za-z0-9_-]{1,2700}$/;
const utf8 = new TextDecoder("utf-8", { fatal: true });

export const encodeUrl = (url: string) =>
  new TextEncoder().encode(url).toBase64({ alphabet: "base64url", omitPadding: true });

function decodeUrl(encoded: string): string | null {
  if (!ENCODED.test(encoded)) return null;
  try {
    const url = utf8.decode(Uint8Array.fromBase64(encoded, { alphabet: "base64url" }));
    return /^https?:\/\/[^\s/?#]+/i.test(url) ? url : null;
  } catch {
    return null;
  }
}

export async function applyTracking(req: SendRequest, track: Track): Promise<Tracked> {
  const want = req.tracking;
  if (req.html === undefined) {
    if (want?.opens || want?.clicks) {
      throw new ApiError(422, "validation_error", "Open and click tracking need an `html` body.");
    }
    return { req };
  }
  let domain: string;
  try {
    domain = domainOf(parseAddress(req.from).address);
  } catch {
    return { req };
  }
  const id = Bun.randomUUIDv7();
  const urls = trackableLinks(req.html);
  const t = await track({
    domain,
    id,
    urls,
    ...(want?.opens !== undefined ? { opens: want.opens } : {}),
    ...(want?.clicks !== undefined ? { clicks: want.clicks } : {}),
  });
  if (!t) return { req };
  const base = `https://${t.host}`;
  const tokens = new Map(t.links.map((token, i) => [urls[i] as string, token]));
  const html = rewriteHtml(
    req.html,
    (url) => {
      const token = tokens.get(url);
      return token ? `${base}/c/${token}/${encodeUrl(url)}` : null;
    },
    t.open ? `${base}/o/${t.open}` : null,
  );
  return { req: { ...req, html }, id, tracking: { opens: t.opens, clicks: t.clicks } };
}

const NO_STORE = { "cache-control": "no-store, private", "referrer-policy": "no-referrer" };

const pixel = () =>
  new Response(PIXEL, {
    headers: { ...NO_STORE, "content-type": "image/gif", "content-length": String(PIXEL.length) },
  });

const notFound = () =>
  new Response("This link is not valid.", {
    status: 404,
    headers: { ...NO_STORE, "content-type": "text/plain; charset=utf-8" },
  });

const agentOf = (req: Request) => req.headers.get("user-agent")?.slice(0, 1000) ?? undefined;

type Routed = Request & { params: Record<string, string> };

export function trackRoutes(core: RpcClient, log: Logger) {
  return {
    "/o/:token": (req: Routed) => {
      const token = req.params["token"] ?? "";
      if (req.method === "GET" && TOKEN.test(token)) {
        const userAgent = agentOf(req);
        core
          .call("trackOpen", { token, ...(userAgent ? { userAgent } : {}) }, { timeoutMs: 10_000 })
          .catch((err: Error) => log.warn("could not record an open", { error: err.message }));
      }
      return pixel();
    },
    "/c/:token/:url": async (req: Routed) => {
      const token = req.params["token"] ?? "";
      const url = decodeUrl(req.params["url"] ?? "");
      if (!TOKEN.test(token) || url === null) return notFound();
      const userAgent = agentOf(req);
      try {
        await core.call(
          "trackClick",
          { token, url, record: req.method === "GET", ...(userAgent ? { userAgent } : {}) },
          { timeoutMs: 10_000 },
        );
      } catch (err) {
        if (fromRpc(err).status === 404) return notFound();
        return new Response("Please try again in a minute.", { status: 503, headers: NO_STORE });
      }
      return new Response(null, { status: 302, headers: { ...NO_STORE, location: url } });
    },
  };
}

export interface TrackCert {
  serverName: string;
  cert: string;
  key: string;
}

export async function trackCerts(dir: string): Promise<TrackCert[]> {
  if ((await Bun.$`test -d ${dir}`.nothrow().quiet()).exitCode !== 0) return [];
  const out: TrackCert[] = [];
  for await (const f of new Bun.Glob("*/cert.pem").scan({ cwd: dir })) {
    const host = f.slice(0, -"/cert.pem".length);
    const key = Bun.file(`${dir}/${host}/key.pem`);
    if (!(await key.exists())) continue;
    out.push({
      serverName: host,
      cert: await Bun.file(`${dir}/${f}`).text(),
      key: await key.text(),
    });
  }
  return out.sort((a, b) => a.serverName.localeCompare(b.serverName));
}

export function startTrackServer(o: {
  core: RpcClient;
  log: Logger;
  hostname: string;
  port: number;
  certs: TrackCert[];
}) {
  return Bun.serve({
    hostname: o.hostname,
    port: o.port,
    tls: o.certs,
    routes: trackRoutes(o.core, o.log),
    fetch: () => notFound(),
  });
}
