export const MAX_LINKS = 200;
export const MAX_URL = 2000;

export const PIXEL = Uint8Array.fromBase64(
  "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7",
);

const NAME = /[A-Za-z][A-Za-z0-9:-]*/y;
const SPACE = /\s/;
const IGNORED = new Set(["link", "base"]);
const RAW = new Set(["script", "style"]);
const ENTITIES: Record<string, string> = { amp: "&", quot: '"', apos: "'", lt: "<", gt: ">" };

export function decodeEntities(s: string): string {
  return s.replace(/&(#x[0-9a-f]+|#[0-9]+|[a-z]+);/gi, (m, e: string) => {
    if (e[0] === "#") {
      const n =
        e[1] === "x" || e[1] === "X"
          ? Number.parseInt(e.slice(2), 16)
          : Number.parseInt(e.slice(1), 10);
      return n > 0 && n <= 0x10ffff ? String.fromCodePoint(n) : m;
    }
    return ENTITIES[e.toLowerCase()] ?? m;
  });
}

interface Href {
  start: number;
  end: number;
  url: string;
}

function hrefs(html: string): Href[] {
  const out: Href[] = [];
  const lower = html.toLowerCase();
  const n = html.length;
  let i = 0;
  for (;;) {
    i = html.indexOf("<", i);
    if (i === -1) break;
    NAME.lastIndex = i + 1;
    const m = NAME.exec(html);
    if (!m) {
      i++;
      continue;
    }
    const tag = m[0].toLowerCase();
    let p = NAME.lastIndex;
    let href: Href | null = null;
    let skip = false;
    for (;;) {
      while (p < n && (SPACE.test(html[p] as string) || html[p] === "/")) p++;
      if (p >= n || html[p] === ">") break;
      const nameStart = p;
      while (p < n && !/[\s=>/]/.test(html[p] as string)) p++;
      const attr = lower.slice(nameStart, p);
      while (p < n && SPACE.test(html[p] as string)) p++;
      if (html[p] !== "=") {
        if (attr === "data-no-track") skip = true;
        continue;
      }
      p++;
      while (p < n && SPACE.test(html[p] as string)) p++;
      let start = p;
      let end: number;
      const q = html[p];
      if (q === '"' || q === "'") {
        start = p + 1;
        end = html.indexOf(q, start);
        if (end === -1) end = n;
        p = end + 1;
      } else {
        while (p < n && !/[\s>]/.test(html[p] as string)) p++;
        end = p;
      }
      if (attr === "data-no-track") skip = true;
      if (attr === "href" && !href) {
        href = { start, end, url: decodeEntities(html.slice(start, end)).trim() };
      }
    }
    if (href && !skip && !IGNORED.has(tag)) out.push(href);
    if (RAW.has(tag)) {
      const close = lower.indexOf(`</${tag}`, p);
      i = close === -1 ? n : close;
    } else {
      i = p + 1;
    }
  }
  return out;
}

const trackable = (url: string) =>
  url.length <= MAX_URL && /^https?:\/\/[^\s/?#]+/i.test(url) && !/\s/.test(url);

export function trackableLinks(html: string): string[] {
  const out = new Set<string>();
  for (const h of hrefs(html)) {
    if (out.size >= MAX_LINKS) break;
    if (trackable(h.url)) out.add(h.url);
  }
  return [...out];
}

export function rewriteHtml(
  html: string,
  link: (url: string) => string | null,
  pixel: string | null,
): string {
  let out = "";
  let at = 0;
  for (const h of hrefs(html)) {
    const next = trackable(h.url) ? link(h.url) : null;
    if (next === null) continue;
    out += html.slice(at, h.start) + next;
    at = h.end;
  }
  out += html.slice(at);
  if (pixel === null) return out;
  const img = `<img src="${pixel}" width="1" height="1" alt="" style="width:1px;height:1px;border:0">`;
  const body = out.toLowerCase().lastIndexOf("</body");
  return body === -1 ? out + img : out.slice(0, body) + img + out.slice(body);
}
