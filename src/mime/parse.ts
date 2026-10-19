export interface MimeLimits {
  maxDepth: number;
  maxParts: number;
  maxHeaders: number;
}

export const MIME_LIMITS: MimeLimits = { maxDepth: 5, maxParts: 50, maxHeaders: 500 };

export class MimeParseError extends Error {}

export interface MimePart {
  headers: Map<string, string[]>;
  type: string;
  params: Map<string, string>;
  charset: string | null;
  disposition: string | null;
  filename: string | null;
  content: Uint8Array;
  body: string;
  parts: MimePart[];
}

const utf8Strict = new TextDecoder("utf-8", { fatal: true });
const utf8 = new TextDecoder("utf-8");
const cp1252 = new TextDecoder("windows-1252");
const enc = new TextEncoder();
const MAX_SECTIONS = 64;

function trimWs(s: string): string {
  return s.replace(/^[ \t\r\n]+|[ \t\r\n]+$/g, "");
}

export function toBinary(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    out += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return out;
}

export function fromBinary(s: string): Uint8Array {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
  return out;
}

function binaryOf(input: Uint8Array | string): string {
  if (typeof input !== "string") return toBinary(input);
  return /[\u0100-\uffff]/.test(input) ? toBinary(enc.encode(input)) : input;
}

function isAscii(bytes: Uint8Array): boolean {
  for (const b of bytes) if (b > 0x7f) return false;
  return true;
}

function guess(bytes: Uint8Array): string {
  if (isAscii(bytes)) return cp1252.decode(bytes);
  try {
    return utf8Strict.decode(bytes);
  } catch {
    return cp1252.decode(bytes);
  }
}

export function decodeCharset(bytes: Uint8Array, charset: string | null): string {
  const label = charset?.trim().toLowerCase().replace(/^"|"$/g, "") ?? "";
  if (!label || label === "us-ascii" || label === "ascii" || label === "unknown-8bit") {
    return guess(bytes);
  }
  if (label === "utf-8" || label === "utf8") return utf8.decode(bytes);
  try {
    return new TextDecoder(label as Bun.Encoding).decode(bytes);
  } catch {
    return guess(bytes);
  }
}

export function binaryText(s: string): string {
  return guess(fromBinary(s));
}

export function decodeBase64(s: string): Uint8Array {
  let clean = s.replace(/[^A-Za-z0-9+/]/g, "");
  if (clean.length % 4 === 1) clean = clean.slice(0, -1);
  try {
    return Uint8Array.fromBase64(clean);
  } catch {
    return new Uint8Array();
  }
}

function hex(c: number): number {
  if (c >= 48 && c <= 57) return c - 48;
  if (c >= 65 && c <= 70) return c - 55;
  if (c >= 97 && c <= 102) return c - 87;
  return -1;
}

export function decodeQuotedPrintable(s: string, header = false): Uint8Array {
  const text = header ? s : s.replace(/=[ \t]*\r?\n/g, "");
  const out = new Uint8Array(text.length);
  let n = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c === 61 && i + 2 < text.length) {
      const hi = hex(text.charCodeAt(i + 1));
      const lo = hex(text.charCodeAt(i + 2));
      if (hi >= 0 && lo >= 0) {
        out[n++] = (hi << 4) | lo;
        i += 2;
        continue;
      }
    }
    out[n++] = header && c === 95 ? 32 : c & 0xff;
  }
  return out.subarray(0, n);
}

const WORD = /=\?([^?\s]+)\?([BbQq])\?([^?\s]*)\?=/g;

export function decodeWords(value: string): string {
  const pieces: { charset: string | null; data: string | Uint8Array }[] = [];
  let last = 0;
  for (const m of value.matchAll(WORD)) {
    const between = value.slice(last, m.index);
    const prev = pieces.at(-1);
    const prevWord = prev !== undefined && prev.charset !== null;
    if (between && !(prevWord && /^[ \t\r\n]+$/.test(between))) {
      pieces.push({ charset: null, data: between });
    }
    const charset = (m[1] as string).split("*")[0]?.toLowerCase() ?? "";
    const raw = m[3] as string;
    const bytes =
      (m[2] as string).toLowerCase() === "b" ? decodeBase64(raw) : decodeQuotedPrintable(raw, true);
    const tail = pieces.at(-1);
    if (tail && tail.charset === charset && tail.data instanceof Uint8Array) {
      const joined = new Uint8Array(tail.data.length + bytes.length);
      joined.set(tail.data);
      joined.set(bytes, tail.data.length);
      tail.data = joined;
    } else {
      pieces.push({ charset, data: bytes });
    }
    last = (m.index ?? 0) + m[0].length;
  }
  if (last < value.length) pieces.push({ charset: null, data: value.slice(last) });
  return pieces
    .map((p) =>
      p.charset === null
        ? binaryText(p.data as string)
        : decodeCharset(p.data as Uint8Array, p.charset),
    )
    .join("");
}

function splitHead(text: string): { head: string; body: string } {
  if (/^\r?\n/.test(text)) return { head: "", body: text.replace(/^\r?\n/, "") };
  const m = /\r?\n\r?\n/.exec(text);
  if (!m) return { head: text, body: "" };
  return { head: text.slice(0, m.index), body: text.slice(m.index + m[0].length) };
}

export function parseHeaderBlock(
  head: string,
  limits: MimeLimits = MIME_LIMITS,
): Map<string, string[]> {
  const out = new Map<string, string[]>();
  let count = 0;
  let name: string | null = null;
  let value = "";
  const flush = () => {
    if (name === null) return;
    if (++count > limits.maxHeaders) throw new MimeParseError("too many headers");
    const list = out.get(name) ?? [];
    list.push(trimWs(value.replace(/[ \t\r\n]+/g, " ")));
    out.set(name, list);
    name = null;
  };
  const lines = head.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] as string;
    if (i === 0 && line.startsWith("From ")) continue;
    if ((line.startsWith(" ") || line.startsWith("\t")) && name !== null) {
      value += line;
      continue;
    }
    flush();
    const colon = line.indexOf(":");
    if (colon <= 0) continue;
    const n = line.slice(0, colon).trim().toLowerCase();
    if (!/^[\x21-\x39\x3b-\x7e]+$/.test(n)) continue;
    name = n;
    value = line.slice(colon + 1);
  }
  flush();
  return out;
}

function splitParams(value: string): string[] {
  const out: string[] = [];
  let cur = "";
  let quoted = false;
  let depth = 0;
  for (let i = 0; i < value.length; i++) {
    const ch = value[i] as string;
    if (quoted) {
      if (ch === "\\" && i + 1 < value.length) {
        cur += ch + (value[++i] as string);
        continue;
      }
      if (ch === '"') quoted = false;
      cur += ch;
    } else if (ch === '"') {
      quoted = true;
      cur += ch;
    } else if (ch === "(") {
      depth++;
    } else if (ch === ")" && depth > 0) {
      depth--;
    } else if (depth > 0) {
    } else if (ch === ";") {
      out.push(cur);
      cur = "";
    } else {
      cur += ch;
    }
  }
  out.push(cur);
  return out;
}

function unquote(v: string): string {
  const t = trimWs(v);
  if (t.length >= 2 && t.startsWith('"') && t.endsWith('"')) {
    return t.slice(1, -1).replace(/\\(.)/g, "$1");
  }
  return t;
}

function percentBytes(s: string): Uint8Array {
  const out: number[] = [];
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 37 && i + 2 < s.length) {
      const hi = hex(s.charCodeAt(i + 1));
      const lo = hex(s.charCodeAt(i + 2));
      if (hi >= 0 && lo >= 0) {
        out.push((hi << 4) | lo);
        i += 2;
        continue;
      }
    }
    out.push(c & 0xff);
  }
  return Uint8Array.from(out);
}

export function parseParams(value: string): { value: string; params: Map<string, string> } {
  const [first = "", ...rest] = splitParams(value);
  const params = new Map<string, string>();
  const sections = new Map<string, { index: number; encoded: boolean; value: string }[]>();
  for (const p of rest) {
    const eq = p.indexOf("=");
    if (eq <= 0) continue;
    const key = p.slice(0, eq).trim().toLowerCase();
    const raw = p.slice(eq + 1);
    const m = /^([^*]+)\*(?:(\d{1,3})(\*)?)?$/.exec(key);
    if (!m) {
      if (!params.has(key)) params.set(key, unquote(raw));
      continue;
    }
    const base = m[1] as string;
    const list = sections.get(base) ?? [];
    if (list.length >= MAX_SECTIONS) continue;
    const index = m[2] === undefined ? 0 : Number(m[2]);
    const encoded = m[2] === undefined || m[3] === "*";
    list.push({ index, encoded, value: encoded ? trimWs(raw) : unquote(raw) });
    sections.set(base, list);
  }
  for (const [base, list] of sections) {
    list.sort((a, b) => a.index - b.index);
    let charset: string | null = null;
    const chunks: Uint8Array[] = [];
    list.forEach((s, i) => {
      let v = s.value;
      if (i === 0 && s.encoded) {
        const q = /^([^']*)'[^']*'(.*)$/s.exec(v);
        if (q) {
          charset = (q[1] as string) || null;
          v = q[2] as string;
        }
      }
      chunks.push(s.encoded ? percentBytes(v) : fromBinary(v));
    });
    const total = chunks.reduce((n, c) => n + c.length, 0);
    const all = new Uint8Array(total);
    let at = 0;
    for (const c of chunks) {
      all.set(c, at);
      at += c.length;
    }
    params.set(base, charset ? toBinary(enc.encode(decodeCharset(all, charset))) : toBinary(all));
  }
  return { value: first.trim().toLowerCase(), params };
}

function contentType(
  headers: Map<string, string[]>,
  fallback: string,
): { type: string; params: Map<string, string> } {
  const raw = headers.get("content-type")?.[0];
  if (!raw) return { type: fallback, params: new Map() };
  const { value, params } = parseParams(raw);
  return {
    type: /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/.test(value) ? value : "text/plain",
    params,
  };
}

function splitMultipart(body: string, boundary: string): string[] {
  const dash = `--${boundary}`;
  const out: string[] = [];
  let start = -1;
  let from = 0;
  while (from <= body.length) {
    const at = body.indexOf(dash, from);
    if (at < 0) break;
    const lineStart = at === 0 || body[at - 1] === "\n";
    const nl = body.indexOf("\n", at);
    const end = nl < 0 ? body.length : nl;
    const rest = body.slice(at + dash.length, end).replace(/\r$/, "");
    const close = rest.startsWith("--");
    if (!lineStart || trimWs(close ? rest.slice(2) : rest) !== "") {
      from = at + dash.length;
      continue;
    }
    if (start >= 0) {
      let stop = at;
      if (body[stop - 1] === "\n") stop--;
      if (body[stop - 1] === "\r") stop--;
      out.push(body.slice(start, Math.max(start, stop)));
    }
    if (close) return out;
    start = nl < 0 ? body.length : nl + 1;
    from = start;
  }
  if (start >= 0 && start < body.length) out.push(body.slice(start));
  return out;
}

function transferDecode(body: string, encoding: string | undefined): Uint8Array {
  const e = encoding?.trim().toLowerCase();
  if (e === "base64") return decodeBase64(body);
  if (e === "quoted-printable") return decodeQuotedPrintable(body);
  return fromBinary(body);
}

function isMessage(type: string): boolean {
  return type === "message/rfc822" || type === "message/global";
}

export function parseMime(input: Uint8Array | string, limits: MimeLimits = MIME_LIMITS): MimePart {
  let count = 0;
  const walk = (text: string, depth: number, fallback: string): MimePart => {
    if (depth > limits.maxDepth) throw new MimeParseError("MIME nesting too deep");
    if (++count > limits.maxParts) throw new MimeParseError("too many MIME parts");
    const { head, body } = splitHead(text);
    const headers = parseHeaderBlock(head, limits);
    const { type, params } = contentType(headers, fallback);
    const disp = headers.get("content-disposition")?.[0];
    const d = disp ? parseParams(disp) : null;
    const name = d?.params.get("filename") ?? params.get("name");
    const part: MimePart = {
      headers,
      type,
      params,
      charset: params.get("charset")?.toLowerCase() ?? null,
      disposition: d?.value || null,
      filename: name === undefined ? null : decodeWords(name),
      content: new Uint8Array(),
      body: "",
      parts: [],
    };
    const boundary = params.get("boundary");
    if (type.startsWith("multipart/") && boundary && boundary.length <= 200) {
      const inner = type === "multipart/digest" ? "message/rfc822" : "text/plain";
      for (const s of splitMultipart(body, boundary)) part.parts.push(walk(s, depth + 1, inner));
      return part;
    }
    part.content = transferDecode(body, headers.get("content-transfer-encoding")?.[0]);
    if (isMessage(type)) {
      const inner = toBinary(part.content);
      part.body = binaryText(inner);
      part.parts.push(walk(inner, depth + 1, "text/plain"));
    } else {
      part.body = decodeCharset(part.content, part.charset);
    }
    return part;
  };
  return walk(binaryOf(input), 0, "text/plain");
}

export function headerText(part: MimePart, name: string): string | null {
  const v = part.headers.get(name.toLowerCase())?.[0];
  return v === undefined ? null : decodeWords(v);
}

export function walkParts(part: MimePart): MimePart[] {
  return [part, ...part.parts.flatMap(walkParts)];
}
