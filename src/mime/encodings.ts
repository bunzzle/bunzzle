const enc = new TextEncoder();

export function isAscii(s: string): boolean {
  return !/[\u0080-\uffff]/.test(s);
}

export function toCrlf(s: string): string {
  return s.replace(/\r\n|\r|\n/g, "\r\n");
}

export function base64Lines(data: Uint8Array, width = 76): string {
  const b64 = data.toBase64();
  const lines: string[] = [];
  for (let i = 0; i < b64.length; i += width) lines.push(b64.slice(i, i + width));
  return lines.join("\r\n");
}

const HEX = new TextEncoder().encode("0123456789ABCDEF");
const LITERAL = new Uint8Array(256);
for (let b = 0x21; b <= 0x7e; b++) if (b !== 0x3d) LITERAL[b] = 1;
const ascii = new TextDecoder("latin1");

export function quotedPrintable(text: string): string {
  const src = enc.encode(toCrlf(text));
  const out = new Uint8Array(src.length * 4 + 16);
  let o = 0;
  let col = 0;
  for (let i = 0; i < src.length; i++) {
    const b = src[i] as number;
    if (b === 0x0d && src[i + 1] === 0x0a) {
      out[o++] = 0x0d;
      out[o++] = 0x0a;
      col = 0;
      i++;
      continue;
    }
    const literal =
      LITERAL[b] === 1 || ((b === 0x20 || b === 0x09) && i + 1 < src.length && src[i + 1] !== 0x0d);
    const width = literal ? 1 : 3;
    if (col + width > 75) {
      out[o++] = 0x3d;
      out[o++] = 0x0d;
      out[o++] = 0x0a;
      col = 0;
    }
    if (literal) {
      out[o++] = b;
    } else {
      out[o++] = 0x3d;
      out[o++] = HEX[b >> 4] as number;
      out[o++] = HEX[b & 15] as number;
    }
    col += width;
  }
  return ascii.decode(out.subarray(0, o));
}

export function needsQuotedPrintable(text: string): boolean {
  return !isAscii(text) || text.split(/\r\n|\r|\n/).some((l) => l.length > 76 || / $/.test(l));
}

export function encodedWords(value: string): string {
  const words: string[] = [];
  let chunk = "";
  const maxBytes = 45;
  for (const ch of value) {
    if (enc.encode(chunk + ch).length > maxBytes) {
      words.push(chunk);
      chunk = "";
    }
    chunk += ch;
  }
  if (chunk) words.push(chunk);
  return words.map((w) => `=?UTF-8?B?${enc.encode(w).toBase64()}?=`).join(" ");
}

export function unstructured(value: string): string {
  if (isAscii(value) && !value.includes("=?")) return value;
  return encodedWords(value);
}

export function foldHeader(name: string, value: string, width = 78): string {
  const line = `${name}: ${value}`;
  if (line.length <= width) return line;
  const parts = line.split(" ");
  const lines: string[] = [];
  let cur = parts[0] as string;
  for (const p of parts.slice(1)) {
    if (cur.length + 1 + p.length > width && cur !== parts[0]) {
      lines.push(cur);
      cur = ` ${p}`;
    } else {
      cur += ` ${p}`;
    }
  }
  lines.push(cur);
  return lines.join("\r\n");
}

const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

export function rfc5322Date(d: Date): string {
  const p = (n: number) => String(n).padStart(2, "0");
  return `${DAYS[d.getUTCDay()]}, ${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())} +0000`;
}
