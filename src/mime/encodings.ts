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

const HEX = "0123456789ABCDEF";

function qpByte(b: number): string {
  return `=${HEX[b >> 4]}${HEX[b & 15]}`;
}

export function quotedPrintable(text: string): string {
  const out: string[] = [];
  for (const line of toCrlf(text).split("\r\n")) {
    const bytes = enc.encode(line);
    let cur = "";
    for (let i = 0; i < bytes.length; i++) {
      const b = bytes[i] as number;
      const last = i === bytes.length - 1;
      let piece: string;
      if (b === 0x3d || b < 0x20 || b > 0x7e) piece = b === 0x09 && !last ? "\t" : qpByte(b);
      else if (b === 0x20 && last) piece = "=20";
      else piece = String.fromCharCode(b);
      if (cur.length + piece.length > 75) {
        out.push(`${cur}=`);
        cur = "";
      }
      cur += piece;
    }
    out.push(cur);
  }
  return out.join("\r\n");
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
