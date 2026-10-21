export interface HeaderField {
  name: string;
  raw: string;
}

export function splitMessage(raw: string): { headers: HeaderField[]; body: string } {
  const sep = raw.indexOf("\r\n\r\n");
  const head = sep < 0 ? raw : raw.slice(0, sep);
  const body = sep < 0 ? "" : raw.slice(sep + 4);
  const headers: HeaderField[] = [];
  for (const line of head.split("\r\n")) {
    if (line === "") continue;
    const last = headers[headers.length - 1];
    if ((line.startsWith(" ") || line.startsWith("\t")) && last) {
      last.raw += `\r\n${line}`;
      continue;
    }
    const colon = line.indexOf(":");
    if (colon <= 0) continue;
    headers.push({ name: line.slice(0, colon), raw: line });
  }
  return { headers, body };
}

export function relaxedHeader(raw: string): string {
  const colon = raw.indexOf(":");
  const name = raw.slice(0, colon).trim().toLowerCase();
  const value = raw
    .slice(colon + 1)
    .replace(/\r\n/g, "")
    .replace(/[ \t]+/g, " ")
    .trim();
  return `${name}:${value}`;
}

export function relaxedBody(body: string): string {
  const lines = body.split("\r\n").map((l) => l.replace(/[ \t]+/g, " ").replace(/ $/, ""));
  while (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();
  return lines.length === 0 ? "" : `${lines.join("\r\n")}\r\n`;
}

export function simpleBody(body: string): string {
  let end = body.length;
  while (end >= 2 && body.slice(end - 2, end) === "\r\n") end -= 2;
  return `${body.slice(0, end)}\r\n`;
}

export function headerData(
  headers: HeaderField[],
  names: string[],
  canon: (raw: string) => string = relaxedHeader,
): string {
  const used = new Map<string, number>();
  let out = "";
  for (const name of names) {
    const instances = headers.filter((h) => h.name.toLowerCase() === name);
    const k = used.get(name) ?? 0;
    used.set(name, k + 1);
    const h = instances[instances.length - 1 - k];
    if (h) out += `${canon(h.raw)}\r\n`;
  }
  return out;
}

export async function bodyHash(body: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(relaxedBody(body)));
  return new Uint8Array(digest).toBase64();
}
