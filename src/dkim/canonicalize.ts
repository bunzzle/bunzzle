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
