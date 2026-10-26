import { encodedWords, isAscii } from "./encodings.ts";
import { decodeWords } from "./parse.ts";

export interface Address {
  address: string;
  name?: string;
}

export class AddressError extends Error {}

const LOCAL_ATOM =
  /^[A-Za-z0-9!#$%&'*+/=?^_`{|}~\u0080-\uffff-]+(\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~\u0080-\uffff-]+)*$/;
const ATEXT_PHRASE = /^[A-Za-z0-9!#$%&'*+/=?^_`{|}~ -]+$/;

export function asciiDomain(domain: string): string {
  const d = domain.trim().toLowerCase().replace(/\.$/, "");
  if (isAscii(d)) return d;
  try {
    return new URL(`http://${d}`).hostname;
  } catch {
    throw new AddressError(`invalid domain: ${domain}`);
  }
}

export function normalizeDomain(raw: string): string {
  const domain = asciiDomain(raw);
  if (!/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(domain) || domain.length > 253) {
    throw new AddressError(`invalid domain: ${raw}`);
  }
  return domain;
}

export function normalizeAddress(raw: string): string {
  const s = raw.trim();
  const at = s.lastIndexOf("@");
  if (at <= 0 || at === s.length - 1) throw new AddressError(`invalid email address: ${raw}`);
  const local = s.slice(0, at);
  if (local.length > 64 || !LOCAL_ATOM.test(local)) {
    throw new AddressError(`invalid email address: ${raw}`);
  }
  try {
    return `${local}@${normalizeDomain(s.slice(at + 1))}`;
  } catch {
    throw new AddressError(`invalid email address: ${raw}`);
  }
}

export function soleAddressDomain(value: string): string {
  const list = parseAddressList(value);
  if (list.length !== 1) throw new AddressError("expected exactly one address");
  return normalizeDomain(domainOf((list[0] as Address).address));
}

export function domainOf(address: string): string {
  return address.slice(address.lastIndexOf("@") + 1);
}

export function parseAddress(raw: string): Address {
  const s = raw.trim();
  const m = /^(.*?)\s*<([^<>]+)>$/.exec(s);
  if (!m) return { address: normalizeAddress(s) };
  let name = (m[1] as string).trim();
  if (name.startsWith('"') && name.endsWith('"') && name.length >= 2) {
    name = name.slice(1, -1).replace(/\\(.)/g, "$1");
  }
  const address = normalizeAddress(m[2] as string);
  return name ? { address, name } : { address };
}

function displayName(name: string): string {
  if (/[\r\n]/.test(name)) throw new AddressError("display name contains a line break");
  if (!isAscii(name)) return encodedWords(name);
  if (ATEXT_PHRASE.test(name)) return name;
  return `"${name.replace(/(["\\])/g, "\\$1")}"`;
}

export function formatAddress(a: Address): string {
  return a.name ? `${displayName(a.name)} <${a.address}>` : a.address;
}

export function needsSmtpUtf8(address: string): boolean {
  return !isAscii(address);
}

interface Token {
  kind: "word" | "quoted" | "literal" | "special";
  value: string;
  space: boolean;
}

const SPECIALS = '<>@,;:."[]()\\';
const DOT_ATOM =
  /^[A-Za-z0-9!#$%&'*+/=?^_`{|}~\u0080-\uffff-]+(\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~\u0080-\uffff-]+)*$/;

function tokenize(value: string): Token[] {
  const out: Token[] = [];
  let i = 0;
  let space = false;
  const push = (kind: Token["kind"], text: string) => {
    out.push({ kind, value: text, space });
    space = false;
  };
  while (i < value.length) {
    const ch = value[i] as string;
    if (ch === " " || ch === "\t" || ch === "\r" || ch === "\n") {
      space = true;
      i++;
    } else if (ch === "(") {
      let depth = 0;
      for (; i < value.length; i++) {
        const c = value[i];
        if (c === "\\") i++;
        else if (c === "(") depth++;
        else if (c === ")" && --depth === 0) break;
      }
      if (depth !== 0) throw new AddressError("unclosed comment");
      space = true;
      i++;
    } else if (ch === '"') {
      let text = "";
      for (i++; ; i++) {
        if (i >= value.length) throw new AddressError("unclosed quoted string");
        const c = value[i] as string;
        if (c === '"') break;
        if (c === "\\") text += value[++i] ?? "";
        else if (c !== "\r" && c !== "\n") text += c;
      }
      i++;
      push("quoted", text);
    } else if (ch === "[") {
      const end = value.indexOf("]", i);
      if (end < 0 || /[[\\]/.test(value.slice(i + 1, end))) {
        throw new AddressError("bad domain literal");
      }
      push("literal", value.slice(i, end + 1).replace(/\s+/g, ""));
      i = end + 1;
    } else if ("<>@,;:.".includes(ch)) {
      push("special", ch);
      i++;
    } else if (SPECIALS.includes(ch) || ch < " " || ch === "\x7f") {
      throw new AddressError(`unexpected ${JSON.stringify(ch)}`);
    } else {
      let j = i + 1;
      while (j < value.length) {
        const c = value[j] as string;
        if (SPECIALS.includes(c) || c <= " " || c === "\x7f") break;
        j++;
      }
      push("word", value.slice(i, j));
      i = j;
    }
  }
  return out;
}

export function parseAddressList(value: string): Address[] {
  const toks = tokenize(value);
  const out: Address[] = [];
  let p = 0;
  const at = (v: string) => toks[p]?.kind === "special" && toks[p]?.value === v;
  const expect = (v: string) => {
    if (!at(v)) throw new AddressError(`expected ${JSON.stringify(v)}`);
    p++;
  };
  const phrase = (): string => {
    let text = "";
    for (
      let t = toks[p];
      t && (t.kind === "word" || t.kind === "quoted" || at("."));
      t = toks[++p]
    ) {
      text += `${text && t.space ? " " : ""}${t.value}`;
    }
    return text;
  };
  const addrSpec = (): string => {
    const parts: string[] = [];
    for (;;) {
      const t = toks[p];
      if (t?.kind !== "word" && t?.kind !== "quoted")
        throw new AddressError("expected a local part");
      parts.push(t.value);
      p++;
      if (!at(".")) break;
      p++;
    }
    const joined = parts.join(".");
    const local = DOT_ATOM.test(joined) ? joined : `"${joined.replace(/(["\\])/g, "\\$1")}"`;
    expect("@");
    const first = toks[p];
    if (first?.kind === "literal") {
      p++;
      return `${local}@${first.value}`;
    }
    const labels: string[] = [];
    for (;;) {
      const t = toks[p];
      if (t?.kind !== "word") throw new AddressError("expected a domain");
      labels.push(t.value);
      p++;
      if (!at(".")) break;
      p++;
    }
    return `${local}@${labels.join(".")}`;
  };
  const mailbox = (): Address => {
    const start = p;
    const name = decodeWords(phrase());
    if (!at("<")) {
      p = start;
      return { address: addrSpec() };
    }
    p++;
    if (at("@")) {
      while (p < toks.length && !at(":")) p++;
      expect(":");
    }
    const address = addrSpec();
    expect(">");
    return name ? { address, name } : { address };
  };
  while (p < toks.length) {
    if (at(",")) {
      p++;
      continue;
    }
    const start = p;
    if (phrase() && at(":")) {
      p++;
      while (!at(";")) {
        if (p >= toks.length) throw new AddressError("unclosed group");
        if (at(",")) p++;
        else out.push(mailbox());
      }
      p++;
    } else {
      p = start;
      out.push(mailbox());
    }
    if (p < toks.length) expect(",");
  }
  return out;
}
