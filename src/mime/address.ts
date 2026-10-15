import { encodedWords, isAscii } from "./encodings.ts";

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

export function normalizeAddress(raw: string): string {
  const s = raw.trim();
  const at = s.lastIndexOf("@");
  if (at <= 0 || at === s.length - 1) throw new AddressError(`invalid email address: ${raw}`);
  const local = s.slice(0, at);
  const domain = asciiDomain(s.slice(at + 1));
  if (local.length > 64 || !LOCAL_ATOM.test(local)) {
    throw new AddressError(`invalid email address: ${raw}`);
  }
  if (!/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(domain) || domain.length > 253) {
    throw new AddressError(`invalid email address: ${raw}`);
  }
  return `${local}@${domain}`;
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
