import { parseIPv4, parseIPv6, reverseName } from "../dns/ip.ts";
import { lookup, txtStrings, validDomain } from "../dns/lookup.ts";
import type { Resolver } from "../dns/resolver.ts";

export type SpfResult =
  | "pass"
  | "fail"
  | "softfail"
  | "neutral"
  | "none"
  | "temperror"
  | "permerror";

export interface SpfInput {
  ip: string;
  mailFrom: string;
  helo: string | null;
}

export interface SpfCheck {
  result: SpfResult;
  domain: string | null;
  scope: "mailfrom" | "helo";
  reason: string | null;
}

class SpfError extends Error {
  constructor(
    readonly result: "temperror" | "permerror",
    message: string,
  ) {
    super(message);
  }
}

const permerror = (message: string) => new SpfError("permerror", message);

const QUALIFIERS: Record<string, SpfResult> = {
  "+": "pass",
  "-": "fail",
  "~": "softfail",
  "?": "neutral",
};

const MAX_LOOKUPS = 10;
const MAX_VOID = 2;
const MAX_NAMES = 10;

interface Term {
  qualifier: SpfResult;
  name: string;
  value: string | null;
  cidr4: number;
  cidr6: number;
}

interface SpfRecord {
  terms: Term[];
  redirect: string | null;
}

interface Ctx {
  resolver: Resolver;
  ip: Uint8Array;
  ipText: string;
  sender: string;
  helo: string;
  lookups: number;
  voids: number;
  deadline: number;
}

function ipBytes(ip: string): Uint8Array | null {
  const v4 = parseIPv4(ip);
  if (v4) return v4;
  const v6 = parseIPv6(ip);
  if (!v6) return null;
  const mapped = v6.subarray(0, 10).every((b) => b === 0) && v6[10] === 0xff && v6[11] === 0xff;
  return mapped ? v6.slice(12) : v6;
}

function inCidr(a: Uint8Array, b: Uint8Array, bits: number): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < bits; i++) {
    const mask = 0x80 >> (i & 7);
    if (((a[i >> 3] as number) & mask) !== ((b[i >> 3] as number) & mask)) return false;
  }
  return true;
}

function macroValue(letter: string, ctx: Ctx, domain: string): string {
  const at = ctx.sender.lastIndexOf("@");
  switch (letter) {
    case "s":
      return ctx.sender;
    case "l":
      return ctx.sender.slice(0, at);
    case "o":
      return ctx.sender.slice(at + 1);
    case "d":
      return domain;
    case "i":
      return ctx.ip.length === 4
        ? [...ctx.ip].join(".")
        : [...ctx.ip]
            .flatMap((b) => [b >> 4, b & 15])
            .map((n) => n.toString(16))
            .join(".");
    case "p":
      return "unknown";
    case "v":
      return ctx.ip.length === 4 ? "in-addr" : "ip6";
    case "h":
      return ctx.helo;
    default:
      throw permerror(`unknown macro letter ${letter}`);
  }
}

function expand(spec: string, ctx: Ctx, domain: string): string {
  let out = "";
  for (let i = 0; i < spec.length; i++) {
    const ch = spec[i] as string;
    if (ch !== "%") {
      out += ch;
      continue;
    }
    const next = spec[i + 1];
    if (next === "%" || next === "_" || next === "-") {
      out += next === "%" ? "%" : next === "_" ? " " : "%20";
      i++;
      continue;
    }
    const end = spec.indexOf("}", i);
    if (next !== "{" || end < 0) throw permerror(`bad macro in ${spec}`);
    const m = /^([a-zA-Z])(\d*)([rR]?)([.\-+,/_=]*)$/.exec(spec.slice(i + 2, end));
    if (!m) throw permerror(`bad macro in ${spec}`);
    const [, letter = "", digits = "", reverse, delimiters = ""] = m;
    let parts = macroValue(letter.toLowerCase(), ctx, domain).split(
      new RegExp(`[${(delimiters || ".").replace(/[-\\\]]/g, "\\$&")}]`),
    );
    if (reverse) parts.reverse();
    if (digits) {
      const n = Number(digits);
      if (n === 0) throw permerror(`bad macro in ${spec}`);
      parts = parts.slice(-n);
    }
    const value = parts.join(".");
    out += letter === letter.toUpperCase() ? encodeURIComponent(value) : value;
    i = end;
  }
  return out;
}

function target(spec: string, ctx: Ctx, domain: string): string {
  let name = expand(spec, ctx, domain).toLowerCase().replace(/\.$/, "");
  while (name.length > 253 && name.includes(".")) name = name.slice(name.indexOf(".") + 1);
  return name;
}

function parseTerm(raw: string): Term {
  let rest = raw;
  let qualifier: SpfResult = "pass";
  const q = QUALIFIERS[rest[0] as string];
  if (q) {
    qualifier = q;
    rest = rest.slice(1);
  }
  const m = /^([a-zA-Z0-9]+)(.*)$/.exec(rest);
  if (!m) throw permerror(`unknown term ${raw}`);
  const name = (m[1] as string).toLowerCase();
  let tail = m[2] as string;
  let cidr4 = 32;
  let cidr6 = 128;
  if (name === "a" || name === "mx") {
    const c = /(?:\/(\d{1,3}))?(?:\/\/(\d{1,3}))?$/.exec(tail);
    if (c?.[1] !== undefined) cidr4 = Number(c[1]);
    if (c?.[2] !== undefined) cidr6 = Number(c[2]);
    tail = tail.slice(0, tail.length - (c?.[0].length ?? 0));
    if (cidr4 > 32 || cidr6 > 128) throw permerror(`bad prefix length in ${raw}`);
  }
  let value: string | null = null;
  if (tail.startsWith(":")) value = tail.slice(1);
  else if (tail !== "") throw permerror(`unknown term ${raw}`);
  if (value === "") throw permerror(`empty value in ${raw}`);
  const needs = name === "include" || name === "exists" || name === "ip4" || name === "ip6";
  if (needs && value === null) throw permerror(`${name} needs a value`);
  if (name === "all" && value !== null) throw permerror(`all takes no value`);
  if (name === "ip4" || name === "ip6") {
    const [addr = "", len, extra] = (value as string).split("/");
    const bytes = name === "ip4" ? parseIPv4(addr) : parseIPv6(addr);
    const max = name === "ip4" ? 32 : 128;
    const bits = len === undefined ? max : Number(len);
    if (!bytes || extra !== undefined || !/^\d{0,3}$/.test(len ?? "") || bits > max) {
      throw permerror(`bad address in ${raw}`);
    }
    if (name === "ip4") cidr4 = bits;
    else cidr6 = bits;
    value = addr;
  }
  if (!["all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"].includes(name)) {
    throw permerror(`unknown mechanism ${name}`);
  }
  return { qualifier, name, value, cidr4, cidr6 };
}

function parseRecord(txt: string): SpfRecord {
  const terms: Term[] = [];
  let redirect: string | null = null;
  let exp = false;
  for (const raw of txt.split(" ").slice(1)) {
    if (raw === "") continue;
    const mod = /^([a-zA-Z][a-zA-Z0-9_.-]*)=(.*)$/.exec(raw);
    if (mod) {
      const name = (mod[1] as string).toLowerCase();
      if (name === "redirect") {
        if (redirect !== null) throw permerror("more than one redirect");
        redirect = mod[2] as string;
      } else if (name === "exp") {
        if (exp) throw permerror("more than one exp");
        exp = true;
      }
      continue;
    }
    terms.push(parseTerm(raw));
  }
  return { terms, redirect };
}

function count(ctx: Ctx) {
  ctx.lookups++;
  if (ctx.lookups > MAX_LOOKUPS) throw permerror(`more than ${MAX_LOOKUPS} DNS lookups`);
  if (Date.now() > ctx.deadline) throw new SpfError("temperror", "the SPF check took too long");
}

function voided(ctx: Ctx) {
  ctx.voids++;
  if (ctx.voids > MAX_VOID) throw permerror(`more than ${MAX_VOID} lookups found nothing`);
}

async function addresses(ctx: Ctx, name: string, countVoid: boolean): Promise<Uint8Array[]> {
  const type = ctx.ip.length === 4 ? "A" : "AAAA";
  const r = await lookup(ctx.resolver, name, type);
  if (r.kind === "failed") throw new SpfError("temperror", `${type} lookup for ${name} failed`);
  if (r.kind === "missing") {
    if (countVoid) voided(ctx);
    return [];
  }
  return r.records.flatMap((rec) => {
    const b =
      rec.type === "A"
        ? parseIPv4(rec.address)
        : rec.type === "AAAA"
          ? parseIPv6(rec.address)
          : null;
    return b ? [b] : [];
  });
}

async function matches(ctx: Ctx, t: Term, domain: string): Promise<boolean> {
  const bits = ctx.ip.length === 4 ? t.cidr4 : t.cidr6;
  switch (t.name) {
    case "all":
      return true;
    case "ip4":
    case "ip6": {
      const net = t.name === "ip4" ? parseIPv4(t.value as string) : parseIPv6(t.value as string);
      return !!net && inCidr(ctx.ip, net, bits);
    }
    case "include": {
      count(ctx);
      const r = await checkHost(ctx, target(t.value as string, ctx, domain));
      if (r === "none") throw permerror(`include of ${t.value} found no SPF record`);
      return r === "pass";
    }
    case "a": {
      count(ctx);
      const name = t.value === null ? domain : target(t.value, ctx, domain);
      return (await addresses(ctx, name, true)).some((a) => inCidr(ctx.ip, a, bits));
    }
    case "mx": {
      count(ctx);
      const name = t.value === null ? domain : target(t.value, ctx, domain);
      const mx = await lookup(ctx.resolver, name, "MX");
      if (mx.kind === "failed") throw new SpfError("temperror", `MX lookup for ${name} failed`);
      if (mx.kind === "missing") {
        voided(ctx);
        return false;
      }
      if (mx.records.length > MAX_NAMES) throw permerror(`${name} has more than ${MAX_NAMES} MX`);
      for (const rec of mx.records) {
        if (rec.type !== "MX" || rec.mx.exchange === "" || rec.mx.exchange === ".") continue;
        const found = await addresses(ctx, rec.mx.exchange, false);
        if (found.some((a) => inCidr(ctx.ip, a, bits))) return true;
      }
      return false;
    }
    case "ptr": {
      count(ctx);
      const name = t.value === null ? domain : target(t.value, ctx, domain);
      const reverse = reverseName(ctx.ipText);
      const ptr = reverse ? await lookup(ctx.resolver, reverse, "PTR") : null;
      if (ptr?.kind !== "found") return false;
      for (const rec of ptr.records.slice(0, MAX_NAMES)) {
        if (rec.type !== "PTR") continue;
        const host = rec.target.toLowerCase().replace(/\.$/, "");
        if (host !== name && !host.endsWith(`.${name}`)) continue;
        try {
          const found = await addresses(ctx, host, false);
          if (found.some((a) => inCidr(ctx.ip, a, ctx.ip.length * 8))) return true;
        } catch {}
      }
      return false;
    }
    case "exists": {
      count(ctx);
      const name = target(t.value as string, ctx, domain);
      const r = await lookup(ctx.resolver, name, "A");
      if (r.kind === "failed") throw new SpfError("temperror", `A lookup for ${name} failed`);
      if (r.kind === "missing") voided(ctx);
      return r.kind === "found";
    }
    default:
      return false;
  }
}

async function checkHost(ctx: Ctx, domain: string): Promise<SpfResult> {
  if (!validDomain(domain)) return "none";
  const txt = await lookup(ctx.resolver, domain, "TXT");
  if (txt.kind === "failed") throw new SpfError("temperror", `TXT lookup for ${domain} failed`);
  const records =
    txt.kind === "found" ? txtStrings(txt.records).filter((s) => /^v=spf1( |$)/i.test(s)) : [];
  if (records.length === 0) return "none";
  if (records.length > 1) throw permerror(`${domain} has more than one SPF record`);
  const record = parseRecord(records[0] as string);
  for (const t of record.terms) {
    if (await matches(ctx, t, domain)) return t.qualifier;
  }
  if (record.redirect !== null) {
    count(ctx);
    const next = target(record.redirect, ctx, domain);
    const r = await checkHost(ctx, next);
    if (r === "none") throw permerror(`redirect to ${next} found no SPF record`);
    return r;
  }
  return "neutral";
}

export async function checkSpf(
  resolver: Resolver,
  input: SpfInput,
  timeoutMs = 20_000,
): Promise<SpfCheck> {
  const helo = (input.helo ?? "").trim().toLowerCase().replace(/\.$/, "");
  const scope = input.mailFrom ? "mailfrom" : "helo";
  let sender = input.mailFrom || `postmaster@${helo}`;
  const at = sender.lastIndexOf("@");
  if (at === 0) sender = `postmaster${sender}`;
  const domain = sender.slice(sender.lastIndexOf("@") + 1).toLowerCase();
  const ip = ipBytes(input.ip);
  if (!ip || at < 0 || !validDomain(domain)) {
    return { result: "none", domain: validDomain(domain) ? domain : null, scope, reason: null };
  }
  const ctx: Ctx = {
    resolver,
    ip,
    ipText: ip.length === 4 ? [...ip].join(".") : input.ip,
    sender,
    helo,
    lookups: 0,
    voids: 0,
    deadline: Date.now() + timeoutMs,
  };
  try {
    return { result: await checkHost(ctx, domain), domain, scope, reason: null };
  } catch (err) {
    if (err instanceof SpfError) return { result: err.result, domain, scope, reason: err.message };
    throw err;
  }
}
