import { node, oid } from "../asn1/der.ts";
import { lookup, txtStrings, validDomain } from "../dns/lookup.ts";
import type { Resolver } from "../dns/resolver.ts";
import { fromBinary } from "../mime/parse.ts";
import {
  type HeaderField,
  headerData,
  relaxedBody,
  relaxedHeader,
  simpleBody,
  splitMessage,
} from "./canonicalize.ts";

export type DkimResult = "pass" | "fail" | "neutral" | "policy" | "temperror" | "permerror";

export interface DkimCheck {
  result: DkimResult;
  domain: string | null;
  selector: string | null;
  reason: string | null;
  testing: boolean;
}

type Canon = "simple" | "relaxed";

interface Key {
  algorithm: "rsa" | "ed25519";
  key: Uint8Array<ArrayBuffer>;
  strict: boolean;
  testing: boolean;
}

class DkimError extends Error {
  constructor(
    readonly result: DkimResult,
    message: string,
  ) {
    super(message);
  }
}

const MAX_SIGNATURES = 10;
const RSA_OID = oid("1.2.840.113549.1.1.1");

function parseTags(value: string): Map<string, string> | null {
  const map = new Map<string, string>();
  for (const part of value.split(";")) {
    if (part.trim() === "") continue;
    const eq = part.indexOf("=");
    if (eq < 0) return null;
    const name = part.slice(0, eq).trim();
    if (!/^[a-zA-Z][a-zA-Z0-9_]*$/.test(name) || map.has(name)) return null;
    map.set(name, part.slice(eq + 1).replace(/[ \t\r\n]+/g, ""));
  }
  return map;
}

function parseKey(txt: string): Key | DkimError {
  const t = parseTags(txt);
  if (!t) return new DkimError("permerror", "malformed key record");
  if (t.has("v") && t.get("v") !== "DKIM1")
    return new DkimError("permerror", "unknown key version");
  const k = (t.get("k") ?? "rsa").toLowerCase();
  if (k !== "rsa" && k !== "ed25519") return new DkimError("permerror", `unknown key type ${k}`);
  const hashes = t.get("h")?.toLowerCase().split(":");
  if (hashes && !hashes.includes("sha256")) {
    return new DkimError("permerror", "key does not allow sha256");
  }
  const services = t.get("s")?.toLowerCase().split(":");
  if (services && !services.includes("*") && !services.includes("email")) {
    return new DkimError("permerror", "key is not for email");
  }
  const p = t.get("p");
  if (p === undefined) return new DkimError("permerror", "key record has no p=");
  if (p === "") return new DkimError("permerror", "key revoked");
  let key: Uint8Array<ArrayBuffer>;
  try {
    key = Uint8Array.fromBase64(p) as Uint8Array<ArrayBuffer>;
  } catch {
    return new DkimError("permerror", "key is not base64");
  }
  const flags = (t.get("t") ?? "").toLowerCase().split(":");
  return { algorithm: k, key, strict: flags.includes("s"), testing: flags.includes("y") };
}

async function fetchKey(resolver: Resolver, selector: string, domain: string): Promise<Key> {
  const name = `${selector}._domainkey.${domain}`;
  const r = await lookup(resolver, name, "TXT");
  if (r.kind === "failed") throw new DkimError("temperror", `key lookup for ${name} failed`);
  if (r.kind === "missing") throw new DkimError("permerror", `no key at ${name}`);
  let problem: DkimError | null = null;
  for (const txt of txtStrings(r.records)) {
    const k = parseKey(txt);
    if (!(k instanceof DkimError)) return k;
    problem ??= k;
  }
  throw problem ?? new DkimError("permerror", `no key at ${name}`);
}

async function importRsa(key: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  const params = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
  let imported: CryptoKey;
  try {
    imported = await crypto.subtle.importKey("spki", key, params, false, ["verify"]);
  } catch {
    const spki = node(0x30, node(0x30, RSA_OID, [0x05, 0x00]), node(0x03, [0x00], key));
    try {
      imported = await crypto.subtle.importKey("spki", new Uint8Array(spki), params, false, [
        "verify",
      ]);
    } catch {
      throw new DkimError("permerror", "key is not a valid RSA key");
    }
  }
  if (((imported.algorithm as { modulusLength?: number }).modulusLength ?? 0) < 1024) {
    throw new DkimError("permerror", "key is shorter than 1024 bits");
  }
  return imported;
}

type Bytes = Uint8Array<ArrayBuffer>;

async function verifySignature(key: Key, sig: Bytes, data: Bytes): Promise<boolean> {
  if (key.algorithm === "rsa") {
    return crypto.subtle.verify("RSASSA-PKCS1-v1_5", await importRsa(key.key), sig, data);
  }
  if (key.key.length !== 32) throw new DkimError("permerror", "key is not a valid Ed25519 key");
  const pub = await crypto.subtle.importKey("raw", key.key, { name: "Ed25519" }, false, ["verify"]);
  return crypto.subtle.verify("Ed25519", pub, sig, await crypto.subtle.digest("SHA-256", data));
}

function canons(c: string | undefined): [Canon, Canon] {
  const [h = "simple", body = "simple", extra] = (c ?? "simple/simple").toLowerCase().split("/");
  const ok = (x: string): x is Canon => x === "simple" || x === "relaxed";
  if (!ok(h) || !ok(body) || extra !== undefined) {
    throw new DkimError("permerror", `unknown canonicalization ${c}`);
  }
  return [h, body];
}

async function checkOne(
  resolver: Resolver,
  sigHeader: HeaderField,
  headers: HeaderField[],
  bodyOf: (canon: Canon) => Bytes,
  now: number,
): Promise<DkimCheck> {
  const t = parseTags(sigHeader.raw.slice(sigHeader.raw.indexOf(":") + 1));
  const domain = t?.get("d")?.toLowerCase().replace(/\.$/, "") ?? null;
  const selector = t?.get("s")?.toLowerCase() ?? null;
  const base = { domain, selector, testing: false };
  try {
    if (!t) throw new DkimError("permerror", "malformed signature");
    if (t.get("v") !== "1") throw new DkimError("permerror", "unknown signature version");
    for (const tag of ["a", "b", "bh", "d", "h", "s"]) {
      if (!t.get(tag)) throw new DkimError("permerror", `signature has no ${tag}=`);
    }
    const a = (t.get("a") as string).toLowerCase();
    if (a === "rsa-sha1") throw new DkimError("permerror", "rsa-sha1 is not accepted");
    if (a !== "rsa-sha256" && a !== "ed25519-sha256") {
      throw new DkimError("permerror", `unknown algorithm ${a}`);
    }
    const [headerCanon, bodyCanon] = canons(t.get("c"));
    const d = domain as string;
    if (!validDomain(d) || !/^[a-z0-9._-]+$/.test(selector as string)) {
      throw new DkimError("permerror", "bad d= or s=");
    }
    const auid = t.get("i") ?? `@${d}`;
    const auidDomain = auid.slice(auid.lastIndexOf("@") + 1).toLowerCase();
    if (!auid.includes("@") || (auidDomain !== d && !auidDomain.endsWith(`.${d}`))) {
      throw new DkimError("permerror", "i= is not within d=");
    }
    const names = (t.get("h") as string).toLowerCase().split(":");
    if (!names.includes("from")) throw new DkimError("permerror", "From is not signed");
    const expires = t.get("x");
    const signed = t.get("t");
    if ((expires && !/^\d+$/.test(expires)) || (signed && !/^\d+$/.test(signed))) {
      throw new DkimError("permerror", "bad t= or x=");
    }
    if (expires && signed && Number(expires) < Number(signed)) {
      throw new DkimError("permerror", "x= is before t=");
    }
    if (expires && Number(expires) < Math.floor(now / 1000)) {
      throw new DkimError("fail", "signature expired");
    }
    const body = bodyOf(bodyCanon);
    const length = t.get("l");
    let covered = body;
    if (length !== undefined) {
      if (!/^\d+$/.test(length)) throw new DkimError("permerror", "bad l=");
      if (Number(length) > body.length)
        throw new DkimError("permerror", "l= is longer than the body");
      covered = body.subarray(0, Number(length));
    }
    const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", covered)).toBase64();
    if (hash !== t.get("bh")) throw new DkimError("fail", "body hash mismatch");
    if (covered.length < body.length) {
      throw new DkimError("policy", "the signature covers only part of the body");
    }
    const key = await fetchKey(resolver, selector as string, d);
    base.testing = key.testing;
    if (`${key.algorithm}-sha256` !== a)
      throw new DkimError("permerror", "key type does not match a=");
    if (key.strict && auidDomain !== d)
      throw new DkimError("permerror", "key needs i= equal to d=");
    const canon = headerCanon === "relaxed" ? relaxedHeader : (raw: string) => raw;
    const stripped = sigHeader.raw.replace(/([:;][ \t\r\n]*b[ \t\r\n]*=)[^;]*/, "$1");
    const data = fromBinary(headerData(headers, names, canon) + canon(stripped)) as Bytes;
    let sig: Bytes;
    try {
      sig = Uint8Array.fromBase64(t.get("b") as string) as Bytes;
    } catch {
      throw new DkimError("permerror", "b= is not base64");
    }
    if (!(await verifySignature(key, sig, data))) throw new DkimError("fail", "bad signature");
    return { ...base, result: "pass", reason: null };
  } catch (err) {
    if (err instanceof DkimError) return { ...base, result: err.result, reason: err.message };
    throw err;
  }
}

export async function checkDkim(
  resolver: Resolver,
  raw: string,
  now = Date.now(),
): Promise<DkimCheck[]> {
  const { headers, body } = splitMessage(raw);
  const sigs = headers.filter((h) => h.name.trim().toLowerCase() === "dkim-signature");
  const bodies = new Map<Canon, Bytes>();
  const bodyOf = (canon: Canon) => {
    let b = bodies.get(canon);
    if (!b) {
      b = fromBinary(canon === "relaxed" ? relaxedBody(body) : simpleBody(body)) as Bytes;
      bodies.set(canon, b);
    }
    return b;
  };
  const out: DkimCheck[] = [];
  for (const sig of sigs.slice(0, MAX_SIGNATURES)) {
    out.push(await checkOne(resolver, sig, headers, bodyOf, now));
  }
  return out;
}
