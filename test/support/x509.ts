import { ecdsaSignatureDer, integer, node, oid, pem, seq, set, utf8 } from "../../src/asn1/der.ts";

export type KeyKind =
  | "rsa"
  | "rsa-pss"
  | "rsa-1024"
  | "rsa-sha1"
  | "p256"
  | "p384"
  | "p521"
  | "ed25519";

export interface Issued {
  der: Uint8Array;
  pem: string;
  keys: CryptoKeyPair;
  kind: KeyKind;
  name: string;
  spki: Uint8Array;
}

export interface IssueOptions {
  name: string;
  issuer?: Issued;
  kind?: KeyKind;
  keys?: CryptoKeyPair;
  ca?: boolean;
  pathLen?: number;
  keyUsage?: "sign-certs" | "digital-signature";
  dns?: string[];
  eku?: string[];
  notBefore?: number;
  notAfter?: number;
  unknownCritical?: boolean;
  permitted?: string[];
  excluded?: string[];
}

const NULL = [0x05, 0x00];
const SHA256 = "2.16.840.1.101.3.4.2.1";
const DAY = 86_400_000;

type Generation =
  | { name: string }
  | { name: string; namedCurve: string }
  | { name: string; modulusLength: number; publicExponent: Uint8Array; hash: string };

function generation(kind: KeyKind): Generation {
  const rsa = (name: string, bits: number, hash = "SHA-256") => ({
    name,
    modulusLength: bits,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash,
  });
  switch (kind) {
    case "rsa":
      return rsa("RSASSA-PKCS1-v1_5", 2048);
    case "rsa-sha1":
      return rsa("RSASSA-PKCS1-v1_5", 2048, "SHA-1");
    case "rsa-1024":
      return rsa("RSASSA-PKCS1-v1_5", 1024);
    case "rsa-pss":
      return rsa("RSA-PSS", 2048);
    case "p256":
      return { name: "ECDSA", namedCurve: "P-256" };
    case "p384":
      return { name: "ECDSA", namedCurve: "P-384" };
    case "p521":
      return { name: "ECDSA", namedCurve: "P-521" };
    case "ed25519":
      return { name: "Ed25519" };
  }
}

export async function keyPair(kind: KeyKind): Promise<CryptoKeyPair> {
  return (await crypto.subtle.generateKey(
    generation(kind) as { name: "ECDSA"; namedCurve: string },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
}

function signatureAlgorithm(kind: KeyKind): number[] {
  switch (kind) {
    case "rsa":
    case "rsa-1024":
      return seq(oid("1.2.840.113549.1.1.11"), NULL);
    case "rsa-sha1":
      return seq(oid("1.2.840.113549.1.1.5"), NULL);
    case "rsa-pss":
      return seq(
        oid("1.2.840.113549.1.1.10"),
        seq(
          node(0xa0, seq(oid(SHA256), NULL)),
          node(0xa1, seq(oid("1.2.840.113549.1.1.8"), seq(oid(SHA256), NULL))),
          node(0xa2, integer([32])),
        ),
      );
    case "p256":
      return seq(oid("1.2.840.10045.4.3.2"));
    case "p384":
      return seq(oid("1.2.840.10045.4.3.3"));
    case "p521":
      return seq(oid("1.2.840.10045.4.3.4"));
    case "ed25519":
      return seq(oid("1.3.101.112"));
  }
}

async function sign(kind: KeyKind, key: CryptoKey, data: Uint8Array): Promise<Uint8Array> {
  const d = data as Uint8Array<ArrayBuffer>;
  switch (kind) {
    case "rsa":
    case "rsa-1024":
    case "rsa-sha1":
      return new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, d));
    case "rsa-pss":
      return new Uint8Array(await crypto.subtle.sign({ name: "RSA-PSS", saltLength: 32 }, key, d));
    case "ed25519":
      return new Uint8Array(await crypto.subtle.sign("Ed25519", key, d));
    default: {
      const hash = kind === "p256" ? "SHA-256" : kind === "p384" ? "SHA-384" : "SHA-512";
      const raw = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash }, key, d));
      return Uint8Array.from(ecdsaSignatureDer(raw));
    }
  }
}

function utcTime(ms: number): number[] {
  const iso = new Date(ms).toISOString();
  const s = `${iso.slice(2, 4)}${iso.slice(5, 7)}${iso.slice(8, 10)}${iso.slice(11, 13)}${iso.slice(14, 16)}${iso.slice(17, 19)}Z`;
  return node(0x17, new TextEncoder().encode(s));
}

const nameDer = (cn: string) => seq(set(seq(oid("2.5.4.3"), utf8(cn))));
const ascii = (s: string) => new TextEncoder().encode(s);

function extension(id: string, value: number[], critical = false): number[] {
  return seq(oid(id), ...(critical ? [node(0x01, [0xff])] : []), node(0x04, value));
}

export async function issue(o: IssueOptions): Promise<Issued> {
  const kind = o.kind ?? "p256";
  const keys = o.keys ?? (await keyPair(kind));
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", keys.publicKey));
  const signer = o.issuer ?? { keys, kind, name: o.name };
  const now = Date.now();

  const exts: number[][] = [];
  if (o.ca !== undefined || o.pathLen !== undefined) {
    exts.push(
      extension(
        "2.5.29.19",
        seq(
          ...(o.ca ? [node(0x01, [0xff])] : []),
          ...(o.pathLen !== undefined ? [integer([o.pathLen])] : []),
        ),
        true,
      ),
    );
  }
  if (o.keyUsage) {
    exts.push(
      extension("2.5.29.15", node(0x03, [0, o.keyUsage === "sign-certs" ? 0x06 : 0x80]), true),
    );
  }
  if (o.dns) exts.push(extension("2.5.29.17", seq(...o.dns.map((d) => node(0x82, ascii(d))))));
  if (o.eku) exts.push(extension("2.5.29.37", seq(...o.eku.map((e) => oid(e)))));
  if (o.permitted || o.excluded) {
    const subtrees = (tag: number, list: string[]) =>
      node(tag, ...list.map((d) => seq(node(0x82, ascii(d)))));
    exts.push(
      extension(
        "2.5.29.30",
        seq(
          ...(o.permitted ? [subtrees(0xa0, o.permitted)] : []),
          ...(o.excluded ? [subtrees(0xa1, o.excluded)] : []),
        ),
        true,
      ),
    );
  }
  if (o.unknownCritical) exts.push(extension("1.3.6.1.4.1.55555.1", [0x05, 0x00], true));

  const algorithm = signatureAlgorithm(signer.kind);
  const tbs = seq(
    node(0xa0, integer([2])),
    integer(crypto.getRandomValues(new Uint8Array(12))),
    algorithm,
    nameDer(signer.name),
    seq(utcTime(o.notBefore ?? now - DAY), utcTime(o.notAfter ?? now + 30 * DAY)),
    nameDer(o.name),
    Array.from(spki),
    ...(exts.length ? [node(0xa3, seq(...exts))] : []),
  );
  const signature = await sign(signer.kind, signer.keys.privateKey, Uint8Array.from(tbs));
  const der = Uint8Array.from(seq(tbs, algorithm, node(0x03, [0], signature)));
  return { der, pem: pem("CERTIFICATE", der), keys, kind, name: o.name, spki };
}

export async function privateKeyPem(issued: Issued): Promise<string> {
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", issued.keys.privateKey));
  return pem("PRIVATE KEY", pkcs8);
}

export function sha256(data: Uint8Array): Uint8Array {
  const h = new Bun.CryptoHasher("sha256");
  h.update(data);
  return new Uint8Array(h.digest());
}
