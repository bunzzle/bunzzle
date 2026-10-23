import {
  bits,
  DerError,
  ecdsaSignatureDer,
  integer,
  node,
  oid,
  seq,
  set,
  tlv,
  utf8,
} from "../asn1/der.ts";
import { algorithm, type Certificate, oidString } from "./cert.ts";
import { verifySignature } from "./verify.ts";

const ECDSA_SHA256 = "1.2.840.10045.4.3.2";
const COMMON_NAME = "2.5.4.3";
const PURPOSES = { server: "1.3.6.1.5.5.7.3.1", client: "1.3.6.1.5.5.7.3.2" } as const;
const P256_SPKI = Uint8Array.fromHex("3059301306072a8648ce3d020106082a8648ce3d030107034200");
const NAME = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;

export type Purpose = keyof typeof PURPOSES | "ca";

export type SignRaw = (data: Uint8Array) => Promise<Uint8Array>;

export interface Csr {
  name: string;
  spki: Uint8Array;
}

export interface IssueOptions {
  name: string;
  spki: Uint8Array;
  purpose: Purpose;
  issuer: Uint8Array;
  sign: SignRaw;
  notBefore: number;
  notAfter: number;
}

export function isP256(spki: Uint8Array): boolean {
  return spki.length === P256_SPKI.length + 65 && P256_SPKI.every((byte, i) => spki[i] === byte);
}

export async function importP256(pkcs8: Uint8Array): Promise<CryptoKeyPair> {
  const alg = { name: "ECDSA", namedCurve: "P-256" };
  const privateKey = await crypto.subtle.importKey(
    "pkcs8",
    pkcs8 as Uint8Array<ArrayBuffer>,
    alg,
    true,
    ["sign"],
  );
  const { d: _, ...jwk } = await crypto.subtle.exportKey("jwk", privateKey);
  const publicKey = await crypto.subtle.importKey(
    "jwk",
    { ...jwk, key_ops: ["verify"] },
    alg,
    true,
    ["verify"],
  );
  return { privateKey, publicKey };
}

export function validName(name: string): boolean {
  return NAME.test(name);
}

export const distinguishedName = (name: string) =>
  Uint8Array.from(seq(set(seq(oid(COMMON_NAME), utf8(name)))));

export const signWith =
  (key: CryptoKey): SignRaw =>
  async (data) =>
    new Uint8Array(
      await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        key,
        data as Uint8Array<ArrayBuffer>,
      ),
    );

const signed = async (body: number[], sign: SignRaw) =>
  Uint8Array.from(
    seq(body, seq(oid(ECDSA_SHA256)), bits(ecdsaSignatureDer(await sign(Uint8Array.from(body))))),
  );

export async function certificateRequest(name: string, key: CryptoKeyPair): Promise<Uint8Array> {
  if (!validName(name)) throw new DerError(`bad node name ${name}`);
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", key.publicKey));
  const info = seq(node(0x02, [0]), distinguishedName(name), spki, node(0xa0));
  return signed(info, signWith(key.privateKey));
}

export async function parseCertificateRequest(der: Uint8Array): Promise<Csr> {
  const top = tlv(der, 0);
  if (top.tag !== 0x30 || top.end !== der.length) throw new DerError("bad certificate request");
  const info = tlv(der, top.body);
  const algT = tlv(der, info.end);
  const sigT = tlv(der, algT.end);
  if (info.tag !== 0x30 || sigT.tag !== 0x03 || sigT.end !== top.end || der[sigT.body] !== 0)
    throw new DerError("bad certificate request");
  const version = tlv(der, info.body);
  const subject = tlv(der, version.end);
  const spkiT = tlv(der, subject.end);
  if (version.tag !== 0x02 || subject.tag !== 0x30 || spkiT.tag !== 0x30)
    throw new DerError("bad certificate request");
  const spki = der.slice(spkiT.start, spkiT.end);
  if (!isP256(spki)) throw new DerError("certificate request key is not ECDSA P-256");
  const signatureAlgorithm = algorithm(der, algT);
  if (signatureAlgorithm.oid !== ECDSA_SHA256)
    throw new DerError("certificate request is not signed with ECDSA SHA-256");
  const check: Pick<Certificate, "tbs" | "signature" | "signatureAlgorithm"> = {
    tbs: der.subarray(info.start, info.end),
    signature: der.subarray(sigT.body + 1, sigT.end),
    signatureAlgorithm,
  };
  if (!(await verifySignature(check, spki)))
    throw new DerError("certificate request signature does not verify");
  const name = commonName(der, subject);
  if (!name || !validName(name)) throw new DerError("certificate request has no valid node name");
  return { name, spki };
}

function commonName(der: Uint8Array, subject: ReturnType<typeof tlv>): string | null {
  for (let at = subject.body; at < subject.end; ) {
    const rdn = tlv(der, at);
    const atv = tlv(der, rdn.body);
    const type = tlv(der, atv.body);
    const value = tlv(der, type.end);
    if (oidString(der.subarray(type.body, type.end)) === COMMON_NAME && value.tag === 0x0c)
      return new TextDecoder("utf-8", { fatal: true }).decode(der.subarray(value.body, value.end));
    at = rdn.end;
  }
  return null;
}

function time(ms: number): number[] {
  const d = new Date(Math.floor(ms / 1000) * 1000);
  const s = d.toISOString().replace(/[-:T]/g, "").replace(".000", "");
  return d.getUTCFullYear() < 2050
    ? node(0x17, new TextEncoder().encode(s.slice(2)))
    : node(0x18, new TextEncoder().encode(s));
}

function extension(id: string, critical: boolean, value: number[]): number[] {
  return seq(oid(id), critical ? node(0x01, [0xff]) : [], node(0x04, value));
}

export async function issueCertificate(o: IssueOptions): Promise<Uint8Array> {
  if (!isP256(o.spki)) throw new DerError("certificate key is not ECDSA P-256");
  const serial = crypto.getRandomValues(new Uint8Array(16));
  serial[0] = (serial[0] as number) & 0x7f;
  const extensions =
    o.purpose === "ca"
      ? [
          extension("2.5.29.19", true, seq(node(0x01, [0xff]), integer([0]))),
          extension("2.5.29.15", true, node(0x03, [1, 0x06])),
        ]
      : [
          extension("2.5.29.19", true, seq()),
          extension("2.5.29.15", true, node(0x03, [7, 0x80])),
          extension("2.5.29.37", false, seq(oid(PURPOSES[o.purpose]))),
        ];
  const tbs = seq(
    node(0xa0, integer([2])),
    integer(serial),
    seq(oid(ECDSA_SHA256)),
    o.issuer,
    seq(time(o.notBefore), time(o.notAfter)),
    distinguishedName(o.name),
    o.spki,
    node(0xa3, seq(...extensions)),
  );
  return signed(tbs, o.sign);
}
