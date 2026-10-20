import type { MasterKey } from "../crypto/master.ts";

export type TokenPurpose = "b" | "u" | "o" | "c";

const ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";
const MAC_BYTES = 10;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const enc = new TextEncoder();
const dec = new TextDecoder();

export function base32(bytes: Uint8Array): string {
  let out = "";
  let bits = 0;
  let value = 0;
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

export function unbase32(text: string): Uint8Array | null {
  const out: number[] = [];
  let bits = 0;
  let value = 0;
  for (const ch of text.toLowerCase()) {
    const v = ALPHABET.indexOf(ch);
    if (v < 0) return null;
    value = ((value << 5) | v) & 0xffff;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

function idBytes(messageId: string): Uint8Array {
  if (UUID.test(messageId)) {
    const out = new Uint8Array(17);
    out.set(Uint8Array.fromHex(messageId.replaceAll("-", "")), 1);
    return out;
  }
  const text = enc.encode(messageId);
  if (text.length < 1 || text.length > 30) throw new Error("message id too long for a token");
  const out = new Uint8Array(1 + text.length);
  out[0] = text.length;
  out.set(text, 1);
  return out;
}

function readId(bytes: Uint8Array): { id: string; length: number } | null {
  const flag = bytes[0];
  if (flag === undefined) return null;
  if (flag === 0) {
    if (bytes.length < 17) return null;
    const hex = bytes.subarray(1, 17).toHex();
    return {
      id: `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`,
      length: 17,
    };
  }
  if (bytes.length < 1 + flag) return null;
  return { id: dec.decode(bytes.subarray(1, 1 + flag)), length: 1 + flag };
}

async function macOf(master: MasterKey, body: Uint8Array, url?: string): Promise<Uint8Array> {
  if (url === undefined) return (await master.mac(body, "token")).subarray(0, MAC_BYTES);
  const u = enc.encode(url);
  const data = new Uint8Array(body.length + u.length);
  data.set(body);
  data.set(u, body.length);
  return (await master.mac(data, "link")).subarray(0, MAC_BYTES);
}

export async function makeToken(
  master: MasterKey,
  purpose: TokenPurpose,
  messageId: string,
  url?: string,
): Promise<string> {
  if ((purpose === "c") !== (url !== undefined)) throw new Error("only link tokens carry a url");
  const id = idBytes(messageId);
  const body = new Uint8Array(1 + id.length);
  body[0] = purpose.charCodeAt(0);
  body.set(id, 1);
  const mac = await macOf(master, body, url);
  const all = new Uint8Array(body.length + MAC_BYTES);
  all.set(body);
  all.set(mac, body.length);
  return base32(all);
}

export async function readToken(
  master: MasterKey,
  token: string,
  url?: string,
): Promise<{ purpose: TokenPurpose; messageId: string } | null> {
  if (token.length > 80) return null;
  const all = unbase32(token);
  if (!all || all.length < 2 + MAC_BYTES) return null;
  const purpose = String.fromCharCode(all[0] as number);
  if (url === undefined ? purpose !== "b" && purpose !== "u" && purpose !== "o" : purpose !== "c") {
    return null;
  }
  const parsed = readId(all.subarray(1));
  if (!parsed || 1 + parsed.length + MAC_BYTES !== all.length) return null;
  const body = all.subarray(0, 1 + parsed.length);
  const want = await macOf(master, body, url);
  const got = all.subarray(1 + parsed.length);
  let diff = 0;
  for (let i = 0; i < MAC_BYTES; i++) diff |= (want[i] as number) ^ (got[i] as number);
  return diff === 0 ? { purpose: purpose as TokenPurpose, messageId: parsed.id } : null;
}
