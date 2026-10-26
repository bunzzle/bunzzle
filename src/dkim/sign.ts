import {
  bodyHash,
  type HeaderField,
  headerData,
  relaxedHeader,
  splitMessage,
} from "./canonicalize.ts";

export type DkimAlgorithm = "rsa-sha256" | "ed25519-sha256";

export interface RemoteKey {
  sign(input: Uint8Array, algorithm: DkimAlgorithm): Promise<Uint8Array>;
}

export interface DkimKey {
  domain: string;
  selector: string;
  algorithm: DkimAlgorithm;
  privateKey: CryptoKey | RemoteKey;
}

export const SIGNED_HEADERS = [
  "from",
  "to",
  "cc",
  "reply-to",
  "subject",
  "date",
  "message-id",
  "in-reply-to",
  "references",
  "mime-version",
  "content-type",
  "content-transfer-encoding",
  "list-unsubscribe",
  "list-unsubscribe-post",
  "feedback-id",
  "x-bunzzle-ref",
];

export const OVERSIGNED_HEADERS = new Set([
  "from",
  "to",
  "cc",
  "reply-to",
  "subject",
  "date",
  "list-unsubscribe",
  "list-unsubscribe-post",
  "feedback-id",
  "x-bunzzle-ref",
]);

const enc = new TextEncoder();

export function headerList(headers: HeaderField[]): string[] {
  const counts = new Map<string, number>();
  for (const h of headers) {
    const n = h.name.toLowerCase();
    counts.set(n, (counts.get(n) ?? 0) + 1);
  }
  const list: string[] = [];
  for (const name of SIGNED_HEADERS) {
    const n = counts.get(name) ?? 0;
    for (let i = 0; i < n; i++) list.push(name);
    if (OVERSIGNED_HEADERS.has(name)) list.push(name);
  }
  return list;
}

export async function signData(key: DkimKey, data: string): Promise<string> {
  const bytes = enc.encode(data);
  const input =
    key.algorithm === "rsa-sha256"
      ? bytes
      : new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  const k = key.privateKey;
  if ("sign" in k) return (await k.sign(input, key.algorithm)).toBase64();
  const name = key.algorithm === "rsa-sha256" ? "RSASSA-PKCS1-v1_5" : "Ed25519";
  return new Uint8Array(await crypto.subtle.sign(name, k, input)).toBase64();
}

function fold(value: string): string {
  const parts = value.split(" ");
  const lines: string[] = [];
  let cur = "DKIM-Signature:";
  for (const p of parts) {
    if (cur.length + 1 + p.length > 78 && cur.trim().length > 0 && cur !== "DKIM-Signature:") {
      lines.push(cur);
      cur = ` ${p}`;
    } else {
      cur += ` ${p}`;
    }
  }
  lines.push(cur);
  return lines.join("\r\n");
}

export async function signMessage(
  raw: string,
  keys: DkimKey[],
  time: Date = new Date(),
): Promise<string> {
  const { headers, body } = splitMessage(raw);
  const bh = bodyHash(body);
  const h = headerList(headers);
  const data = headerData(headers, h);
  const t = Math.floor(time.getTime() / 1000);
  const signatures: string[] = [];
  for (const key of keys) {
    const tags = `v=1; a=${key.algorithm}; c=relaxed/relaxed; d=${key.domain}; s=${key.selector}; t=${t}; h=${h.join(":")}; bh=${bh}; b=`;
    const unsigned = fold(tags);
    const b = await signData(key, data + relaxedHeader(unsigned));
    signatures.push(`${unsigned}${b}`);
  }
  return `${signatures.join("\r\n")}\r\n${raw}`;
}
