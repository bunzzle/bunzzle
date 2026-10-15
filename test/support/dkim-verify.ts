import { relaxedHeader, splitMessage } from "../../src/dkim/canonicalize.ts";
import { bodyHash, headerData } from "../../src/dkim/sign.ts";

export interface PublicKey {
  algorithm: "rsa-sha256" | "ed25519-sha256";
  key: Uint8Array<ArrayBuffer>;
}

export interface Verdict {
  selector: string;
  ok: boolean;
  reason?: string;
}

function tags(value: string): Map<string, string> {
  const map = new Map<string, string>();
  for (const part of value.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    map.set(part.slice(0, eq).trim(), part.slice(eq + 1).replace(/\s+/g, ""));
  }
  return map;
}

async function importPublic(pk: PublicKey): Promise<CryptoKey> {
  return pk.algorithm === "rsa-sha256"
    ? crypto.subtle.importKey(
        "spki",
        pk.key,
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
        false,
        ["verify"],
      )
    : crypto.subtle.importKey("raw", pk.key, { name: "Ed25519" }, false, ["verify"]);
}

export async function verifyDkim(raw: string, keys: Record<string, PublicKey>): Promise<Verdict[]> {
  const { headers, body } = splitMessage(raw);
  const verdicts: Verdict[] = [];
  for (const sigHeader of headers.filter((h) => h.name.toLowerCase() === "dkim-signature")) {
    const value = sigHeader.raw.slice(sigHeader.raw.indexOf(":") + 1);
    const t = tags(value);
    const selector = t.get("s") ?? "";
    const pk = keys[selector];
    if (!pk) {
      verdicts.push({ selector, ok: false, reason: "no key" });
      continue;
    }
    if (t.get("a") !== pk.algorithm) {
      verdicts.push({ selector, ok: false, reason: "algorithm mismatch" });
      continue;
    }
    if ((await bodyHash(body)) !== t.get("bh")) {
      verdicts.push({ selector, ok: false, reason: "body hash mismatch" });
      continue;
    }
    const names = (t.get("h") ?? "").toLowerCase().split(":");
    const stripped = sigHeader.raw.replace(/(^|;)(\s*b\s*=)[^;]*/, "$1$2");
    const data = headerData(headers, names) + relaxedHeader(stripped);
    const bytes = new TextEncoder().encode(data);
    const sig = Uint8Array.fromBase64(t.get("b") ?? "");
    const key = await importPublic(pk);
    const ok =
      pk.algorithm === "rsa-sha256"
        ? await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, sig, bytes)
        : await crypto.subtle.verify(
            "Ed25519",
            key,
            sig,
            await crypto.subtle.digest("SHA-256", bytes),
          );
    verdicts.push(ok ? { selector, ok } : { selector, ok, reason: "bad signature" });
  }
  return verdicts;
}
