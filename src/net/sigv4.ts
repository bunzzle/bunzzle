export interface AwsCredentials {
  accessKeyId: string;
  secretAccessKey: string;
}

export interface SignInput {
  method: string;
  url: string;
  headers?: Record<string, string>;
  body?: string;
}

const enc = new TextEncoder();

async function hmac(key: Uint8Array<ArrayBuffer>, data: string): Promise<Uint8Array<ArrayBuffer>> {
  const k = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, [
    "sign",
  ]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, enc.encode(data)));
}

async function sha256(data: string): Promise<string> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(data))).toHex();
}

const encode = (s: string) =>
  encodeURIComponent(s).replace(
    /[!'()*]/g,
    (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`,
  );

const byteOrder = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

export async function signRequest(
  req: SignInput,
  credentials: AwsCredentials,
  scope: { region: string; service: string },
  now: number,
): Promise<Record<string, string>> {
  const u = new URL(req.url);
  const amzDate = new Date(now).toISOString().replace(/[-:]|\.\d{3}/g, "");
  const day = amzDate.slice(0, 8);
  const headers: Record<string, string> = { ...req.headers, "x-amz-date": amzDate };
  const canonical = new Map<string, string>([["host", u.host]]);
  for (const [k, v] of Object.entries(headers)) {
    canonical.set(k.toLowerCase(), v.trim().replace(/\s+/g, " "));
  }
  const names = [...canonical.keys()].sort(byteOrder);
  const signedHeaders = names.join(";");
  const query = [...u.searchParams]
    .map(([k, v]) => `${encode(k)}=${encode(v)}`)
    .sort(byteOrder)
    .join("&");
  const request = [
    req.method,
    u.pathname.split("/").map(encode).join("/") || "/",
    query,
    ...names.map((n) => `${n}:${canonical.get(n)}`),
    "",
    signedHeaders,
    await sha256(req.body ?? ""),
  ].join("\n");
  const credentialScope = `${day}/${scope.region}/${scope.service}/aws4_request`;
  const toSign = ["AWS4-HMAC-SHA256", amzDate, credentialScope, await sha256(request)].join("\n");
  let key = await hmac(enc.encode(`AWS4${credentials.secretAccessKey}`), day);
  for (const part of [scope.region, scope.service, "aws4_request"]) key = await hmac(key, part);
  const signature = (await hmac(key, toSign)).toHex();
  return {
    ...headers,
    Authorization: `AWS4-HMAC-SHA256 Credential=${credentials.accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`,
  };
}
