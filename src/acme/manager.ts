import { fromPem, notAfter } from "../asn1/der.ts";
import type { Logger } from "../core/log.ts";
import {
  AcmeClient,
  accountKeyFromPkcs8,
  type DnsPublisher,
  newAccountKey,
  type Request,
} from "./client.ts";

const DAY = 86_400_000;
const RENEW_BEFORE = 30 * DAY;

export interface AcmeOptions {
  directory: string;
  email: string;
  hosts: string[];
  dir: string;
  dns: DnsPublisher;
  request: Request;
  log: Logger;
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
  propagationMs?: number;
}

export async function certificateState(
  dir: string,
  hosts: string[],
  now: number,
): Promise<{ expires: number | null; due: boolean }> {
  const cert = Bun.file(`${dir}/cert.pem`);
  const recorded = Bun.file(`${dir}/hosts.json`);
  if (!(await cert.exists()) || !(await recorded.exists())) return { expires: null, due: true };
  try {
    const [leaf] = fromPem(await cert.text());
    const expires = leaf ? notAfter(leaf) : 0;
    const same =
      JSON.stringify((await recorded.json()) as string[]) === JSON.stringify([...hosts].sort());
    return { expires, due: !same || expires - now < RENEW_BEFORE };
  } catch {
    return { expires: null, due: true };
  }
}

async function writePrivate(path: string, data: string | Uint8Array, mode: string) {
  const tmp = `${path}.${crypto.randomUUID()}.tmp`;
  await Bun.write(tmp, data);
  await Bun.$`chmod ${mode} ${tmp} && mv ${tmp} ${path}`.quiet();
}

async function accountKey(dir: string): Promise<CryptoKey> {
  const file = Bun.file(`${dir}/account.key`);
  if (await file.exists()) {
    return accountKeyFromPkcs8(Uint8Array.fromBase64((await file.text()).trim()));
  }
  const created = await newAccountKey();
  await writePrivate(`${dir}/account.key`, created.pkcs8.toBase64(), "600");
  return created.key;
}

export async function ensureCertificate(o: AcmeOptions): Promise<"fresh" | "issued"> {
  const now = (o.now ?? Date.now)();
  const hosts = [...new Set(o.hosts.map((h) => h.toLowerCase()))].sort();
  const state = await certificateState(o.dir, hosts, now);
  if (!state.due) return "fresh";
  await Bun.$`mkdir -p ${o.dir}`.quiet();
  const client = new AcmeClient(o.directory, await accountKey(o.dir), o.request, o.sleep);
  await client.register(o.email);
  const issued = await client.issue(hosts, o.dns, o.propagationMs);
  await writePrivate(`${o.dir}/key.pem`, issued.keyPem, "640");
  await writePrivate(`${o.dir}/cert.pem`, issued.certPem, "644");
  await writePrivate(`${o.dir}/hosts.json`, JSON.stringify(hosts), "644");
  const [leaf] = fromPem(issued.certPem);
  o.log.info("TLS certificate issued", {
    hosts,
    expires: leaf ? new Date(notAfter(leaf)).toISOString() : null,
  });
  return "issued";
}
