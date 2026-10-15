import type { Database } from "bun:sqlite";
import { z } from "zod";

export type RecordKind = "DKIM" | "SPF" | "DMARC" | "RETURN_PATH_MX" | "RETURN_PATH_SPF";
export type CheckStatus = "not_started" | "verified" | "missing" | "mismatch";
export type DomainStatus = "pending" | "verified";

export interface DomainRecord {
  record: RecordKind;
  name: string;
  type: "TXT" | "MX";
  value: string;
  required: boolean;
  status: CheckStatus;
  found: string | null;
}

export interface Domain {
  name: string;
  status: DomainStatus;
  records: DomainRecord[];
  createdAt: number;
  checkedAt: number | null;
}

export interface PublicDkimKey {
  selector: string;
  algorithm: "rsa-sha256" | "ed25519-sha256";
  publicKey: string;
}

const recordSchema = z.object({
  record: z.enum(["DKIM", "SPF", "DMARC", "RETURN_PATH_MX", "RETURN_PATH_SPF"]),
  name: z.string(),
  type: z.enum(["TXT", "MX"]),
  value: z.string(),
  required: z.boolean(),
  status: z.enum(["not_started", "verified", "missing", "mismatch"]),
  found: z.string().nullable(),
});

export function spfMechanism(sourceIp: string | null): string {
  if (!sourceIp) return "a mx";
  return sourceIp.includes(":") ? `ip6:${sourceIp}` : `ip4:${sourceIp}`;
}

export function expectedRecords(
  domain: string,
  keys: PublicDkimKey[],
  sourceIp: string | null,
  inboundHost: string | null = null,
): DomainRecord[] {
  const base = { type: "TXT" as const, status: "not_started" as const, found: null };
  const returnPath: DomainRecord[] = inboundHost
    ? [
        {
          ...base,
          record: "RETURN_PATH_MX",
          type: "MX",
          name: bounceDomain(domain),
          value: `10 ${inboundHost}`,
          required: false,
        },
        {
          ...base,
          record: "RETURN_PATH_SPF",
          name: bounceDomain(domain),
          value: `v=spf1 ${spfMechanism(sourceIp)} ~all`,
          required: false,
        },
      ]
    : [];
  return [
    ...keys.map((k) => ({
      ...base,
      record: "DKIM" as const,
      name: `${k.selector}._domainkey.${domain}`,
      value: `v=DKIM1; k=${k.algorithm === "rsa-sha256" ? "rsa" : "ed25519"}; p=${k.publicKey}`,
      required: true,
    })),
    {
      ...base,
      record: "SPF",
      name: domain,
      value: `v=spf1 ${spfMechanism(sourceIp)} ~all`,
      required: false,
    },
    {
      ...base,
      record: "DMARC",
      name: `_dmarc.${domain}`,
      value: "v=DMARC1; p=none;",
      required: false,
    },
    ...returnPath,
  ];
}

export const bounceDomain = (domain: string) => `bounce.${domain}`;

function tags(txt: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const part of txt.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    out.set(part.slice(0, eq).trim().toLowerCase(), part.slice(eq + 1).replace(/\s+/g, ""));
  }
  return out;
}

function check(r: DomainRecord, found: string[], sourceIp: string | null): DomainRecord {
  const result = (status: CheckStatus, value: string | null): DomainRecord => ({
    ...r,
    status,
    found: value,
  });
  if (r.record === "DKIM") {
    const want = tags(r.value).get("p");
    const dkim = found.filter((t) => /^v=DKIM1\b/i.test(t.trim()) || tags(t).has("p"));
    if (dkim.length === 0) return result("missing", null);
    const match = dkim.find((t) => tags(t).get("p") === want);
    return match ? result("verified", match) : result("mismatch", dkim[0] ?? null);
  }
  if (r.record === "RETURN_PATH_MX") {
    const want = r.value.split(" ")[1]?.toLowerCase().replace(/\.$/, "");
    if (found.length === 0) return result("missing", null);
    const match = found.find((h) => h.toLowerCase().replace(/\.$/, "").endsWith(` ${want}`));
    return match ? result("verified", match) : result("mismatch", found.join(", "));
  }
  if (r.record === "SPF" || r.record === "RETURN_PATH_SPF") {
    const spf = found.filter((t) => /^v=spf1(\s|$)/i.test(t.trim()));
    if (spf.length === 0) return result("missing", null);
    const record = spf[0] as string;
    if (spf.length > 1) return result("mismatch", spf.join(" | "));
    if (!sourceIp) return result("verified", record);
    return record.toLowerCase().includes(spfMechanism(sourceIp).toLowerCase())
      ? result("verified", record)
      : result("mismatch", record);
  }
  const dmarc = found.find((t) => /^v=DMARC1\b/i.test(t.trim()));
  return dmarc ? result("verified", dmarc) : result("missing", null);
}

export function evaluate(
  records: DomainRecord[],
  found: Record<string, string[]>,
  sourceIp: string | null,
): { records: DomainRecord[]; status: DomainStatus } {
  const checked = records.map((r) =>
    check(r, found[`${r.type}:${r.name}`] ?? found[r.name] ?? [], sourceIp),
  );
  const ok = checked.filter((r) => r.required).every((r) => r.status === "verified");
  return { records: checked, status: ok ? "verified" : "pending" };
}

export function returnPathReady(
  d: { status: DomainStatus; records: DomainRecord[] } | null,
): boolean {
  if (d?.status !== "verified") return false;
  const rp = d.records.filter((r) => r.record.startsWith("RETURN_PATH"));
  return rp.length > 0 && rp.every((r) => r.status === "verified");
}

interface Row {
  name: string;
  status: DomainStatus;
  records: string;
  created_at: number;
  checked_at: number | null;
}

const fromRow = (r: Row): Domain => ({
  name: r.name,
  status: r.status,
  records: z.array(recordSchema).parse(JSON.parse(r.records)),
  createdAt: r.created_at,
  checkedAt: r.checked_at,
});

export function saveDomain(db: Database, d: Domain, now: number): void {
  db.query<unknown, [string, DomainStatus, string, number, number | null, number]>(
    `INSERT INTO domains (name, status, records, created_at, checked_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT (name) DO UPDATE SET status = excluded.status, records = excluded.records,
       checked_at = excluded.checked_at, updated_at = excluded.updated_at`,
  ).run(d.name, d.status, JSON.stringify(d.records), d.createdAt, d.checkedAt, now);
}

export function getDomain(db: Database, name: string): Domain | null {
  const r = db
    .query<Row, [string]>(
      "SELECT name, status, records, created_at, checked_at FROM domains WHERE name = ?",
    )
    .get(name);
  return r ? fromRow(r) : null;
}

export function listDomains(db: Database): Domain[] {
  return db
    .query<Row, []>(
      "SELECT name, status, records, created_at, checked_at FROM domains ORDER BY name",
    )
    .all()
    .map(fromRow);
}

export function isVerified(db: Database, name: string): boolean {
  return getDomain(db, name)?.status === "verified";
}
