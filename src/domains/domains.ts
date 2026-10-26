import type { Database } from "bun:sqlite";
import type { ProjectId } from "../accounts/projects.ts";
import { b } from "../validate/schema.ts";

export type RecordKind =
  | "DKIM"
  | "DKIM_NEXT"
  | "DKIM_RETIRING"
  | "SPF"
  | "DMARC"
  | "RETURN_PATH_MX"
  | "RETURN_PATH_SPF"
  | "RETURN_PATH";
export type CheckStatus = "not_started" | "verified" | "missing" | "mismatch";
export type DomainStatus = "pending" | "verified";
export const DOMAIN_MODES = ["records", "delegated"] as const;
export type DomainMode = (typeof DOMAIN_MODES)[number];

export interface DomainRecord {
  record: RecordKind;
  name: string;
  type: "TXT" | "MX" | "CNAME";
  value: string;
  required: boolean;
  status: CheckStatus;
  found: string | null;
}

export interface Domain {
  project: ProjectId;
  name: string;
  mode: DomainMode;
  status: DomainStatus;
  records: DomainRecord[];
  createdAt: number;
  checkedAt: number | null;
}

export interface PublicDkimKey {
  selector: string;
  algorithm: "rsa-sha256" | "ed25519-sha256";
  publicKey: string;
  state?: "active" | "next" | "retiring";
}

const recordSchema = b.object({
  record: b.enum([
    "DKIM",
    "DKIM_NEXT",
    "DKIM_RETIRING",
    "SPF",
    "DMARC",
    "RETURN_PATH_MX",
    "RETURN_PATH_SPF",
    "RETURN_PATH",
  ]),
  name: b.string(),
  type: b.enum(["TXT", "MX", "CNAME"]),
  value: b.string(),
  required: b.boolean(),
  status: b.enum(["not_started", "verified", "missing", "mismatch"]),
  found: b.string().nullable(),
});

export function spfMechanism(sourceIps: string | string[] | null): string {
  const ips = (Array.isArray(sourceIps) ? sourceIps : sourceIps ? [sourceIps] : []).filter(Boolean);
  if (ips.length === 0) return "a mx";
  return ips.map((ip) => (ip.includes(":") ? `ip6:${ip}` : `ip4:${ip}`)).join(" ");
}

export const dkimValue = (k: PublicDkimKey) =>
  `v=DKIM1; k=${k.algorithm === "rsa-sha256" ? "rsa" : "ed25519"}; p=${k.publicKey}`;

export function expectedRecords(
  domain: string,
  keys: PublicDkimKey[],
  sourceIp: string | string[] | null,
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
      record: (k.state === "next"
        ? "DKIM_NEXT"
        : k.state === "retiring"
          ? "DKIM_RETIRING"
          : "DKIM") as RecordKind,
      name: `${k.selector}._domainkey.${domain}`,
      value: dkimValue(k),
      required: (k.state ?? "active") === "active",
    })),
    {
      ...base,
      record: "SPF",
      name: domain,
      value: `v=spf1 ${spfMechanism(sourceIp)} ~all`,
      required: false,
    },
    dmarcRecord(domain, inboundHost),
    ...returnPath,
  ];
}

export const dmarcRecord = (domain: string, inboundHost: string | null): DomainRecord => ({
  record: "DMARC",
  name: `_dmarc.${domain}`,
  type: "TXT",
  value: inboundHost
    ? `v=DMARC1; p=none; rua=mailto:${dmarcAddress(domain)};`
    : "v=DMARC1; p=none;",
  required: false,
  status: "not_started",
  found: null,
});

export const bounceDomain = (domain: string) => `bounce.${domain}`;
export const dmarcAddress = (domain: string) => `dmarc@${bounceDomain(domain)}`;

export function tags(txt: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const part of txt.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    out.set(part.slice(0, eq).trim().toLowerCase(), part.slice(eq + 1).replace(/\s+/g, ""));
  }
  return out;
}

function check(r: DomainRecord, found: string[], sourceIp: string | string[] | null): DomainRecord {
  const result = (status: CheckStatus, value: string | null): DomainRecord => ({
    ...r,
    status,
    found: value,
  });
  if (r.type === "CNAME") {
    if (found.length === 0) return result("missing", null);
    const chain = found.join(" -> ");
    return found.some((t) => hostName(t) === hostName(r.value))
      ? result("verified", chain)
      : result("mismatch", chain);
  }
  if (r.record === "DKIM" || r.record === "DKIM_NEXT" || r.record === "DKIM_RETIRING") {
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
    const want = r.value.includes(" include:")
      ? r.value.split(/\s+/).slice(1, -1).join(" ")
      : spfMechanism(sourceIp);
    if (want === "a mx") return result("verified", record);
    const have = record.toLowerCase().split(/\s+/);
    return want.split(" ").every((m) => have.includes(m.toLowerCase()))
      ? result("verified", record)
      : result("mismatch", record);
  }
  const dmarc = found.find((t) => /^v=DMARC1\b/i.test(t.trim()));
  if (!dmarc) return result("missing", null);
  const want = tags(r.value).get("rua");
  if (!want) return result("verified", dmarc);
  const have = (tags(dmarc).get("rua") ?? "").toLowerCase().split(",");
  return have.includes(want.toLowerCase()) ? result("verified", dmarc) : result("mismatch", dmarc);
}

const hostName = (name: string) => name.toLowerCase().replace(/\.$/, "");

const MAX_CNAME_HOPS = 8;

const inside = (name: string, within: string[]) =>
  within.some((w) => name === w || name.endsWith(`.${w}`));

export async function lookupRecords(
  records: DomainRecord[],
  lookup: (
    queries: { name: string; type: DomainRecord["type"] }[],
  ) => Promise<Record<string, string[]>>,
  within: string[],
): Promise<Record<string, string[]>> {
  const scope = within.map(hostName);
  const queries = [
    ...new Map(
      records.map((r) => [`${r.type}:${r.name}`, { name: r.name, type: r.type }]),
    ).values(),
  ];
  const found = await lookup(queries);
  for (const r of records.filter((x) => x.type === "CNAME")) {
    const chain = (found[`CNAME:${r.name}`] ?? []).map(hostName);
    const out = chain.findIndex((n) => !inside(n, scope));
    if (out >= 0) chain.splice(out + 1);
    while (
      out < 0 &&
      chain.length > 0 &&
      chain.length < MAX_CNAME_HOPS &&
      !chain.includes(hostName(r.value))
    ) {
      const last = chain.at(-1) as string;
      const next = (await lookup([{ name: last, type: "CNAME" }]))[`CNAME:${last}`] ?? [];
      const hop = next.map(hostName).find((n) => !chain.includes(n));
      if (!hop) break;
      chain.push(hop);
      if (!inside(hop, scope)) break;
    }
    found[`CNAME:${r.name}`] = chain;
  }
  return found;
}

export function evaluate(
  records: DomainRecord[],
  found: Record<string, string[]>,
  sourceIp: string | string[] | null,
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
  project_id: string;
  name: string;
  mode: DomainMode;
  status: DomainStatus;
  records: string;
  created_at: number;
  checked_at: number | null;
}

const fromRow = (r: Row): Domain => ({
  project: r.project_id as ProjectId,
  name: r.name,
  mode: r.mode,
  status: r.status,
  records: b.array(recordSchema).parse(JSON.parse(r.records)),
  createdAt: r.created_at,
  checkedAt: r.checked_at,
});

const cachedDomains = new WeakMap<Database, Map<string, Domain>>();

function domainCache(db: Database): Map<string, Domain> {
  let c = cachedDomains.get(db);
  if (!c) {
    c = new Map();
    cachedDomains.set(db, c);
  }
  return c;
}

export function saveDomain(db: Database, d: Domain, now: number): void {
  domainCache(db).delete(d.name);
  db.query<
    unknown,
    [string, string, DomainMode, DomainStatus, string, number, number | null, number]
  >(
    `INSERT INTO domains (project_id, name, mode, status, records, created_at, checked_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT (name) DO UPDATE SET status = excluded.status, records = excluded.records,
       checked_at = excluded.checked_at, updated_at = excluded.updated_at
     WHERE domains.project_id = excluded.project_id`,
  ).run(
    d.project,
    d.name,
    d.mode,
    d.status,
    JSON.stringify(d.records),
    d.createdAt,
    d.checkedAt,
    now,
  );
}

export function findDomain(db: Database, name: string): Domain | null {
  const c = domainCache(db);
  const hit = c.get(name);
  if (hit) return hit;
  const r = db
    .query<Row, [string]>(
      "SELECT project_id, name, mode, status, records, created_at, checked_at FROM domains WHERE name = ?",
    )
    .get(name);
  if (!r) return null;
  const d = fromRow(r);
  Object.freeze(d.records);
  for (const rec of d.records) Object.freeze(rec);
  Object.freeze(d);
  if (!db.inTransaction) c.set(name, d);
  return d;
}

export function getDomain(db: Database, project: ProjectId, name: string): Domain | null {
  const d = findDomain(db, name);
  return d?.project === project ? d : null;
}

export function allDomains(db: Database): Domain[] {
  return db
    .query<Row, []>(
      "SELECT project_id, name, mode, status, records, created_at, checked_at FROM domains ORDER BY name",
    )
    .all()
    .map(fromRow);
}

export function listDomains(db: Database, project: ProjectId): Domain[] {
  return db
    .query<Row, [string]>(
      `SELECT project_id, name, mode, status, records, created_at, checked_at FROM domains
       WHERE project_id = ? ORDER BY name`,
    )
    .all(project)
    .map(fromRow);
}

export function zoneDomainNames(db: Database): string[] {
  return db
    .query<{ name: string }, []>(
      "SELECT name FROM domains WHERE mode = 'delegated' OR slot_keys = 1 ORDER BY name",
    )
    .all()
    .map((r) => r.name);
}

export function setDomainMode(db: Database, name: string, mode: DomainMode, now: number): void {
  domainCache(db).delete(name);
  db.query("UPDATE domains SET mode = ?, updated_at = ? WHERE name = ?").run(mode, now, name);
}

export function setSlotKeys(db: Database, name: string, on: boolean): void {
  db.query("UPDATE domains SET slot_keys = ? WHERE name = ?").run(on ? 1 : 0, name);
}

export function isVerified(db: Database, name: string): boolean {
  return findDomain(db, name)?.status === "verified";
}

export function domainPool(db: Database, name: string): string | null {
  return (
    db.query<{ pool: string | null }, [string]>("SELECT pool FROM domains WHERE name = ?").get(name)
      ?.pool ?? null
  );
}

export function setDomainPool(
  db: Database,
  project: ProjectId,
  name: string,
  pool: string | null,
  now: number,
): boolean {
  return (
    db
      .query<unknown, [string | null, number, string, string]>(
        "UPDATE domains SET pool = ?, updated_at = ? WHERE name = ? AND project_id = ?",
      )
      .run(pool, now, name, project).changes > 0
  );
}

export function releaseProjectDomains(db: Database, project: ProjectId): string[] {
  const names = db
    .query<{ name: string }, [string]>("DELETE FROM domains WHERE project_id = ? RETURNING name")
    .all(project)
    .map((r) => r.name);
  const c = domainCache(db);
  for (const name of names) c.delete(name);
  return names;
}

export function moveDomain(db: Database, name: string, to: ProjectId, now: number): boolean {
  domainCache(db).delete(name);
  return (
    db
      .query<unknown, [string, number, string]>(
        "UPDATE domains SET project_id = ?1, updated_at = ?2 WHERE name = ?3 AND project_id <> ?1",
      )
      .run(to, now, name).changes > 0
  );
}
