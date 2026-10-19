import type { Database } from "bun:sqlite";
import { b } from "../validate/schema.ts";

export type Scope = "send" | "read" | "full";

export interface ApiKey {
  id: string;
  name: string;
  prefix: string;
  scope: Scope;
  domains: string[] | null;
  rateLimit: number;
  createdAt: number;
  lastUsedAt: number | null;
  revokedAt: number | null;
}

export const TOKEN = /^bz_[A-Za-z0-9_-]{43}$/;

export function hashToken(token: string): string {
  return new Bun.CryptoHasher("sha256").update(token).digest("hex");
}

export function newToken(): string {
  return `bz_${crypto.getRandomValues(new Uint8Array(32)).toBase64({ alphabet: "base64url", omitPadding: true })}`;
}

export function allows(scope: Scope, needed: Scope): boolean {
  return scope === "full" || scope === needed;
}

interface Row {
  id: string;
  name: string;
  prefix: string;
  scope: Scope;
  domains: string | null;
  rate_limit: number;
  created_at: number;
  last_used_at: number | null;
  revoked_at: number | null;
}

const fromRow = (r: Row): ApiKey => ({
  id: r.id,
  name: r.name,
  prefix: r.prefix,
  scope: r.scope,
  domains: r.domains === null ? null : b.array(b.string()).parse(JSON.parse(r.domains)),
  rateLimit: r.rate_limit,
  createdAt: r.created_at,
  lastUsedAt: r.last_used_at,
  revokedAt: r.revoked_at,
});

export interface NewKey {
  name: string;
  scope: Scope;
  domains?: string[] | null;
  rateLimit?: number;
}

export function createKey(db: Database, k: NewKey, now: number): { key: ApiKey; token: string } {
  const token = newToken();
  const id = Bun.randomUUIDv7();
  const domains = k.domains?.length ? JSON.stringify([...new Set(k.domains)].sort()) : null;
  db.query<unknown, [string, string, string, string, Scope, string | null, number, number]>(
    `INSERT INTO api_keys (id, name, token_hash, prefix, scope, domains, rate_limit, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(id, k.name, hashToken(token), token.slice(0, 10), k.scope, domains, k.rateLimit ?? 20, now);
  return { key: getKey(db, id) as ApiKey, token };
}

export function getKey(db: Database, id: string): ApiKey | null {
  const r = db.query<Row, [string]>("SELECT * FROM api_keys WHERE id = ?").get(id);
  return r ? fromRow(r) : null;
}

const cached = new WeakMap<Database, Map<string, ApiKey>>();
const MAX_CACHED = 10_000;

function cacheOf(db: Database): Map<string, ApiKey> {
  let c = cached.get(db);
  if (!c) {
    c = new Map();
    cached.set(db, c);
  }
  return c;
}

export function keyForHash(db: Database, hash: string): ApiKey | null {
  const c = cacheOf(db);
  const hit = c.get(hash);
  if (hit) return hit;
  const r = db
    .query<Row, [string]>("SELECT * FROM api_keys WHERE token_hash = ? AND revoked_at IS NULL")
    .get(hash);
  if (!r) return null;
  const key = fromRow(r);
  if (key.domains) Object.freeze(key.domains);
  Object.freeze(key);
  if (!db.inTransaction) {
    if (c.size >= MAX_CACHED) c.clear();
    c.set(hash, key);
  }
  return key;
}

export function touchKey(db: Database, id: string, now: number): void {
  db.query<unknown, [number, string]>("UPDATE api_keys SET last_used_at = ? WHERE id = ?").run(
    now,
    id,
  );
}

export function listKeys(db: Database): ApiKey[] {
  return db.query<Row, []>("SELECT * FROM api_keys ORDER BY created_at").all().map(fromRow);
}

export function revokeKey(db: Database, id: string, now: number): boolean {
  const c = cacheOf(db);
  for (const [hash, key] of c) if (key.id === id) c.delete(hash);
  return (
    db
      .query<unknown, [number, string]>(
        "UPDATE api_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
      )
      .run(now, id).changes > 0
  );
}
