import type { CfRecord, CfResult } from "./cloudflare.ts";
import { type Plan, planRemove, planUpsert } from "./rdata.ts";
import type { RequestInput, RequestResult } from "./request.ts";

const TTL = 3600;
const ATTEMPTS = 3;
const MAX_WAIT_S = 60;

const bare = (name: string) => name.toLowerCase().replace(/\.$/, "");

function messages(v: unknown): string[] {
  if (typeof v === "string") return [v];
  if (Array.isArray(v)) return v.flatMap(messages);
  if (v && typeof v === "object") return Object.values(v).flatMap(messages);
  return [];
}

function problem(body: string, status: number): string {
  try {
    const found = messages(JSON.parse(body));
    if (found.length > 0) return found.join("; ");
  } catch {}
  return `status ${status}`;
}

export class Desec {
  constructor(
    private readonly token: string,
    private readonly base: string,
    private readonly request: (r: RequestInput) => Promise<RequestResult>,
    private readonly sleep: (ms: number) => Promise<void> = Bun.sleep,
  ) {}

  async #api<T>(
    method: RequestInput["method"],
    path: string,
    body?: unknown,
  ): Promise<{ status: number; data: T | null }> {
    for (let attempt = 1; ; attempt++) {
      const r = await this.request({
        method,
        url: `${this.base}${path}`,
        headers: {
          Authorization: `Token ${this.token}`,
          ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
        },
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
        maxBody: 1024 * 1024,
      });
      if (!r.ok) throw new Error(r.error);
      if (r.status === 429 && attempt < ATTEMPTS) {
        const wait = Number(r.headers.get("retry-after") ?? attempt);
        if (Number.isFinite(wait) && wait >= 0 && wait <= MAX_WAIT_S) {
          await this.sleep(Math.max(wait, 1) * 1_000);
          continue;
        }
      }
      if (r.status === 404 && method === "GET") return { status: 404, data: null };
      if (r.status >= 300) throw new Error(`deSEC: ${problem(r.body, r.status)}`);
      if (r.body.trim() === "") return { status: r.status, data: null };
      try {
        return { status: r.status, data: JSON.parse(r.body) as T };
      } catch {
        throw new Error(`deSEC answered ${r.status} with no JSON`);
      }
    }
  }

  async zoneFor(name: string): Promise<string | null> {
    const { data } = await this.#api<{ name: string }[]>(
      "GET",
      `/domains/?owns_qname=${encodeURIComponent(bare(name))}`,
    );
    return data?.[0]?.name ?? null;
  }

  #path(zone: string, subname: string, type: string) {
    return `/domains/${encodeURIComponent(zone)}/rrsets/${subname ? encodeURIComponent(subname) : "@"}/${type}/`;
  }

  async #apply(rec: CfRecord, plan: (values: string[]) => Plan): Promise<CfResult> {
    try {
      const zone = await this.zoneFor(rec.name);
      if (!zone) return { ok: false, error: `no deSEC domain for ${rec.name}` };
      const name = bare(rec.name);
      const subname = name === zone ? "" : name.slice(0, -(zone.length + 1));
      const { data } = await this.#api<{ records: string[] }>(
        "GET",
        this.#path(zone, subname, rec.type),
      );
      const existing = data?.records ?? [];
      const { values, action } = plan(existing);
      if (values === null) return { ok: true, action };
      if (existing.length === 0) {
        await this.#api("POST", `/domains/${encodeURIComponent(zone)}/rrsets/`, {
          subname,
          type: rec.type,
          ttl: TTL,
          records: values,
        });
      } else {
        await this.#api("PATCH", this.#path(zone, subname, rec.type), { records: values });
      }
      return { ok: true, action };
    } catch (err) {
      return { ok: false, error: (err as Error).message };
    }
  }

  upsert(rec: CfRecord): Promise<CfResult> {
    return this.#apply(rec, (values) => planUpsert(rec, values));
  }

  remove(rec: CfRecord): Promise<CfResult> {
    return this.#apply(rec, (values) => planRemove(rec, values));
  }
}
