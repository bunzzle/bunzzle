import type { RequestInput, RequestResult } from "./request.ts";

export interface CfRecord {
  type: "TXT" | "MX";
  name: string;
  content: string;
  priority?: number | undefined;
}

export type CfResult =
  | { ok: true; action: "created" | "updated" | "exists" | "removed" | "absent" }
  | { ok: false; error: string };

interface ApiRecord {
  id: string;
  type: string;
  name: string;
  content: string;
  priority?: number;
}

const unquote = (s: string) => s.replace(/^"|"$/g, "").replace(/"\s*"/g, "").trim();

export class Cloudflare {
  constructor(
    private readonly token: string,
    private readonly base: string,
    private readonly request: (r: RequestInput) => Promise<RequestResult>,
  ) {}

  async #api<T>(method: RequestInput["method"], path: string, body?: unknown): Promise<T> {
    const r = await this.request({
      method,
      url: `${this.base}${path}`,
      headers: {
        Authorization: `Bearer ${this.token}`,
        ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      maxBody: 1024 * 1024,
    });
    if (!r.ok) throw new Error(r.error);
    let parsed: { success?: boolean; result?: T; errors?: { message?: string }[] };
    try {
      parsed = JSON.parse(r.body);
    } catch {
      throw new Error(`Cloudflare answered ${r.status} with no JSON`);
    }
    if (!parsed.success) {
      throw new Error(
        `Cloudflare: ${parsed.errors?.map((e) => e.message).join("; ") || `status ${r.status}`}`,
      );
    }
    return parsed.result as T;
  }

  async zoneFor(name: string): Promise<string | null> {
    const labels = name.toLowerCase().replace(/\.$/, "").split(".");
    for (let i = 0; i <= labels.length - 2; i++) {
      const candidate = labels.slice(i).join(".");
      const zones = await this.#api<{ id: string; name: string }[]>(
        "GET",
        `/zones?name=${encodeURIComponent(candidate)}`,
      );
      const zone = zones.find((z) => z.name.toLowerCase() === candidate);
      if (zone) return zone.id;
    }
    return null;
  }

  async #records(zone: string, rec: CfRecord): Promise<ApiRecord[]> {
    return this.#api<ApiRecord[]>(
      "GET",
      `/zones/${zone}/dns_records?type=${rec.type}&name=${encodeURIComponent(rec.name)}`,
    );
  }

  async upsert(rec: CfRecord): Promise<CfResult> {
    try {
      const zone = await this.zoneFor(rec.name);
      if (!zone) return { ok: false, error: `no Cloudflare zone for ${rec.name}` };
      const existing = await this.#records(zone, rec);
      const same = existing.find(
        (r) =>
          unquote(r.content).toLowerCase() === rec.content.toLowerCase() &&
          (rec.type !== "MX" || r.priority === rec.priority),
      );
      if (same) return { ok: true, action: "exists" };
      const body = {
        type: rec.type,
        name: rec.name,
        content: rec.content,
        ttl: 1,
        ...(rec.type === "MX" ? { priority: rec.priority ?? 10 } : {}),
      };
      const replace =
        rec.type === "TXT"
          ? existing.find((r) =>
              rec.content.startsWith("v=spf1")
                ? unquote(r.content).startsWith("v=spf1")
                : unquote(r.content).startsWith("v=DKIM1"),
            )
          : undefined;
      if (replace) {
        await this.#api("PUT", `/zones/${zone}/dns_records/${replace.id}`, body);
        return { ok: true, action: "updated" };
      }
      await this.#api("POST", `/zones/${zone}/dns_records`, body);
      return { ok: true, action: "created" };
    } catch (err) {
      return { ok: false, error: (err as Error).message };
    }
  }

  async remove(rec: CfRecord): Promise<CfResult> {
    try {
      const zone = await this.zoneFor(rec.name);
      if (!zone) return { ok: false, error: `no Cloudflare zone for ${rec.name}` };
      const match = (await this.#records(zone, rec)).find(
        (r) => unquote(r.content).toLowerCase() === rec.content.toLowerCase(),
      );
      if (!match) return { ok: true, action: "absent" };
      await this.#api("DELETE", `/zones/${zone}/dns_records/${match.id}`);
      return { ok: true, action: "removed" };
    } catch (err) {
      return { ok: false, error: (err as Error).message };
    }
  }
}
