import type { RequestInput, RequestResult } from "./request.ts";

export const POSTMASTER_SCOPE = "https://www.googleapis.com/auth/postmaster.readonly";

export interface PostmasterCredentials {
  clientId: string;
  clientSecret: string;
  refreshToken: string;
}

export interface DayStats {
  day: string;
  spamRatio: number | null;
  reputation: string | null;
  spfRatio: number | null;
  dkimRatio: number | null;
  dmarcRatio: number | null;
  encryptedRatio: number | null;
}

export type PostmasterResult = { ok: true; days: DayStats[] } | { ok: false; error: string };

interface ApiStats {
  name?: string;
  userReportedSpamRatio?: number;
  domainReputation?: string;
  spfSuccessRatio?: number;
  dkimSuccessRatio?: number;
  dmarcSuccessRatio?: number;
  outboundEncryptionRatio?: number;
}

const DAY_MS = 86_400_000;
const MAX_PAGES = 5;

const ratio = (v: unknown) => (typeof v === "number" && Number.isFinite(v) ? v : null);

function dateParams(prefix: string, ms: number): string {
  const d = new Date(ms);
  return `${prefix}.year=${d.getUTCFullYear()}&${prefix}.month=${d.getUTCMonth() + 1}&${prefix}.day=${d.getUTCDate()}`;
}

function dayOf(name: string | undefined): string | null {
  const m = /\/trafficStats\/(\d{4})(\d{2})(\d{2})$/.exec(name ?? "");
  return m ? `${m[1]}-${m[2]}-${m[3]}` : null;
}

function problem(body: string, status: number): string {
  try {
    const parsed = JSON.parse(body) as {
      error?: { message?: string } | string;
      error_description?: string;
    };
    if (typeof parsed.error === "object" && parsed.error?.message) return parsed.error.message;
    if (parsed.error_description) return parsed.error_description;
    if (typeof parsed.error === "string") return parsed.error;
  } catch {}
  return `status ${status}`;
}

export class Postmaster {
  #token: { value: string; until: number } | null = null;

  constructor(
    private readonly credentials: PostmasterCredentials,
    private readonly request: (r: RequestInput) => Promise<RequestResult>,
    private readonly apiUrl = "https://gmailpostmastertools.googleapis.com",
    private readonly tokenUrl = "https://oauth2.googleapis.com/token",
    private readonly now: () => number = Date.now,
  ) {}

  async #accessToken(): Promise<string> {
    if (this.#token && this.#token.until > this.now()) return this.#token.value;
    const form = new URLSearchParams({
      grant_type: "refresh_token",
      client_id: this.credentials.clientId,
      client_secret: this.credentials.clientSecret,
      refresh_token: this.credentials.refreshToken,
    });
    const r = await this.request({
      method: "POST",
      url: this.tokenUrl,
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: form.toString(),
      maxBody: 64 * 1024,
    });
    if (!r.ok) throw new Error(r.error);
    if (r.status !== 200)
      throw new Error(`could not refresh the access token: ${problem(r.body, r.status)}`);
    const t = JSON.parse(r.body) as { access_token?: string; expires_in?: number };
    if (!t.access_token) throw new Error("the token answer has no access token");
    this.#token = {
      value: t.access_token,
      until: this.now() + Math.max(60, (t.expires_in ?? 3600) - 60) * 1000,
    };
    return t.access_token;
  }

  async trafficStats(domain: string, days = 7): Promise<PostmasterResult> {
    try {
      const token = await this.#accessToken();
      const end = this.now();
      const out: DayStats[] = [];
      let page: string | null = null;
      for (let n = 0; n < MAX_PAGES; n++) {
        const url = `${this.apiUrl}/v1/domains/${encodeURIComponent(domain)}/trafficStats?${dateParams("startDate", end - days * DAY_MS)}&${dateParams("endDate", end + DAY_MS)}&pageSize=100${page ? `&pageToken=${encodeURIComponent(page)}` : ""}`;
        const r = await this.request({
          method: "GET",
          url,
          headers: { Authorization: `Bearer ${token}` },
          maxBody: 1024 * 1024,
        });
        if (!r.ok) throw new Error(r.error);
        if (r.status === 404 || r.status === 403) {
          return {
            ok: false,
            error: `${domain} is not set up in Postmaster Tools for this account: ${problem(r.body, r.status)}`,
          };
        }
        if (r.status !== 200) throw new Error(`Postmaster Tools: ${problem(r.body, r.status)}`);
        const body = JSON.parse(r.body) as { trafficStats?: ApiStats[]; nextPageToken?: string };
        for (const s of body.trafficStats ?? []) {
          const day = dayOf(s.name);
          if (!day) continue;
          out.push({
            day,
            spamRatio: ratio(s.userReportedSpamRatio),
            reputation: s.domainReputation ?? null,
            spfRatio: ratio(s.spfSuccessRatio),
            dkimRatio: ratio(s.dkimSuccessRatio),
            dmarcRatio: ratio(s.dmarcSuccessRatio),
            encryptedRatio: ratio(s.outboundEncryptionRatio),
          });
        }
        page = body.nextPageToken ?? null;
        if (!page) break;
      }
      out.sort((a, b) => b.day.localeCompare(a.day));
      return { ok: true, days: out };
    } catch (err) {
      return { ok: false, error: (err as Error).message };
    }
  }
}
