import { child, children, parseXml, textAt, type XmlNode } from "../dmarc/xml.ts";
import type { CfRecord, CfResult } from "./cloudflare.ts";
import type { RequestInput, RequestResult } from "./request.ts";
import { type AwsCredentials, signRequest } from "./sigv4.ts";

const VERSION = "2013-04-01";
const TTL = 300;
const ATTEMPTS = 3;
const SETTLE_MS = 40_000;
const POLL_MS = 2_000;
const RETRY = new Set(["Throttling", "PriorRequestNotComplete", "InvalidChangeBatch"]);

type Action = "created" | "updated" | "exists" | "removed" | "absent";

interface RecordSet {
  ttl: number;
  values: string[];
}

class ApiError extends Error {
  constructor(
    message: string,
    readonly code: string,
  ) {
    super(message);
  }
}

const fqdn = (name: string) => `${name.toLowerCase().replace(/\.$/, "")}.`;

const xml = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

export function txtValue(content: string): string {
  const parts: string[] = [];
  for (let i = 0; i < content.length || i === 0; i += 255) {
    parts.push(`"${content.slice(i, i + 255).replace(/[\\"]/g, (c) => `\\${c}`)}"`);
  }
  return parts.join(" ");
}

export function txtText(value: string): string {
  const parts = [...value.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => m[1] as string);
  const raw = parts.length > 0 ? parts.join("") : value;
  return raw.replace(/\\([0-7]{3}|.)/g, (_, e: string) =>
    e.length === 3 ? String.fromCharCode(Number.parseInt(e, 8)) : e,
  );
}

const mxValue = (rec: CfRecord) => `${rec.priority ?? 10} ${fqdn(rec.content)}`;

function same(rec: CfRecord, value: string): boolean {
  if (rec.type === "TXT") return txtText(value) === rec.content;
  const [priority, host] = value.trim().split(/\s+/);
  return Number(priority) === (rec.priority ?? 10) && fqdn(host ?? "") === fqdn(rec.content);
}

export class Route53 {
  constructor(
    private readonly credentials: AwsCredentials,
    private readonly base: string,
    private readonly request: (r: RequestInput) => Promise<RequestResult>,
    private readonly now: () => number = Date.now,
    private readonly sleep: (ms: number) => Promise<void> = Bun.sleep,
  ) {}

  async #api(method: "GET" | "POST", path: string, body?: string): Promise<XmlNode | undefined> {
    const url = `${this.base}/${VERSION}${path}`;
    const headers = await signRequest(
      {
        method,
        url,
        ...(body !== undefined ? { body, headers: { "Content-Type": "application/xml" } } : {}),
      },
      this.credentials,
      { region: "us-east-1", service: "route53" },
      this.now(),
    );
    const r = await this.request({
      method,
      url,
      headers,
      ...(body !== undefined ? { body } : {}),
      maxBody: 1024 * 1024,
    });
    if (!r.ok) throw new Error(r.error);
    let top: XmlNode | undefined;
    try {
      top = parseXml(r.body).children[0];
    } catch {
      throw new Error(`Route 53 answered ${r.status} with no XML`);
    }
    if (r.status >= 300) {
      const code = textAt(top, "Error", "Code") ?? top?.name ?? `status ${r.status}`;
      const message =
        textAt(top, "Error", "Message") ??
        (children(child(top, "Messages"), "Message")
          .map((m) => m.text.trim())
          .join("; ") ||
          code);
      throw new ApiError(`Route 53: ${message}`, code);
    }
    return top;
  }

  async zoneFor(name: string): Promise<string | null> {
    const labels = name.toLowerCase().replace(/\.$/, "").split(".");
    for (let i = 0; i <= labels.length - 2; i++) {
      const candidate = `${labels.slice(i).join(".")}.`;
      const res = await this.#api(
        "GET",
        `/hostedzonesbyname?dnsname=${encodeURIComponent(candidate)}&maxitems=100`,
      );
      const ids = children(child(res, "HostedZones"), "HostedZone")
        .filter(
          (z) =>
            textAt(z, "Name")?.toLowerCase() === candidate &&
            textAt(z, "Config", "PrivateZone") !== "true",
        )
        .map((z) => (textAt(z, "Id") ?? "").replace(/^\/hostedzone\//, ""));
      if (ids.length > 1) throw new Error(`several public Route 53 zones are named ${candidate}`);
      if (ids[0]) return ids[0];
    }
    return null;
  }

  async #set(zone: string, rec: CfRecord): Promise<RecordSet | null> {
    const name = fqdn(rec.name);
    const res = await this.#api(
      "GET",
      `/hostedzone/${encodeURIComponent(zone)}/rrset?name=${encodeURIComponent(name)}&type=${rec.type}&maxitems=1`,
    );
    const set = child(child(res, "ResourceRecordSets"), "ResourceRecordSet");
    if (!set || textAt(set, "Name")?.toLowerCase() !== name || textAt(set, "Type") !== rec.type) {
      return null;
    }
    if (child(set, "AliasTarget") || child(set, "SetIdentifier")) {
      throw new Error(`${rec.name} ${rec.type} is an alias or uses a routing policy`);
    }
    return {
      ttl: Number(textAt(set, "TTL") ?? TTL),
      values: children(child(set, "ResourceRecords"), "ResourceRecord").map(
        (r) => textAt(r, "Value") ?? "",
      ),
    };
  }

  async #change(
    zone: string,
    rec: CfRecord,
    existing: RecordSet | null,
    values: string[],
  ): Promise<string | null> {
    const set = (vals: string[], ttl: number) =>
      `<ResourceRecordSet><Name>${xml(fqdn(rec.name))}</Name><Type>${rec.type}</Type><TTL>${ttl}</TTL><ResourceRecords>${vals
        .map((v) => `<ResourceRecord><Value>${xml(v)}</Value></ResourceRecord>`)
        .join("")}</ResourceRecords></ResourceRecordSet>`;
    const changes = [
      ...(existing
        ? [`<Change><Action>DELETE</Action>${set(existing.values, existing.ttl)}</Change>`]
        : []),
      ...(values.length > 0
        ? [`<Change><Action>CREATE</Action>${set(values, existing?.ttl ?? TTL)}</Change>`]
        : []),
    ];
    const body = `<?xml version="1.0" encoding="UTF-8"?><ChangeResourceRecordSetsRequest xmlns="https://route53.amazonaws.com/doc/${VERSION}/"><ChangeBatch><Changes>${changes.join("")}</Changes></ChangeBatch></ChangeResourceRecordSetsRequest>`;
    const res = await this.#api("POST", `/hostedzone/${encodeURIComponent(zone)}/rrset/`, body);
    return textAt(res, "ChangeInfo", "Id");
  }

  async #settle(change: string | null): Promise<void> {
    if (!change) return;
    const id = encodeURIComponent(change.replace(/^\/change\//, ""));
    for (let waited = 0; waited < SETTLE_MS; waited += POLL_MS) {
      const res = await this.#api("GET", `/change/${id}`);
      if (textAt(res, "ChangeInfo", "Status") === "INSYNC") return;
      await this.sleep(POLL_MS);
    }
  }

  async #apply(
    rec: CfRecord,
    plan: (values: string[]) => { values: string[] | null; action: Action },
  ): Promise<CfResult> {
    try {
      const zone = await this.zoneFor(rec.name);
      if (!zone) return { ok: false, error: `no Route 53 zone for ${rec.name}` };
      for (let attempt = 1; ; attempt++) {
        const existing = await this.#set(zone, rec);
        const { values, action } = plan(existing?.values ?? []);
        if (values === null) return { ok: true, action };
        try {
          await this.#settle(await this.#change(zone, rec, existing, values));
          return { ok: true, action };
        } catch (err) {
          if (!(err instanceof ApiError) || !RETRY.has(err.code) || attempt >= ATTEMPTS) throw err;
          await this.sleep(1_000 * attempt);
        }
      }
    } catch (err) {
      return { ok: false, error: (err as Error).message };
    }
  }

  upsert(rec: CfRecord): Promise<CfResult> {
    const wanted = rec.type === "MX" ? mxValue(rec) : txtValue(rec.content);
    const kind =
      rec.type !== "TXT"
        ? null
        : rec.content.startsWith("v=spf1")
          ? "v=spf1"
          : rec.content.startsWith("v=DKIM1")
            ? "v=DKIM1"
            : null;
    return this.#apply(rec, (values) => {
      if (values.some((v) => same(rec, v))) return { values: null, action: "exists" };
      const i = kind ? values.findIndex((v) => txtText(v).startsWith(kind)) : -1;
      if (i >= 0) {
        return { values: values.map((v, j) => (j === i ? wanted : v)), action: "updated" };
      }
      return { values: [...values, wanted], action: "created" };
    });
  }

  remove(rec: CfRecord): Promise<CfResult> {
    return this.#apply(rec, (values) => {
      const rest = values.filter((v) => !same(rec, v));
      return rest.length === values.length
        ? { values: null, action: "absent" }
        : { values: rest, action: "removed" };
    });
  }
}
