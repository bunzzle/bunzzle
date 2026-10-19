export type ResultType =
  | "starttls-not-supported"
  | "certificate-host-mismatch"
  | "certificate-expired"
  | "certificate-not-trusted"
  | "validation-failure"
  | "sts-policy-fetch-error"
  | "sts-policy-invalid";

export interface AttemptSession {
  host: string;
  address: string;
  phase: string;
  error: string | null;
  tls: { status: string; error: string | null } | null;
}

export interface AttemptEvent {
  target: string;
  source: string | null;
  sts: { mode: string; id: string; mx: string[]; maxAge: number } | null;
  sessions: AttemptSession[];
}

const HOST = new Set([
  "ERR_TLS_CERT_ALTNAME_INVALID",
  "HOSTNAME_MISMATCH",
  "ERR_TLS_CERT_ALTNAME_FORMAT",
]);
const EXPIRED = new Set(["CERT_HAS_EXPIRED", "CERT_NOT_YET_VALID"]);
const UNTRUSTED = new Set([
  "SELF_SIGNED_CERT_IN_CHAIN",
  "DEPTH_ZERO_SELF_SIGNED_CERT",
  "UNABLE_TO_GET_ISSUER_CERT",
  "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
  "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
  "CERT_UNTRUSTED",
  "CERT_REVOKED",
]);

export function sessionResult(s: AttemptSession): "success" | ResultType | null {
  const status = s.tls?.status ?? "none";
  if (status === "verified") return "success";
  if (status === "unverified") {
    const code = s.tls?.error ?? "";
    if (HOST.has(code)) return "certificate-host-mismatch";
    if (EXPIRED.has(code)) return "certificate-expired";
    if (UNTRUSTED.has(code)) return "certificate-not-trusted";
    return "validation-failure";
  }
  if (s.phase === "starttls" && /handshake/i.test(s.error ?? "")) return "validation-failure";
  const pastHello = s.phase !== "connect" && s.phase !== "greeting" && s.phase !== "ehlo";
  if (pastHello || /STARTTLS/.test(s.error ?? "")) return "starttls-not-supported";
  return null;
}

interface Detail {
  "result-type": ResultType;
  "sending-mta-ip"?: string;
  "receiving-mx-hostname": string;
  "receiving-ip": string;
  "failed-session-count": number;
}

interface PolicyBlock {
  policy: {
    "policy-type": "sts" | "no-policy-found";
    "policy-string"?: string[];
    "policy-domain": string;
    "mx-host"?: string[];
  };
  summary: { "total-successful-session-count": number; "total-failure-session-count": number };
  "failure-details": Detail[];
}

export interface TlsReport {
  "organization-name": string;
  "date-range": { "start-datetime": string; "end-datetime": string };
  "contact-info": string;
  "report-id": string;
  policies: PolicyBlock[];
}

export function stsPolicyString(sts: NonNullable<AttemptEvent["sts"]>): string[] {
  return [
    "version: STSv1",
    `mode: ${sts.mode}`,
    ...sts.mx.map((m) => `mx: ${m}`),
    `max_age: ${sts.maxAge}`,
  ];
}

export class Aggregator {
  readonly #domains = new Map<string, Map<string, PolicyBlock>>();

  add(e: AttemptEvent) {
    const domain = e.target.toLowerCase();
    const key = e.sts ? `sts:${e.sts.id}` : "none";
    let policies = this.#domains.get(domain);
    if (!policies) {
      policies = new Map();
      this.#domains.set(domain, policies);
    }
    let block = policies.get(key);
    if (!block) {
      block = {
        policy: e.sts
          ? {
              "policy-type": "sts",
              "policy-string": stsPolicyString(e.sts),
              "policy-domain": domain,
              "mx-host": e.sts.mx,
            }
          : { "policy-type": "no-policy-found", "policy-domain": domain },
        summary: { "total-successful-session-count": 0, "total-failure-session-count": 0 },
        "failure-details": [],
      };
      policies.set(key, block);
    }
    for (const s of e.sessions) {
      const r = sessionResult(s);
      if (r === null) continue;
      if (r === "success") {
        block.summary["total-successful-session-count"]++;
        continue;
      }
      block.summary["total-failure-session-count"]++;
      const source = e.source && e.source !== "default" ? e.source : undefined;
      const found = block["failure-details"].find(
        (d) =>
          d["result-type"] === r &&
          d["receiving-mx-hostname"] === s.host &&
          d["receiving-ip"] === s.address &&
          d["sending-mta-ip"] === source,
      );
      if (found) found["failed-session-count"]++;
      else if (block["failure-details"].length < 1000) {
        block["failure-details"].push({
          "result-type": r,
          ...(source ? { "sending-mta-ip": source } : {}),
          "receiving-mx-hostname": s.host,
          "receiving-ip": s.address,
          "failed-session-count": 1,
        });
      }
    }
  }

  domains(): string[] {
    return [...this.#domains.keys()].sort();
  }

  report(
    domain: string,
    o: { org: string; contact: string; start: number; end: number; id: string },
  ): TlsReport | null {
    const policies = this.#domains.get(domain);
    if (!policies) return null;
    const blocks = [...policies.values()].filter(
      (p) =>
        p.summary["total-successful-session-count"] + p.summary["total-failure-session-count"] > 0,
    );
    if (blocks.length === 0) return null;
    return {
      "organization-name": o.org,
      "date-range": {
        "start-datetime": new Date(o.start).toISOString().replace(/\.\d{3}Z$/, "Z"),
        "end-datetime": new Date(o.end).toISOString().replace(/\.\d{3}Z$/, "Z"),
      },
      "contact-info": o.contact,
      "report-id": o.id,
      policies: blocks,
    };
  }
}

export interface Rua {
  mailto: string[];
  https: string[];
}

export function parseTlsRpt(txt: string[]): Rua | null {
  const records = txt.filter((t) => /^v=TLSRPTv1\s*(;|$)/i.test(t.trim()));
  if (records.length !== 1) return null;
  const rua = /(?:^|;)\s*rua=([^;]+)/i.exec(records[0] as string)?.[1] ?? "";
  const out: Rua = { mailto: [], https: [] };
  for (const raw of rua
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .slice(0, 10)) {
    if (/^mailto:/i.test(raw)) {
      const address = decodeURIComponent(raw.slice(7).split("?")[0] ?? "");
      if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(address)) out.mailto.push(address);
    } else if (/^https:\/\//i.test(raw) && URL.canParse(raw)) {
      out.https.push(raw);
    }
  }
  return out.mailto.length || out.https.length ? out : null;
}

export function reportMail(
  r: TlsReport,
  domain: string,
  o: { from: string; to: string; submitter: string; messageId: string; date: string },
): string {
  const start = Math.floor(Date.parse(r["date-range"]["start-datetime"]) / 1000);
  const end = Math.floor(Date.parse(r["date-range"]["end-datetime"]) / 1000);
  const file = `${o.submitter}!${domain}!${start}!${end}!${r["report-id"].replace(/[^A-Za-z0-9.-]/g, "")}.json.gz`;
  const gz = Bun.gzipSync(new TextEncoder().encode(JSON.stringify(r)));
  const boundary = `tlsrpt_${crypto.getRandomValues(new Uint8Array(12)).toHex()}`;
  const b64 = gz.toBase64().replace(/.{76}/g, "$&\r\n");
  return [
    `From: ${o.from}`,
    `To: ${o.to}`,
    `Subject: Report Domain: ${domain} Submitter: ${o.submitter} Report-ID: <${r["report-id"]}>`,
    `Date: ${o.date}`,
    `Message-ID: ${o.messageId}`,
    `TLS-Report-Domain: ${domain}`,
    `TLS-Report-Submitter: ${o.submitter}`,
    "MIME-Version: 1.0",
    `Content-Type: multipart/report; report-type="tlsrpt"; boundary="${boundary}"`,
    "",
    `--${boundary}`,
    "Content-Type: text/plain; charset=us-ascii",
    "",
    `This is an aggregate TLS report from ${o.submitter} for ${domain}.`,
    `--${boundary}`,
    `Content-Type: application/tlsrpt+gzip; name="${file}"`,
    "Content-Transfer-Encoding: base64",
    `Content-Disposition: attachment; filename="${file}"`,
    "",
    b64,
    `--${boundary}--`,
    "",
  ].join("\r\n");
}
