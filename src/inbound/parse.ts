import {
  headerText,
  MIME_LIMITS,
  type MimeLimits,
  type MimePart,
  parseHeaderBlock,
  parseMime,
  walkParts,
} from "../mime/parse.ts";

export interface DsnRecipient {
  address: string;
  action: string;
  status: string | null;
  diagnostic: string | null;
  remoteMta: string | null;
}

export type Report =
  | { kind: "dsn"; ref: string | null; recipients: DsnRecipient[] }
  | { kind: "arf"; ref: string | null; feedbackType: string; originalRcpt: string | null }
  | { kind: "auto-reply"; ref: string | null }
  | {
      kind: "bounce";
      ref: string | null;
      status: string | null;
      diagnostic: string;
      addresses: string[];
    }
  | { kind: "unknown"; ref: string | null };

const REF = /^x-bunzzle-ref:[ \t]*([a-z2-7]{20,80})/im;

function findRef(parts: MimePart[]): string | null {
  for (const p of parts) {
    const h = p.headers.get("x-bunzzle-ref")?.[0];
    if (h && /^[a-z2-7]{20,80}$/i.test(h)) return h.toLowerCase();
    if (p.type === "text/rfc822-headers" || p.type === "message/rfc822-headers") {
      const m = REF.exec(p.body);
      if (m) return (m[1] as string).toLowerCase();
    }
  }
  const m = REF.exec(parts.map((p) => p.body).join("\n"));
  return m ? (m[1] as string).toLowerCase() : null;
}

function field(block: Map<string, string[]>, name: string): string | null {
  return block.get(name)?.[0] ?? null;
}

function stripType(value: string | null): string | null {
  if (!value) return null;
  const semi = value.indexOf(";");
  return (semi >= 0 ? value.slice(semi + 1) : value).trim().replace(/^<|>$/g, "") || null;
}

function parseDsn(text: string): DsnRecipient[] {
  const blocks = text.split(/\r?\n\s*\r?\n/).filter((b) => b.trim());
  const out: DsnRecipient[] = [];
  for (const b of blocks.slice(1)) {
    const h = parseHeaderBlock(b);
    const address = stripType(field(h, "final-recipient") ?? field(h, "original-recipient"));
    if (!address) continue;
    out.push({
      address: address.toLowerCase(),
      action: (field(h, "action") ?? "").toLowerCase(),
      status: field(h, "status"),
      diagnostic: stripType(field(h, "diagnostic-code")),
      remoteMta: stripType(field(h, "remote-mta")),
    });
  }
  return out;
}

const AUTO_SUBJECT =
  /^(auto(matic)?[ -]?(reply|response|antwort)|out of (the )?office|abwesend|absence|r[ée]ponse automatique|vacation|away from)/i;
const BOUNCE_SUBJECT =
  /undeliver|delivery (status notification|failure|has failed)|returned mail|failure notice|mail delivery (failed|system)|non[- ]?delivery/i;

export function classifyReport(raw: Uint8Array | string, limits: MimeLimits = MIME_LIMITS): Report {
  const root = parseMime(raw, limits);
  const parts = walkParts(root);
  const ref = findRef(parts);
  const report = parts.find((p) => p.type === "multipart/report");
  const reportType = report?.params.get("report-type")?.toLowerCase();
  if (report && reportType === "delivery-status") {
    const status = walkParts(report).find(
      (p) => p.type === "message/delivery-status" || p.type === "message/global-delivery-status",
    );
    return { kind: "dsn", ref, recipients: status ? parseDsn(status.body) : [] };
  }
  if (report && reportType === "feedback-report") {
    const fb = walkParts(report).find((p) => p.type === "message/feedback-report");
    const h = fb ? parseHeaderBlock(fb.body) : new Map<string, string[]>();
    return {
      kind: "arf",
      ref,
      feedbackType: (field(h, "feedback-type") ?? "abuse").toLowerCase(),
      originalRcpt: stripType(field(h, "original-rcpt-to"))?.toLowerCase() ?? null,
    };
  }
  const h = root.headers;
  const subject = headerText(root, "subject") ?? "";
  const auto = (h.get("auto-submitted")?.[0] ?? "no").toLowerCase();
  const from = (headerText(root, "from") ?? "").toLowerCase();
  const text = parts
    .filter((p) => p.type.startsWith("text/") || p.type === "message/rfc822")
    .map((p) => p.body)
    .join("\n")
    .slice(0, 200_000);
  const looksBounce = BOUNCE_SUBJECT.test(subject) || /mailer-daemon|postmaster/.test(from);
  if (looksBounce) {
    const m = /\b([45]\d\d)[ -]([245]\.\d{1,3}\.\d{1,3})?[ \t]*([^\r\n]{0,300})/.exec(text);
    const enhanced = /\b([45]\.\d{1,3}\.\d{1,3})\b/.exec(text)?.[1] ?? null;
    const addresses = [
      ...new Set(
        [...text.matchAll(/<?([A-Za-z0-9._%+'-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})>?/g)].map((x) =>
          (x[1] as string).toLowerCase(),
        ),
      ),
    ].slice(0, 50);
    return {
      kind: "bounce",
      ref,
      status: m?.[2] ?? enhanced,
      diagnostic: m
        ? `${m[1]} ${m[2] ?? ""} ${m[3] ?? ""}`.replace(/\s+/g, " ").trim()
        : text.trim().slice(0, 300),
      addresses,
    };
  }
  if (
    auto !== "no" ||
    h.has("x-autoreply") ||
    h.has("x-autorespond") ||
    /auto[_-]?reply/i.test(h.get("precedence")?.[0] ?? "") ||
    AUTO_SUBJECT.test(subject)
  ) {
    return { kind: "auto-reply", ref };
  }
  return { kind: "unknown", ref };
}
