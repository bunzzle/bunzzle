export interface Limits {
  maxDepth: number;
  maxParts: number;
  maxHeaders: number;
}

export const LIMITS: Limits = { maxDepth: 5, maxParts: 50, maxHeaders: 500 };

export interface Part {
  headers: Map<string, string[]>;
  type: string;
  params: Map<string, string>;
  body: string;
  parts: Part[];
}

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

export class ParseError extends Error {}

function splitHead(raw: string): { head: string; body: string } {
  const m = /\r?\n\r?\n/.exec(raw);
  if (!m) return { head: raw, body: "" };
  return { head: raw.slice(0, m.index), body: raw.slice(m.index + m[0].length) };
}

export function parseHeaders(head: string, limits: Limits = LIMITS): Map<string, string[]> {
  const out = new Map<string, string[]>();
  const lines = head.split(/\r?\n/);
  let count = 0;
  let current: { name: string; value: string } | null = null;
  const flush = () => {
    if (!current) return;
    if (++count > limits.maxHeaders) throw new ParseError("too many headers");
    const list = out.get(current.name) ?? [];
    list.push(current.value.trim());
    out.set(current.name, list);
    current = null;
  };
  for (const line of lines) {
    if (/^[ \t]/.test(line) && current) {
      current.value += ` ${line.trim()}`;
      continue;
    }
    flush();
    const colon = line.indexOf(":");
    if (colon <= 0) continue;
    current = { name: line.slice(0, colon).trim().toLowerCase(), value: line.slice(colon + 1) };
  }
  flush();
  return out;
}

function contentType(headers: Map<string, string[]>): {
  type: string;
  params: Map<string, string>;
} {
  const value = headers.get("content-type")?.[0] ?? "text/plain";
  const [type = "text/plain", ...rest] = value.split(";");
  const params = new Map<string, string>();
  for (const p of rest) {
    const eq = p.indexOf("=");
    if (eq < 0) continue;
    params.set(
      p.slice(0, eq).trim().toLowerCase(),
      p
        .slice(eq + 1)
        .trim()
        .replace(/^"(.*)"$/, "$1"),
    );
  }
  return { type: type.trim().toLowerCase(), params };
}

function decode(body: string, encoding: string | undefined): string {
  const e = encoding?.trim().toLowerCase();
  if (e === "base64") {
    try {
      return new TextDecoder().decode(Uint8Array.fromBase64(body.replace(/\s+/g, "")));
    } catch {
      return body;
    }
  }
  if (e === "quoted-printable") {
    const bytes: number[] = [];
    const text = body.replace(/=\r?\n/g, "");
    for (let i = 0; i < text.length; i++) {
      const ch = text[i] as string;
      if (ch === "=" && /^[0-9A-Fa-f]{2}$/.test(text.slice(i + 1, i + 3))) {
        bytes.push(Number.parseInt(text.slice(i + 1, i + 3), 16));
        i += 2;
      } else bytes.push(...new TextEncoder().encode(ch));
    }
    return new TextDecoder().decode(new Uint8Array(bytes));
  }
  return body;
}

export function parseMessage(raw: string, limits: Limits = LIMITS): Part {
  let parts = 0;
  const walk = (text: string, depth: number): Part => {
    if (depth > limits.maxDepth) throw new ParseError("MIME nesting too deep");
    if (++parts > limits.maxParts) throw new ParseError("too many MIME parts");
    const { head, body } = splitHead(text);
    const headers = parseHeaders(head, limits);
    const { type, params } = contentType(headers);
    const part: Part = { headers, type, params, body: "", parts: [] };
    const boundary = params.get("boundary");
    if (type.startsWith("multipart/") && boundary) {
      const sections = body.split(
        new RegExp(`\\r?\\n?--${escapeRegex(boundary)}(?:--)?[ \\t]*\\r?\\n?`),
      );
      for (const s of sections.slice(1, -1)) part.parts.push(walk(s, depth + 1));
      if (sections.length === 2 && sections[1]?.trim())
        part.parts.push(walk(sections[1], depth + 1));
    } else if (type === "message/rfc822") {
      part.parts.push(walk(body, depth + 1));
      part.body = body;
    } else {
      part.body = decode(body, headers.get("content-transfer-encoding")?.[0]);
    }
    return part;
  };
  return walk(raw, 0);
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function all(part: Part): Part[] {
  return [part, ...part.parts.flatMap(all)];
}

const REF = /^x-bunzzle-ref:[ \t]*([a-z2-7]{20,80})/im;

function findRef(root: Part): string | null {
  for (const p of all(root)) {
    const h = p.headers.get("x-bunzzle-ref")?.[0];
    if (h && /^[a-z2-7]{20,80}$/i.test(h)) return h.toLowerCase();
    if (p.type === "text/rfc822-headers" || p.type === "message/rfc822-headers") {
      const m = REF.exec(p.body);
      if (m) return (m[1] as string).toLowerCase();
    }
  }
  const m = REF.exec(
    all(root)
      .map((p) => p.body)
      .join("\n"),
  );
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
    const h = parseHeaders(b);
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

export function classifyReport(raw: string, limits: Limits = LIMITS): Report {
  const root = parseMessage(raw, limits);
  const ref = findRef(root);
  const report = all(root).find((p) => p.type === "multipart/report");
  const reportType = report?.params.get("report-type")?.toLowerCase();
  if (report && reportType === "delivery-status") {
    const status = all(report).find(
      (p) => p.type === "message/delivery-status" || p.type === "message/global-delivery-status",
    );
    return { kind: "dsn", ref, recipients: status ? parseDsn(status.body) : [] };
  }
  if (report && reportType === "feedback-report") {
    const fb = all(report).find((p) => p.type === "message/feedback-report");
    const h = fb ? parseHeaders(fb.body) : new Map<string, string[]>();
    return {
      kind: "arf",
      ref,
      feedbackType: (field(h, "feedback-type") ?? "abuse").toLowerCase(),
      originalRcpt: stripType(field(h, "original-rcpt-to"))?.toLowerCase() ?? null,
    };
  }
  const h = root.headers;
  const subject = h.get("subject")?.[0] ?? "";
  const auto = (h.get("auto-submitted")?.[0] ?? "no").toLowerCase();
  const from = (h.get("from")?.[0] ?? "").toLowerCase();
  const text = all(root)
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
