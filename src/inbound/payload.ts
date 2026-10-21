import { decodeWords, fromBinary, type MimePart, parseMime } from "../mime/parse.ts";
import { type AuthResults, authPayload } from "./auth.ts";
import type { RouteFormat } from "./routes.ts";

export const ROUTE_MIME_LIMITS = { maxDepth: 10, maxParts: 200, maxHeaders: 1_000 };

export interface Envelope {
  id: string;
  receivedAt: number;
  mailFrom: string;
  rcptTo: string[];
  remoteIp: string;
  tls: boolean;
  auth: AuthResults | null;
}

interface Attachment {
  filename: string | null;
  content_type: string;
  content_id: string | null;
  size: number;
  content: string;
}

const header = (part: MimePart, name: string): string | null => {
  const v = part.headers.get(name)?.[0];
  return v === undefined ? null : decodeWords(v);
};

const isMessage = (p: MimePart) => p.type === "message/rfc822" || p.type === "message/global";

function leaves(part: MimePart): MimePart[] {
  if (isMessage(part) || part.parts.length === 0) return [part];
  return part.parts.flatMap(leaves);
}

function automated(top: MimePart, mailFrom: string): boolean {
  const auto = header(top, "auto-submitted");
  if (auto && auto.trim().toLowerCase() !== "no") return true;
  const precedence = header(top, "precedence")?.trim().toLowerCase();
  if (precedence === "bulk" || precedence === "list" || precedence === "junk") return true;
  return top.headers.has("list-id") || mailFrom === "";
}

function envelopeFields(e: Envelope) {
  return {
    id: e.id,
    received_at: new Date(e.receivedAt).toISOString(),
    mail_from: e.mailFrom,
    rcpt_to: e.rcptTo,
    remote_ip: e.remoteIp,
    tls: e.tls,
    auth: e.auth ? authPayload(e.auth) : null,
  };
}

export function buildPayload(raw: string, e: Envelope, format: RouteFormat): string {
  if (format === "raw") {
    return JSON.stringify({ ...envelopeFields(e), raw: fromBinary(raw).toBase64() });
  }
  const top = parseMime(raw, ROUTE_MIME_LIMITS);
  let text: string | null = null;
  let html: string | null = null;
  const attachments: Attachment[] = [];
  for (const p of leaves(top)) {
    const attached = p.disposition === "attachment" || p.filename !== null;
    if (!attached && p.type === "text/plain" && text === null) text = p.body;
    else if (!attached && p.type === "text/html" && html === null) html = p.body;
    else if (!p.type.startsWith("multipart/")) {
      const id = p.headers.get("content-id")?.[0]?.trim().replace(/^<|>$/g, "") ?? null;
      attachments.push({
        filename: p.filename ?? (isMessage(p) ? "message.eml" : null),
        content_type: p.type,
        content_id: id || null,
        size: p.content.byteLength,
        content: p.content.toBase64(),
      });
    }
  }
  const headers: [string, string][] = [];
  for (const [name, values] of top.headers) {
    for (const v of values) headers.push([name, decodeWords(v)]);
  }
  return JSON.stringify({
    ...envelopeFields(e),
    from: header(top, "from"),
    to: header(top, "to"),
    cc: header(top, "cc"),
    reply_to: header(top, "reply-to"),
    subject: header(top, "subject"),
    date: header(top, "date"),
    message_id: header(top, "message-id"),
    in_reply_to: header(top, "in-reply-to"),
    references: header(top, "references"),
    automated: automated(top, e.mailFrom),
    headers,
    text,
    html,
    attachments,
  });
}
