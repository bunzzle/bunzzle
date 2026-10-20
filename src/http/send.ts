import { type Address, AddressError, domainOf, parseAddress } from "../mime/address.ts";
import { type Attachment, buildMessage, MimeError, newMessageId } from "../mime/builder.ts";
import { MissingVariables, parse, render, TemplateError } from "../templates/render.ts";
import { b } from "../validate/schema.ts";
import { ApiError } from "./errors.ts";

const addresses = b.union([b.string().min(1), b.array(b.string().min(1)).min(1).max(50)]);
const tag = b
  .string()
  .regex(/^[A-Za-z0-9_-]{1,256}$/, "tags may only use letters, digits, _ and -");

export const rescheduleSchema = b.object({ scheduled_at: b.string().max(64) });

export const sendSchema = b.object({
  from: b.string().min(3).max(1000),
  to: addresses,
  subject: b.string().max(998).optional(),
  template: b
    .object({
      id: b.string().min(1).max(64),
      version: b.number().int().min(1).optional(),
      variables: b.record(b.string(), b.unknown()).optional(),
    })
    .optional(),
  cc: addresses.optional(),
  bcc: addresses.optional(),
  reply_to: addresses.optional(),
  html: b
    .string()
    .max(40 * 1024 * 1024)
    .optional(),
  text: b
    .string()
    .max(40 * 1024 * 1024)
    .optional(),
  headers: b.record(b.string(), b.string().max(998)).optional(),
  attachments: b
    .array(
      b.object({
        filename: b.string().min(1).max(255),
        content: b.union([b.string(), b.array(b.number().int().min(0).max(255))]).optional(),
        path: b.string().optional(),
        content_type: b.string().max(255).optional(),
        content_id: b.string().max(255).optional(),
      }),
    )
    .max(100)
    .optional(),
  tags: b
    .array(b.object({ name: tag, value: tag }))
    .max(50)
    .optional(),
  scheduled_at: b.string().max(64).optional(),
  expires_at: b.string().max(64).optional(),
  require_tls: b.boolean().optional(),
  lane: b.enum(["transactional", "bulk"]).optional(),
});

export type SendRequest = b.infer<typeof sendSchema>;

export const templateResult = b.object({
  id: b.string(),
  name: b.string(),
  version: b.number(),
  subject: b.string(),
  html: b.string().nullable(),
  text: b.string().nullable(),
});

export type StoredTemplate = b.infer<typeof templateResult>;

export interface Rendered {
  subject: string;
  html?: string;
  text?: string;
}

export function renderTemplate(t: StoredTemplate, variables: Record<string, unknown>): Rendered {
  const missing = new Set<string>();
  const one = (field: string, source: string, mode: "html" | "text") => {
    try {
      return render(parse(source), variables, mode);
    } catch (err) {
      if (err instanceof MissingVariables) {
        for (const name of err.names) missing.add(name);
        return "";
      }
      if (err instanceof TemplateError) {
        throw new ApiError(422, "validation_error", `Template ${field}: ${err.message}`);
      }
      throw err;
    }
  };
  const out = {
    subject: one("subject", t.subject, "text"),
    ...(t.html !== null ? { html: one("html", t.html, "html") } : {}),
    ...(t.text !== null ? { text: one("text", t.text, "text") } : {}),
  };
  if (missing.size > 0) {
    throw new ApiError(
      422,
      "validation_error",
      `Missing template variables: ${[...missing].join(", ")}`,
    );
  }
  return out;
}

export function applyTemplate(req: SendRequest, t: StoredTemplate): SendRequest {
  if (req.subject !== undefined || req.html !== undefined || req.text !== undefined) {
    throw new ApiError(
      422,
      "validation_error",
      "Send either `template` or `subject`, `html` and `text`, not both.",
    );
  }
  return { ...req, ...renderTemplate(t, req.template?.variables ?? {}) };
}

export interface PreparedEmail {
  from: string;
  fromDomain: string;
  recipients: string[];
  data: string;
  smtpUtf8: boolean;
  requireTls: boolean;
  lane: "transactional" | "bulk";
  scheduledAt?: number;
  expiresAt?: number;
  meta: {
    from: string;
    to: string[];
    cc: string[];
    bcc: string[];
    replyTo: string[];
    tags: { name: string; value: string }[];
  };
}

const list = (v: string | string[] | undefined): string[] =>
  v === undefined ? [] : Array.isArray(v) ? v : [v];

function parseList(field: string, v: string | string[] | undefined): Address[] {
  return list(v).map((raw) => {
    try {
      return parseAddress(raw);
    } catch {
      throw new ApiError(422, "validation_error", `Invalid \`${field}\` field: ${raw}`);
    }
  });
}

function time(field: string, v: string | undefined): number | undefined {
  if (v === undefined) return undefined;
  const t = Date.parse(v);
  if (Number.isNaN(t)) {
    throw new ApiError(422, "validation_error", `\`${field}\` must be an ISO 8601 date`);
  }
  return t;
}

export function prepareEmail(req: SendRequest, now: Date): PreparedEmail {
  let from: Address;
  try {
    from = parseAddress(req.from);
  } catch {
    throw new ApiError(
      422,
      "validation_error",
      "Invalid `from` field. The email address needs to follow the `email@example.com` or `Name <email@example.com>` format.",
    );
  }
  const to = parseList("to", req.to);
  const cc = parseList("cc", req.cc);
  const bcc = parseList("bcc", req.bcc);
  const replyTo = parseList("reply_to", req.reply_to);
  if (to.length + cc.length + bcc.length > 50) {
    throw new ApiError(422, "validation_error", "At most 50 recipients (to, cc and bcc together)");
  }
  if (req.subject === undefined) {
    throw new ApiError(422, "validation_error", "Missing `subject` field.");
  }
  if (req.html === undefined && req.text === undefined) {
    throw new ApiError(422, "validation_error", "Missing `html` or `text` field.");
  }
  const attachments: Attachment[] = (req.attachments ?? []).map((a) => {
    if (a.path !== undefined) {
      throw new ApiError(
        422,
        "validation_error",
        "Attachments by `path` (URL) are not supported: send the file as `content` (base64).",
      );
    }
    if (a.content === undefined) {
      throw new ApiError(422, "validation_error", `Attachment ${a.filename} has no \`content\`.`);
    }
    let content: Uint8Array;
    try {
      content =
        typeof a.content === "string"
          ? Uint8Array.fromBase64(a.content.replace(/\s+/g, ""))
          : new Uint8Array(a.content);
    } catch {
      throw new ApiError(422, "validation_error", `Attachment ${a.filename} is not valid base64.`);
    }
    return {
      filename: a.filename,
      content,
      ...(a.content_type ? { contentType: a.content_type } : {}),
      ...(a.content_id ? { contentId: a.content_id } : {}),
    };
  });
  const fromDomain = domainOf(from.address);
  let built: ReturnType<typeof buildMessage>;
  try {
    built = buildMessage({
      from,
      to,
      ...(cc.length ? { cc } : {}),
      ...(replyTo.length ? { replyTo } : {}),
      subject: req.subject,
      ...(req.text !== undefined ? { text: req.text } : {}),
      ...(req.html !== undefined ? { html: req.html } : {}),
      ...(attachments.length ? { attachments } : {}),
      ...(req.headers ? { headers: req.headers } : {}),
      messageId: newMessageId(fromDomain),
      date: now,
    });
  } catch (err) {
    if (err instanceof MimeError || err instanceof AddressError) {
      throw new ApiError(422, "validation_error", err.message);
    }
    throw err;
  }
  const scheduledAt = time("scheduled_at", req.scheduled_at);
  const expiresAt = time("expires_at", req.expires_at);
  const recipients = [...new Set([...to, ...cc, ...bcc].map((a) => a.address))];
  if (req.lane === "bulk" && recipients.length !== 1) {
    throw new ApiError(
      422,
      "validation_error",
      "A bulk email must have exactly one recipient, so each one gets its own unsubscribe link.",
    );
  }
  return {
    from: from.address,
    fromDomain,
    recipients,
    data: built.raw,
    smtpUtf8: built.smtpUtf8,
    requireTls: req.require_tls ?? false,
    lane: req.lane ?? "transactional",
    ...(scheduledAt !== undefined ? { scheduledAt } : {}),
    ...(expiresAt !== undefined ? { expiresAt } : {}),
    meta: {
      from: req.from,
      to: to.map((a) => a.address),
      cc: cc.map((a) => a.address),
      bcc: bcc.map((a) => a.address),
      replyTo: replyTo.map((a) => a.address),
      tags: req.tags ?? [],
    },
  };
}
