import { type Address, domainOf, formatAddress, needsSmtpUtf8 } from "./address.ts";
import {
  base64Lines,
  foldHeader,
  isAscii,
  needsQuotedPrintable,
  quotedPrintable,
  rfc5322Date,
  toCrlf,
  unstructured,
} from "./encodings.ts";

export interface Attachment {
  filename: string;
  content: Uint8Array;
  contentType?: string;
  contentId?: string;
}

export interface MessageInput {
  from: Address;
  to: Address[];
  cc?: Address[];
  replyTo?: Address[];
  subject: string;
  text?: string;
  html?: string;
  attachments?: Attachment[];
  headers?: Record<string, string>;
  messageId: string;
  date: Date;
}

export interface BuiltMessage {
  raw: string;
  messageId: string;
  smtpUtf8: boolean;
}

export class MimeError extends Error {}

const HEADER_NAME = /^[!-9;-~]+$/;
const RESERVED = new Set([
  "from",
  "to",
  "cc",
  "bcc",
  "reply-to",
  "subject",
  "date",
  "message-id",
  "mime-version",
  "content-type",
  "content-transfer-encoding",
  "dkim-signature",
  "return-path",
]);

export function newMessageId(domain: string): string {
  return `<${Bun.randomUUIDv7()}@${domain}>`;
}

function boundary(): string {
  return `bz_${crypto.getRandomValues(new Uint8Array(12)).toHex()}`;
}

interface Part {
  headers: string[];
  body: string;
}

function textPart(text: string, subtype: "plain" | "html"): Part {
  if (needsQuotedPrintable(text)) {
    return {
      headers: [
        `Content-Type: text/${subtype}; charset=utf-8`,
        "Content-Transfer-Encoding: quoted-printable",
      ],
      body: quotedPrintable(text),
    };
  }
  return {
    headers: [`Content-Type: text/${subtype}; charset=utf-8`, "Content-Transfer-Encoding: 7bit"],
    body: toCrlf(text),
  };
}

function paramValue(name: string, value: string): string {
  if (isAscii(value) && !/["\\\r\n]/.test(value)) return `${name}="${value}"`;
  return `${name}*=UTF-8''${encodeURIComponent(value).replace(/['()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`)}`;
}

function attachmentPart(a: Attachment): Part {
  if (/[\r\n]/.test(a.filename)) throw new MimeError("attachment filename contains a line break");
  const type = a.contentType ?? "application/octet-stream";
  if (!/^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/i.test(type)) {
    throw new MimeError(`invalid attachment content type: ${type}`);
  }
  const headers = [
    `Content-Type: ${type}; ${paramValue("name", a.filename)}`,
    "Content-Transfer-Encoding: base64",
    `Content-Disposition: ${a.contentId ? "inline" : "attachment"}; ${paramValue("filename", a.filename)}`,
  ];
  if (a.contentId) {
    if (!/^[^<>\s]+$/.test(a.contentId)) throw new MimeError("invalid content id");
    headers.push(`Content-ID: <${a.contentId}>`);
  }
  return { headers, body: base64Lines(a.content) };
}

function multipart(subtype: string, parts: Part[]): Part {
  const b = boundary();
  const body = parts
    .map((p) => `--${b}\r\n${p.headers.join("\r\n")}\r\n\r\n${p.body}\r\n`)
    .join("");
  return {
    headers: [`Content-Type: multipart/${subtype}; boundary="${b}"`],
    body: `${body}--${b}--`,
  };
}

function addressList(list: Address[]): string {
  return list.map(formatAddress).join(", ");
}

export function buildMessage(input: MessageInput): BuiltMessage {
  if (input.to.length === 0 && (input.cc?.length ?? 0) === 0) {
    throw new MimeError("at least one recipient is required");
  }
  if (input.text === undefined && input.html === undefined) {
    throw new MimeError("text or html body is required");
  }
  if (/[\r\n]/.test(input.subject)) throw new MimeError("subject contains a line break");
  if (!/^<[^<>\s@]+@[^<>\s@]+>$/.test(input.messageId)) throw new MimeError("invalid message id");

  const all = [input.from, ...input.to, ...(input.cc ?? []), ...(input.replyTo ?? [])];
  const smtpUtf8 = all.some((a) => needsSmtpUtf8(a.address));

  const headers: string[] = [
    foldHeader("From", formatAddress(input.from)),
    ...(input.to.length > 0 ? [foldHeader("To", addressList(input.to))] : []),
    ...(input.cc?.length ? [foldHeader("Cc", addressList(input.cc))] : []),
    ...(input.replyTo?.length ? [foldHeader("Reply-To", addressList(input.replyTo))] : []),
    foldHeader("Subject", unstructured(input.subject)),
    `Date: ${rfc5322Date(input.date)}`,
    `Message-ID: ${input.messageId}`,
  ];

  for (const [name, value] of Object.entries(input.headers ?? {})) {
    if (!HEADER_NAME.test(name)) throw new MimeError(`invalid header name: ${name}`);
    if (RESERVED.has(name.toLowerCase())) throw new MimeError(`header not allowed: ${name}`);
    if (/[\r\n]/.test(value)) throw new MimeError(`header ${name} contains a line break`);
    headers.push(foldHeader(name, unstructured(value)));
  }
  headers.push("MIME-Version: 1.0");

  const bodies: Part[] = [];
  if (input.text !== undefined) bodies.push(textPart(input.text, "plain"));
  if (input.html !== undefined) bodies.push(textPart(input.html, "html"));
  let root = bodies.length === 2 ? multipart("alternative", bodies) : (bodies[0] as Part);
  const attachments = input.attachments ?? [];
  if (attachments.length > 0) root = multipart("mixed", [root, ...attachments.map(attachmentPart)]);

  const raw = `${[...headers, ...root.headers].join("\r\n")}\r\n\r\n${root.body}\r\n`;
  for (const line of raw.split("\r\n")) {
    if (line.length > 998) throw new MimeError("a line is longer than 998 characters");
  }
  return { raw, messageId: input.messageId, smtpUtf8 };
}

export function senderDomain(input: Pick<MessageInput, "from">): string {
  return domainOf(input.from.address);
}
