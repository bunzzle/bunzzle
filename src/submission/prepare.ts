import {
  type AddressError,
  domainOf,
  needsSmtpUtf8,
  normalizeAddress,
  parseAddress,
} from "../mime/address.ts";
import { newMessageId } from "../mime/builder.ts";
import { rfc5322Date } from "../mime/encodings.ts";
import { decodeWords, fromBinary } from "../mime/parse.ts";

export class SubmitError extends Error {
  constructor(
    readonly code: number,
    readonly text: string,
  ) {
    super(text);
  }
}

export interface Submitted {
  from: string;
  fromDomain: string;
  recipients: string[];
  data: string;
  smtpUtf8: boolean;
  meta: {
    from: string;
    to: string[];
    cc: string[];
    bcc: string[];
    replyTo: string[];
    tags: { name: string; value: string }[];
    lane: "transactional";
  };
}

const DROP = new Set(["bcc", "return-path", "x-bunzzle-ref", "dkim-signature"]);
const ADDR = /[^\s<>(),;:"[\]\\]+@[^\s<>(),;:"[\]\\]+/g;

const utf8 = new TextDecoder("utf-8", { fatal: true });

function asText(raw: string): string {
  if (!/[\x80-\xff]/.test(raw)) return raw;
  try {
    return utf8.decode(fromBinary(raw));
  } catch {
    throw new SubmitError(
      554,
      "5.6.0 8-bit content must be UTF-8; send other charsets as quoted-printable or base64",
    );
  }
}

interface Field {
  name: string;
  lines: string[];
}

function fields(head: string): Field[] {
  const out: Field[] = [];
  for (const line of head.split("\r\n")) {
    const last = out.at(-1);
    if ((line.startsWith(" ") || line.startsWith("\t")) && last) {
      last.lines.push(line);
      continue;
    }
    const colon = line.indexOf(":");
    if (colon <= 0 || !/^[\x21-\x39\x3b-\x7e]+$/.test(line.slice(0, colon))) {
      throw new SubmitError(554, "5.6.0 Malformed header line");
    }
    out.push({ name: line.slice(0, colon).toLowerCase(), lines: [line] });
  }
  return out;
}

const fieldText = (f: Field) =>
  decodeWords(
    f.lines
      .join("")
      .slice(f.name.length + 1)
      .trim(),
  );

const addresses = (list: Field[], name: string) =>
  list
    .filter((f) => f.name === name)
    .flatMap((f) => fieldText(f).match(ADDR) ?? [])
    .map((a) => a.toLowerCase())
    .slice(0, 1000);

export function prepareSubmitted(raw: string, recipients: string[], now: Date): Submitted {
  const text = asText(raw);
  const split = text.indexOf("\r\n\r\n");
  const head = split < 0 ? text.replace(/\r\n$/, "") : text.slice(0, split);
  const body = split < 0 ? "" : text.slice(split + 4);
  const all = fields(head);
  const froms = all.filter((f) => f.name === "from");
  if (froms.length !== 1) {
    throw new SubmitError(550, "5.6.0 The message needs exactly one From header");
  }
  let from: string;
  try {
    from = parseAddress(fieldText(froms[0] as Field)).address;
  } catch {
    throw new SubmitError(550, "5.1.7 The From header has no valid address");
  }
  let rcpts: string[];
  try {
    rcpts = [...new Set(recipients.map((r) => normalizeAddress(r)))];
  } catch (err) {
    throw new SubmitError(550, `5.1.3 ${(err as AddressError).message}`);
  }
  const fromDomain = domainOf(from);
  const kept = all.filter((f) => !DROP.has(f.name));
  if (!kept.some((f) => f.name === "message-id")) {
    kept.push({ name: "message-id", lines: [`Message-ID: ${newMessageId(fromDomain)}`] });
  }
  if (!kept.some((f) => f.name === "date")) {
    kept.push({ name: "date", lines: [`Date: ${rfc5322Date(now)}`] });
  }
  const to = addresses(all, "to");
  const cc = addresses(all, "cc");
  const shown = new Set([...to, ...cc]);
  return {
    from,
    fromDomain,
    recipients: rcpts,
    data: `${kept.flatMap((f) => f.lines).join("\r\n")}\r\n\r\n${body}`,
    smtpUtf8: [from, ...rcpts].some(needsSmtpUtf8),
    meta: {
      from: fieldText(froms[0] as Field).slice(0, 1000),
      to,
      cc,
      bcc: rcpts.filter((r) => !shown.has(r)),
      replyTo: addresses(all, "reply-to").slice(0, 50),
      tags: [],
      lane: "transactional",
    },
  };
}
