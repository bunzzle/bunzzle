import { MIME_LIMITS, type MimePart, parseMime, walkParts } from "../mime/parse.ts";
import { child, children, parseXml, textAt, type XmlNode } from "./xml.ts";

export class DmarcError extends Error {}

export interface DmarcRow {
  sourceIp: string;
  count: number;
  disposition: string;
  dkim: string;
  spf: string;
  headerFrom: string;
  envelopeFrom: string | null;
  dkimDomains: string[];
  spfDomain: string | null;
}

export interface DmarcReport {
  org: string;
  email: string | null;
  reportId: string;
  begin: number;
  end: number;
  domain: string;
  policy: string;
  rows: DmarcRow[];
}

export const DMARC_LIMITS = { unpacked: 20 * 1024 * 1024, ratio: 200, rows: 10_000 };

const TYPES = /^application\/(zip|x-zip-compressed|gzip|x-gzip|xml)$|^text\/xml$/;

function payload(root: MimePart): { kind: "zip" | "gzip" | "xml"; data: Uint8Array } | null {
  for (const p of walkParts(root)) {
    if (p.parts.length > 0) continue;
    const name = (p.filename ?? "").toLowerCase();
    const byType = TYPES.exec(p.type);
    let kind: "zip" | "gzip" | "xml" | null = null;
    if (byType)
      kind =
        p.type.includes("zip") && !p.type.includes("gzip")
          ? "zip"
          : p.type.includes("gzip")
            ? "gzip"
            : "xml";
    else if (name.endsWith(".zip")) kind = "zip";
    else if (name.endsWith(".gz")) kind = "gzip";
    else if (name.endsWith(".xml")) kind = "xml";
    if (kind) return { kind, data: p.content };
  }
  return null;
}

async function inflate(
  data: Uint8Array,
  format: "gzip" | "deflate-raw",
  max: number,
): Promise<Uint8Array> {
  const stream = new Blob([data as Uint8Array<ArrayBuffer>])
    .stream()
    .pipeThrough(new DecompressionStream(format));
  const chunks: Uint8Array[] = [];
  let n = 0;
  try {
    for await (const c of stream) {
      n += c.length;
      if (n > max) throw new DmarcError("the report is too large when unpacked");
      chunks.push(c);
    }
  } catch (err) {
    if (err instanceof DmarcError) throw err;
    throw new DmarcError("the report could not be unpacked");
  }
  const out = new Uint8Array(n);
  let at = 0;
  for (const c of chunks) {
    out.set(c, at);
    at += c.length;
  }
  return out;
}

async function unzip(data: Uint8Array, max: number): Promise<Uint8Array> {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  let eocd = -1;
  for (let i = data.length - 22; i >= Math.max(0, data.length - 65_557); i--) {
    if (view.getUint32(i, true) === 0x06054b50) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new DmarcError("not a zip file");
  const entries = view.getUint16(eocd + 10, true);
  let at = view.getUint32(eocd + 16, true);
  for (let e = 0; e < Math.min(entries, 16); e++) {
    if (at + 46 > data.length || view.getUint32(at, true) !== 0x02014b50) break;
    const method = view.getUint16(at + 10, true);
    const compressed = view.getUint32(at + 20, true);
    const nameLen = view.getUint16(at + 28, true);
    const extraLen = view.getUint16(at + 30, true);
    const commentLen = view.getUint16(at + 32, true);
    const local = view.getUint32(at + 42, true);
    const name = new TextDecoder().decode(data.subarray(at + 46, at + 46 + nameLen));
    at += 46 + nameLen + extraLen + commentLen;
    if (!name.toLowerCase().endsWith(".xml")) continue;
    if (local + 30 > data.length || view.getUint32(local, true) !== 0x04034b50) {
      throw new DmarcError("broken zip entry");
    }
    const start = local + 30 + view.getUint16(local + 26, true) + view.getUint16(local + 28, true);
    const body = data.subarray(start, start + compressed);
    if (body.length !== compressed) throw new DmarcError("truncated zip entry");
    if (method === 0) {
      if (body.length > max) throw new DmarcError("the report is too large when unpacked");
      return body;
    }
    if (method === 8) return inflate(body, "deflate-raw", max);
    throw new DmarcError(`unsupported zip compression method ${method}`);
  }
  throw new DmarcError("no XML file in the zip");
}

function epoch(s: string | null): number {
  const n = Number(s);
  if (!s || !Number.isSafeInteger(n) || n < 0) throw new DmarcError("bad date range");
  return n * 1000;
}

function row(record: XmlNode): DmarcRow {
  const r = child(record, "row");
  const sourceIp = textAt(r, "source_ip");
  const headerFrom = textAt(record, "identifiers", "header_from");
  if (!sourceIp || !headerFrom) throw new DmarcError("a record without source_ip or header_from");
  const count = Number(textAt(r, "count") ?? "0");
  const auth = child(record, "auth_results");
  return {
    sourceIp: sourceIp.slice(0, 64),
    count: Number.isSafeInteger(count) && count >= 0 ? count : 0,
    disposition: (textAt(r, "policy_evaluated", "disposition") ?? "none").slice(0, 20),
    dkim: (textAt(r, "policy_evaluated", "dkim") ?? "fail").slice(0, 20),
    spf: (textAt(r, "policy_evaluated", "spf") ?? "fail").slice(0, 20),
    headerFrom: headerFrom.toLowerCase().slice(0, 253),
    envelopeFrom:
      textAt(record, "identifiers", "envelope_from")?.toLowerCase().slice(0, 253) ?? null,
    dkimDomains: children(auth, "dkim")
      .filter((d) => textAt(d, "result") === "pass")
      .map((d) => (textAt(d, "domain") ?? "").toLowerCase().slice(0, 253))
      .filter(Boolean)
      .slice(0, 10),
    spfDomain: (() => {
      const s = children(auth, "spf").find((x) => textAt(x, "result") === "pass");
      return s ? (textAt(s, "domain")?.toLowerCase().slice(0, 253) ?? null) : null;
    })(),
  };
}

export function reportFromXml(xml: string): DmarcReport {
  const feedback = child(parseXml(xml), "feedback");
  if (!feedback) throw new DmarcError("not a DMARC aggregate report");
  const meta = child(feedback, "report_metadata");
  const policy = child(feedback, "policy_published");
  const org = textAt(meta, "org_name");
  const reportId = textAt(meta, "report_id");
  const domain = textAt(policy, "domain");
  if (!org || !reportId || !domain)
    throw new DmarcError("the report misses org_name, report_id or domain");
  const records = children(feedback, "record");
  if (records.length > DMARC_LIMITS.rows) throw new DmarcError("too many records");
  return {
    org: org.slice(0, 200),
    email: textAt(meta, "email")?.slice(0, 320) ?? null,
    reportId: reportId.slice(0, 200),
    begin: epoch(textAt(meta, "date_range", "begin")),
    end: epoch(textAt(meta, "date_range", "end")),
    domain: domain.toLowerCase().slice(0, 253),
    policy: (textAt(policy, "p") ?? "none").slice(0, 20),
    rows: records.map(row),
  };
}

export async function readDmarcReport(raw: Uint8Array | string): Promise<DmarcReport> {
  const root = parseMime(raw, { ...MIME_LIMITS, maxParts: 10 });
  const found = payload(root);
  if (!found) throw new DmarcError("no report attachment");
  const max = Math.min(
    DMARC_LIMITS.unpacked,
    Math.max(64 * 1024, found.data.length * DMARC_LIMITS.ratio),
  );
  const xml =
    found.kind === "xml"
      ? found.data
      : found.kind === "gzip"
        ? await inflate(found.data, "gzip", max)
        : await unzip(found.data, max);
  return reportFromXml(new TextDecoder().decode(xml));
}
