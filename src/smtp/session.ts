import type { TlsaData } from "../dns/wire.ts";
import {
  type Reply,
  replyText,
  SmtpConnection,
  SmtpError,
  type TranscriptLine,
} from "./connection.ts";
import { verifyDane } from "./dane.ts";
import { SessionPool } from "./pool.ts";

export type TlsStatus = "none" | "unverified" | "verified" | "dane";
export type TlsRule =
  | "relay"
  | "dane"
  | "requiretls"
  | "mta-sts"
  | "provider"
  | "opportunistic"
  | "tls-optional";

export type RequireTlsMode = "enforce" | "relaxed";

export interface TlsPolicy {
  rule: TlsRule;
  required: boolean;
  tlsa?: TlsaData[];
  requiretls?: RequireTlsMode;
}

export interface TlsRecord {
  status: TlsStatus;
  rule: TlsRule;
  version: string | null;
  cipher: string | null;
  error: string | null;
}

export interface Timeouts {
  connect: number;
  greeting: number;
  ehlo: number;
  starttls: number;
  mail: number;
  rcpt: number;
  dataInit: number;
  dataXfer: number;
  dataDone: number;
  quit: number;
}

export const DEFAULT_TIMEOUTS: Timeouts = {
  connect: 30_000,
  greeting: 300_000,
  ehlo: 300_000,
  starttls: 300_000,
  mail: 300_000,
  rcpt: 300_000,
  dataInit: 120_000,
  dataXfer: 180_000,
  dataDone: 600_000,
  quit: 5_000,
};

export type Phase =
  | "dns"
  | "connect"
  | "greeting"
  | "ehlo"
  | "starttls"
  | "auth"
  | "mail"
  | "rcpt"
  | "data"
  | "dot";

export type RecipientStatus = "delivered" | "deferred" | "bounced" | "unknown";

export interface RecipientResult {
  address: string;
  status: RecipientStatus;
  phase: Phase;
  code: number | null;
  enhanced: string | null;
  reply: string;
}

export type OnOutcomes = (results: RecipientResult[]) => void;

export interface SessionInput {
  onOutcomes?: OnOutcomes | undefined;
  host: string;
  address: string;
  port: number;
  localAddress?: string;
  ehloName: string;
  policy: TlsPolicy;
  from: string;
  recipients: string[];
  data: string;
  smtpUtf8: boolean;
  timeouts?: Partial<Timeouts>;
  tlsCa?: string;
  names?: string[];
  implicitTls?: boolean;
  auth?: { username: string; password: string };
  pool?: SessionPool;
  perConnection?: number;
  maxOpen?: number;
  fresh?: boolean;
}

export interface SessionResult {
  host: string;
  address: string;
  startedAt: number;
  finishedAt: number;
  tls: TlsRecord;
  extensions: string[];
  phase: Phase | "done";
  error: string | null;
  tryNext: boolean;
  recipients: RecipientResult[];
  reused?: boolean | undefined;
  transcript?: TranscriptLine[] | undefined;
}

class Abort extends Error {
  constructor(
    readonly phase: Phase,
    readonly status: RecipientStatus,
    readonly tryNext: boolean,
    message: string,
    readonly reply: Reply | null = null,
    readonly enhanced: string | null = null,
  ) {
    super(message);
  }
}

const enc = new TextEncoder();

function statusOf(code: number): RecipientStatus {
  if (code >= 200 && code < 300) return "delivered";
  return code >= 500 ? "bounced" : "deferred";
}

function networkStatus(phase: Phase, err: SmtpError): string {
  if (phase === "connect") return "4.4.1";
  if (err.kind === "tls") return "4.7.5";
  if (err.kind === "protocol") return "4.5.0";
  return "4.4.2";
}

export function dotStuff(data: string): string {
  const body = data.endsWith("\r\n") ? data : `${data}\r\n`;
  return `${body.replace(/^\./gm, "..")}.\r\n`;
}

function parseEhlo(reply: Reply): Map<string, string> {
  const ext = new Map<string, string>();
  for (const line of reply.lines.slice(1)) {
    const [kw, ...rest] = line.trim().split(/\s+/);
    if (kw) ext.set(kw.toUpperCase(), rest.join(" "));
  }
  return ext;
}

export async function runSession(input: SessionInput): Promise<SessionResult> {
  const t: Timeouts = { ...DEFAULT_TIMEOUTS, ...input.timeouts };
  const startedAt = Date.now();
  const tls: TlsRecord = {
    status: "none",
    rule: input.policy.rule,
    version: null,
    cipher: null,
    error: null,
  };
  const result: SessionResult = {
    host: input.host,
    address: input.address,
    startedAt,
    finishedAt: startedAt,
    tls,
    extensions: [],
    phase: "connect",
    error: null,
    tryNext: false,
    recipients: [],
  };
  const results = new Map<string, RecipientResult>();
  let conn: SmtpConnection | null = null;
  let phase: Phase = "connect";
  const poolKey = input.pool ? SessionPool.key(input) : "";
  const pooled = input.pool && !input.fresh ? input.pool.take(poolKey) : null;
  let ext = new Map<string, string>();
  let uses = 0;
  let kept = false;

  const expect2xx = async (
    p: Phase,
    timeout: number,
    accept = (c: number) => c >= 200 && c < 300,
  ) => {
    if (!conn) throw new Error("no connection");
    const reply = await conn.readReply(timeout);
    if (!accept(reply.code)) {
      const temporary = reply.code < 500;
      throw new Abort(p, temporary ? "deferred" : "bounced", true, replyText(reply), reply);
    }
    return reply;
  };

  try {
    if (pooled) {
      conn = pooled.conn;
      ext = pooled.ext;
      Object.assign(tls, pooled.tls);
      uses = pooled.uses;
      result.reused = true;
      conn.transcript = { start: startedAt, lines: [] };
      conn.note("-", `reusing the connection to ${input.address}:${input.port}`);
    } else {
      conn = await SmtpConnection.connect({
        host: input.address,
        port: input.port,
        timeoutMs: t.connect,
        ...(input.localAddress ? { localAddress: input.localAddress } : {}),
      });
      conn.transcript = { start: startedAt, lines: [] };
      conn.note(
        "-",
        `connected to ${input.address}:${input.port}${input.localAddress ? ` from ${input.localAddress}` : ""}`,
      );

      if (input.implicitTls) {
        phase = "starttls";
        const info = await conn.startTls(input.host, t.starttls, input.tlsCa);
        tls.version = info.version;
        tls.cipher = info.cipher;
        tls.error = info.error;
        tls.status = info.authorized ? "verified" : "unverified";
        if (!info.authorized) {
          throw new Abort(
            phase,
            "deferred",
            false,
            `the certificate of ${input.host} is not valid: ${info.error}`,
            null,
            "4.7.5",
          );
        }
      }

      phase = "greeting";
      await expect2xx(phase, t.greeting, (c) => c === 220);

      phase = "ehlo";
      await conn.write(`EHLO ${input.ehloName}\r\n`, t.ehlo);
      let ehlo = await conn.readReply(t.ehlo);
      if (ehlo.code === 250) {
        ext = parseEhlo(ehlo);
      } else {
        await conn.write(`HELO ${input.ehloName}\r\n`, t.ehlo);
        ehlo = await conn.readReply(t.ehlo);
        if (ehlo.code !== 250) {
          throw new Abort(
            phase,
            ehlo.code >= 500 ? "bounced" : "deferred",
            true,
            replyText(ehlo),
            ehlo,
          );
        }
      }

      phase = "starttls";
      if (!input.implicitTls && ext.has("STARTTLS")) {
        await conn.write("STARTTLS\r\n", t.starttls);
        const r = await conn.readReply(t.starttls);
        if (r.code === 220) {
          const tlsa = input.policy.tlsa;
          const info = await conn.startTls(input.host, t.starttls, input.tlsCa);
          tls.version = info.version;
          tls.cipher = info.cipher;
          tls.error = info.error;
          tls.status = info.authorized ? "verified" : "unverified";
          if (tlsa) {
            const verdict = await verifyDane(tlsa, conn.peerChain(), input.names ?? [input.host]);
            if (!verdict.ok) {
              throw new Abort(
                phase,
                "deferred",
                true,
                `DANE: ${verdict.reason} (${input.host})`,
                null,
                "4.7.5",
              );
            }
            if (verdict.how !== "unauthenticated") tls.status = "dane";
          } else if (input.policy.required && !info.authorized) {
            throw new Abort(
              phase,
              "deferred",
              true,
              `TLS required (${input.policy.rule}) but the certificate of ${input.host} is not valid: ${info.error}`,
              null,
              "4.7.5",
            );
          }
          phase = "ehlo";
          await conn.write(`EHLO ${input.ehloName}\r\n`, t.ehlo);
          ext = parseEhlo(await expect2xx(phase, t.ehlo, (c) => c === 250));
        } else if (input.policy.required) {
          throw new Abort(
            phase,
            "deferred",
            true,
            `TLS required but STARTTLS was refused: ${replyText(r)}`,
            r,
            "4.7.10",
          );
        }
      } else if (input.policy.required && !input.implicitTls) {
        throw new Abort(
          phase,
          "deferred",
          true,
          `TLS required (${input.policy.rule}) but ${input.host} does not offer STARTTLS`,
          null,
          "4.7.10",
        );
      }
    }
    result.extensions = [...ext.keys()];

    const requiretls = input.policy.requiretls;
    if (requiretls === "enforce") {
      if (tls.status !== "verified" && tls.status !== "dane") {
        throw new Abort(
          "starttls",
          "deferred",
          true,
          `REQUIRETLS: the certificate of ${input.host} is not verified`,
          null,
          "4.7.10",
        );
      }
      if (!ext.has("REQUIRETLS")) {
        throw new Abort(
          "mail",
          "bounced",
          true,
          `REQUIRETLS: ${input.host} does not support REQUIRETLS`,
          null,
          "5.7.30",
        );
      }
    }

    const size = enc.encode(input.data).length;
    const maxSize = Number(ext.get("SIZE") ?? 0);
    if (maxSize > 0 && size > maxSize) {
      throw new Abort(
        "mail",
        "bounced",
        false,
        `message is ${size} bytes, server accepts at most ${maxSize}`,
        null,
        "5.3.4",
      );
    }
    if (input.smtpUtf8 && !ext.has("SMTPUTF8")) {
      throw new Abort(
        "mail",
        "bounced",
        false,
        `${input.host} does not support SMTPUTF8 addresses`,
        null,
        "5.6.7",
      );
    }

    if (input.auth && !result.reused) {
      phase = "auth";
      const mechs = (ext.get("AUTH") ?? "").toUpperCase().split(/\s+/);
      if (!mechs.includes("PLAIN")) {
        throw new Abort(
          phase,
          "deferred",
          false,
          `${input.host} does not offer AUTH PLAIN`,
          null,
          "4.7.0",
        );
      }
      const token = enc
        .encode(`\u0000${input.auth.username}\u0000${input.auth.password}`)
        .toBase64();
      await conn.write(`AUTH PLAIN ${token}\r\n`, t.mail);
      const r = await conn.readReply(t.mail);
      if (r.code !== 235) {
        throw new Abort(
          phase,
          "deferred",
          false,
          `relay login failed: ${replyText(r)}`,
          r,
          "4.7.0",
        );
      }
    }

    phase = "mail";
    let mail = `MAIL FROM:<${input.from}>`;
    if (ext.has("SIZE")) mail += ` SIZE=${size}`;
    if (input.smtpUtf8) mail += ext.has("8BITMIME") ? " BODY=8BITMIME SMTPUTF8" : " SMTPUTF8";
    if (requiretls && ext.has("REQUIRETLS") && tls.status !== "none") mail += " REQUIRETLS";
    const rcpts = input.recipients.map((r) => `RCPT TO:<${r}>`);
    const pipelining = ext.has("PIPELINING");

    const rejectMail = (r: Reply) => {
      if (r.code !== 250)
        throw new Abort("mail", statusOf(r.code), r.code === 421, replyText(r), r);
    };
    const rcptReplies: Reply[] = [];
    let dataReply: Reply | null = null;
    if (pipelining) {
      await conn.write(`${[mail, ...rcpts, "DATA"].join("\r\n")}\r\n`, t.mail);
      rejectMail(await conn.readReply(t.mail));
      phase = "rcpt";
      for (let i = 0; i < rcpts.length; i++) rcptReplies.push(await conn.readReply(t.rcpt));
      phase = "data";
      dataReply = await conn.readReply(t.dataInit);
    } else {
      await conn.write(`${mail}\r\n`, t.mail);
      rejectMail(await conn.readReply(t.mail));
      phase = "rcpt";
      for (const r of rcpts) {
        await conn.write(`${r}\r\n`, t.rcpt);
        rcptReplies.push(await conn.readReply(t.rcpt));
      }
    }

    const accepted: string[] = [];
    input.recipients.forEach((address, i) => {
      const r = rcptReplies[i] as Reply;
      if (r.code === 250 || r.code === 251) {
        accepted.push(address);
        return;
      }
      results.set(address, {
        address,
        status: statusOf(r.code),
        phase: "rcpt",
        code: r.code,
        enhanced: r.enhanced,
        reply: replyText(r),
      });
    });

    phase = "data";
    if (!pipelining && accepted.length > 0) {
      await conn.write("DATA\r\n", t.dataInit);
      dataReply = await conn.readReply(t.dataInit);
    }
    if (accepted.length === 0) {
      if (dataReply?.code === 354) await conn.write(".\r\n", t.dataXfer);
      result.phase = "rcpt";
    } else {
      const r = dataReply as Reply;
      if (r.code !== 354) throw new Abort("data", statusOf(r.code), false, replyText(r), r);
      await conn.write(dotStuff(input.data), t.dataXfer, { content: true });
      phase = "dot";
      let final: Reply;
      try {
        final = await conn.readReply(t.dataDone);
      } catch (err) {
        if (err instanceof SmtpError) {
          throw new Abort(
            "dot",
            "unknown",
            false,
            `no reply after the end of data: ${err.message}`,
          );
        }
        throw err;
      }
      for (const address of accepted) {
        results.set(address, {
          address,
          status: statusOf(final.code),
          phase: "dot",
          code: final.code,
          enhanced: final.enhanced,
          reply: replyText(final),
        });
      }
      result.phase = "done";
      input.onOutcomes?.(accepted.map((a) => results.get(a) as RecipientResult));
    }

    if (
      input.pool &&
      result.phase === "done" &&
      uses + 1 < (input.perConnection ?? 100) &&
      !conn.closed &&
      !conn.hasBufferedData()
    ) {
      input.pool.give(poolKey, { conn, ext, tls: { ...tls }, uses: uses + 1 }, input.maxOpen);
      kept = true;
    } else {
      try {
        await conn.write("QUIT\r\n", t.quit);
        await conn.readReply(t.quit);
      } catch {}
    }
  } catch (err) {
    if (pooled && err instanceof SmtpError && phase === "mail") {
      conn?.close();
      input.pool?.done(poolKey);
      kept = true;
      return runSession({ ...input, fresh: true });
    }
    let abort: Abort;
    if (err instanceof Abort) abort = err;
    else if (err instanceof SmtpError) {
      if (err.kind === "tls") tls.error = err.message;
      abort = new Abort(phase, "deferred", true, err.message, null, networkStatus(phase, err));
    } else throw err;
    result.phase = abort.phase;
    result.error = abort.message;
    conn?.note("-", abort.message);
    result.tryNext = abort.tryNext;
    for (const address of input.recipients) {
      if (results.has(address)) continue;
      results.set(address, {
        address,
        status: abort.status,
        phase: abort.phase,
        code: abort.reply?.code ?? null,
        enhanced: abort.reply?.enhanced ?? abort.enhanced,
        reply: abort.message,
      });
    }
    if (conn && !conn.closed && abort.phase !== "dot") {
      try {
        await conn.write("QUIT\r\n", t.quit);
      } catch {}
    }
  } finally {
    result.transcript = conn?.transcript?.lines;
    if (conn) conn.transcript = null;
    if (!kept) {
      conn?.close();
      input.pool?.done(poolKey);
    }
  }

  result.recipients = input.recipients.map((a) => results.get(a) as RecipientResult);
  result.finishedAt = Date.now();
  return result;
}
