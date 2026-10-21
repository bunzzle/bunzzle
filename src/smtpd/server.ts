import type { Socket, TCPSocketListener } from "bun";
import { toBinary } from "../mime/parse.ts";

export interface SmtpReply {
  code: number;
  text: string;
}

export interface SmtpSession {
  remote: string;
  tls: boolean;
  user: unknown;
  utf8: boolean;
  requiretls: boolean;
  helo: string | null;
}

export interface SmtpHooks {
  auth?(password: string, session: SmtpSession): Promise<unknown | null>;
  sender?(address: string, session: SmtpSession): Promise<SmtpReply | null>;
  recipient(address: string, session: SmtpSession): Promise<SmtpReply | null>;
  message(
    recipients: string[],
    raw: string,
    session: SmtpSession,
    from: string,
  ): Promise<SmtpReply>;
}

export interface SmtpServerOptions {
  hostname: string;
  port: number;
  name: string;
  banner: string;
  hooks: SmtpHooks;
  tls?: { cert: string; key: string } | null;
  implicitTls?: boolean;
  requireTls?: boolean;
  requireAuth?: boolean;
  maxSize?: number;
  maxRecipients?: number;
  maxMessages?: number;
  maxConnectionsPerIp?: number;
  idleMs?: number;
  authFailures?: { max: number; windowMs: number };
  blocking?: { maxStrikes: number; windowMs: number; banMs: number } | null;
  utf8?: boolean;
  requiretls?: boolean;
}

interface Conn {
  buffer: string;
  data: string[] | null;
  size: number;
  tooBig: boolean;
  from: string | null;
  rcpts: string[];
  chain: Promise<void>;
  idle: ReturnType<typeof setTimeout> | null;
  upgrading: boolean;
  session: SmtpSession;
  messages: number;
  authStep: { mech: "PLAIN" | "LOGIN"; stage: "initial" | "user" | "password" } | null;
}

const MAX_LINE = 4096;

export const DEFAULT_BLOCKING = { maxStrikes: 20, windowMs: 10 * 60_000, banMs: 15 * 60_000 };
const say = (r: SmtpReply) => `${r.code} ${r.text}`;

export function startSmtpServer(o: SmtpServerOptions): { port: number; stop(): void } {
  const maxSize = o.maxSize ?? 1024 * 1024;
  const maxRcpts = o.maxRecipients ?? 10;
  const maxMessages = o.maxMessages ?? 100;
  const idleMs = o.idleMs ?? 60_000;
  const perIp = o.maxConnectionsPerIp ?? 20;
  const conns = new Map<Socket<undefined>, Conn>();
  const open = new Map<string, number>();
  const failures = new Map<string, number[]>();
  const strikes = new Map<string, number[]>();
  const banned = new Map<string, number>();
  const isBanned = (ip: string) => {
    const until = banned.get(ip);
    if (until === undefined) return false;
    if (until > Date.now()) return true;
    banned.delete(ip);
    return false;
  };
  const strike = (s: Socket<undefined>, ip: string): boolean => {
    const b = o.blocking;
    if (!b) return false;
    const now = Date.now();
    const list = (strikes.get(ip) ?? []).filter((t) => now - t < b.windowMs);
    list.push(now);
    if (strikes.size > 10_000 && !strikes.has(ip))
      strikes.delete(strikes.keys().next().value as string);
    strikes.set(ip, list);
    if (list.length < b.maxStrikes) return false;
    strikes.delete(ip);
    if (banned.size > 10_000) banned.delete(banned.keys().next().value as string);
    banned.set(ip, now + b.banMs);
    s.write("421 4.7.0 Too many errors from your address, try again later\r\n");
    s.end();
    return true;
  };

  const reply = (s: Socket<undefined>, text: string): void => {
    s.write(`${text}\r\n`);
  };
  const reset = (c: Conn) => {
    c.from = null;
    c.rcpts = [];
    c.data = null;
    c.size = 0;
    c.tooBig = false;
  };
  const touch = (s: Socket<undefined>, c: Conn) => {
    if (c.idle) clearTimeout(c.idle);
    c.idle = setTimeout(() => {
      if (strike(s, c.session.remote)) return;
      reply(s, "421 4.4.2 Idle too long, closing");
      s.end();
    }, idleMs);
  };
  const recentFailures = (ip: string) => {
    const limit = o.authFailures;
    if (!limit) return 0;
    const now = Date.now();
    const list = (failures.get(ip) ?? []).filter((t) => now - t < limit.windowMs);
    if (list.length) failures.set(ip, list);
    else failures.delete(ip);
    return list.length;
  };
  const blocked = (ip: string) => !!o.authFailures && recentFailures(ip) >= o.authFailures.max;

  const ehlo = (s: Socket<undefined>, c: Conn) => {
    reset(c);
    const lines = [o.name, "PIPELINING", `SIZE ${maxSize}`, "ENHANCEDSTATUSCODES", "8BITMIME"];
    if (o.utf8) lines.push("SMTPUTF8");
    if (o.tls && !c.session.tls) lines.push("STARTTLS");
    if (o.hooks.auth && c.session.tls) lines.push("AUTH PLAIN LOGIN");
    if (o.requiretls && c.session.tls) lines.push("REQUIRETLS");
    s.write(lines.map((l, i) => `250${i === lines.length - 1 ? " " : "-"}${l}\r\n`).join(""));
  };

  const finishAuth = async (s: Socket<undefined>, c: Conn, password: string | null) => {
    c.authStep = null;
    if (password === null) return reply(s, "501 5.5.2 Cannot decode the response");
    const ip = c.session.remote;
    if (blocked(ip)) return reply(s, "421 4.7.0 Too many failed logins, try again later");
    let user: unknown = null;
    try {
      user = (await o.hooks.auth?.(password, c.session)) ?? null;
    } catch {
      return reply(s, "454 4.7.0 Temporary authentication failure");
    }
    if (user === null) {
      const n = recentFailures(ip) + 1;
      failures.set(ip, [...(failures.get(ip) ?? []), Date.now()]);
      await Bun.sleep(Math.min(5_000, 250 * n));
      return reply(s, "535 5.7.8 Authentication credentials invalid");
    }
    failures.delete(ip);
    c.session.user = user;
    reply(s, "235 2.7.0 Authentication successful");
  };

  const decode = (b64: string): string | null => {
    try {
      return new TextDecoder("utf-8", { fatal: true }).decode(Uint8Array.fromBase64(b64.trim()));
    } catch {
      return null;
    }
  };

  const authLine = async (s: Socket<undefined>, c: Conn, text: string) => {
    const step = c.authStep;
    if (!step) return;
    if (text === "*") {
      c.authStep = null;
      return reply(s, "501 5.7.0 Authentication canceled");
    }
    if (step.mech === "PLAIN") {
      const plain = decode(text);
      return finishAuth(s, c, plain?.split("\u0000")[2] ?? null);
    }
    if (step.stage === "user") {
      c.authStep = { mech: "LOGIN", stage: "password" };
      return reply(s, "334 UGFzc3dvcmQ6");
    }
    return finishAuth(s, c, decode(text));
  };

  const command = async (s: Socket<undefined>, c: Conn, line: string) => {
    const upper = line.toUpperCase();
    const tlsMissing = o.requireTls && !c.session.tls;
    if (upper.startsWith("EHLO")) {
      c.session.helo = line.slice(4).trim() || null;
      ehlo(s, c);
    } else if (upper === "STARTTLS" || upper.startsWith("STARTTLS ")) {
      if (!o.tls) return reply(s, "502 5.5.1 STARTTLS not available");
      if (c.session.tls) return reply(s, "503 5.5.1 TLS already active");
      if (upper !== "STARTTLS") return reply(s, "501 5.5.4 No parameters allowed");
      upgrade(s, c, o.tls);
    } else if (upper.startsWith("HELO")) {
      c.session.helo = line.slice(4).trim() || null;
      reply(s, `250 ${o.name}`);
    } else if (upper.startsWith("AUTH")) {
      if (!o.hooks.auth) return reply(s, "502 5.5.1 AUTH not available");
      if (!c.session.tls) return reply(s, "530 5.7.0 Must issue a STARTTLS command first");
      if (c.session.user !== null) return reply(s, "503 5.5.1 Already authenticated");
      if (c.from !== null) return reply(s, "503 5.5.1 AUTH not allowed during a mail transaction");
      const [, mech = "", initial] = line.split(/\s+/);
      if (mech.toUpperCase() === "PLAIN") {
        if (initial !== undefined && initial !== "=") {
          return finishAuth(s, c, decode(initial)?.split("\u0000")[2] ?? null);
        }
        c.authStep = { mech: "PLAIN", stage: "initial" };
        return reply(s, "334 ");
      }
      if (mech.toUpperCase() === "LOGIN") {
        c.authStep = { mech: "LOGIN", stage: "user" };
        return reply(s, "334 VXNlcm5hbWU6");
      }
      reply(s, "504 5.5.4 Unrecognized authentication type");
    } else if (upper.startsWith("MAIL FROM:")) {
      if (tlsMissing) return reply(s, "530 5.7.0 Must issue a STARTTLS command first");
      if (o.requireAuth && c.session.user === null) {
        return reply(s, "530 5.7.0 Authentication required");
      }
      if (c.messages >= maxMessages) {
        reply(s, "421 4.7.0 Too many messages on one connection, reconnect");
        return void s.end();
      }
      reset(c);
      const from = /<([^>]*)>/.exec(line)?.[1] ?? "";
      const size = /\sSIZE=(\d+)/i.exec(line)?.[1];
      if (size !== undefined && Number(size) > maxSize) {
        return reply(s, `552 5.3.4 Message larger than ${maxSize} bytes`);
      }
      const requiretls = /\sREQUIRETLS(?:\s|$)/i.test(line);
      if (requiretls && !o.requiretls) return reply(s, "555 5.5.4 REQUIRETLS not supported");
      if (requiretls && !c.session.tls) {
        return reply(s, "530 5.7.10 REQUIRETLS needs a TLS connection");
      }
      c.session.utf8 = /\sSMTPUTF8\b/i.test(line);
      c.session.requiretls = requiretls;
      const refused = o.hooks.sender ? await o.hooks.sender(from, c.session) : null;
      if (refused) return reply(s, say(refused));
      c.from = from;
      reply(s, "250 2.1.0 Ok");
    } else if (upper.startsWith("RCPT TO:")) {
      if (c.from === null) return reply(s, "503 5.5.1 MAIL first");
      if (c.rcpts.length >= maxRcpts) return reply(s, "452 4.5.3 Too many recipients");
      const address = /<([^>]*)>/.exec(line)?.[1]?.trim() ?? "";
      if (address.length === 0 || address.length > 320) {
        return reply(s, "501 5.1.3 Bad recipient address");
      }
      let refused: SmtpReply | null;
      try {
        refused = await o.hooks.recipient(address, c.session);
      } catch {
        return reply(s, "451 4.3.0 Try again later");
      }
      if (refused) {
        if (refused.code >= 500 && strike(s, c.session.remote)) return;
        return reply(s, say(refused));
      }
      c.rcpts.push(address);
      reply(s, "250 2.1.5 Ok");
    } else if (upper === "DATA") {
      if (c.rcpts.length === 0) return reply(s, "503 5.5.1 No valid recipients");
      c.data = [];
      reply(s, "354 End data with <CR><LF>.<CR><LF>");
    } else if (upper === "RSET") {
      reset(c);
      reply(s, "250 2.0.0 Ok");
    } else if (upper === "NOOP") {
      reply(s, "250 2.0.0 Ok");
    } else if (upper.startsWith("VRFY")) {
      reply(s, "252 2.5.0 Cannot verify");
    } else if (upper === "QUIT") {
      reply(s, "221 2.0.0 Bye");
      s.end();
    } else {
      if (strike(s, c.session.remote)) return;
      reply(s, "502 5.5.2 Command not recognized");
    }
  };

  const upgrade = (s: Socket<undefined>, c: Conn, tls: { cert: string; key: string }) => {
    reply(s, "220 2.0.0 Ready to start TLS");
    reset(c);
    c.buffer = "";
    conns.delete(s);
    try {
      const [, secure] = s.upgradeTLS({ tls, socket: secureHandlers });
      c.session.tls = true;
      c.upgrading = false;
      conns.set(secure, c);
      touch(secure, c);
    } catch {
      if (c.idle) clearTimeout(c.idle);
      s.end();
    }
  };

  const endOfData = async (s: Socket<undefined>, c: Conn) => {
    const lines = c.data ?? [];
    const rcpts = c.rcpts;
    const from = c.from ?? "";
    const tooBig = c.tooBig;
    reset(c);
    if (tooBig) return reply(s, `552 5.3.4 Message larger than ${maxSize} bytes`);
    c.messages++;
    let result: SmtpReply;
    try {
      result = await o.hooks.message(rcpts, `${lines.join("\r\n")}\r\n`, c.session, from);
    } catch {
      result = { code: 451, text: "4.3.0 Try again later" };
    }
    reply(s, say(result));
  };

  const line = (s: Socket<undefined>, c: Conn, text: string) => {
    if (c.data !== null) {
      if (text === ".") {
        c.chain = c.chain.then(() => endOfData(s, c));
        return;
      }
      const content = text.startsWith(".") ? text.slice(1) : text;
      c.size += content.length + 2;
      if (c.size > maxSize) c.tooBig = true;
      else c.data.push(content);
      return;
    }
    if (c.authStep) {
      c.chain = c.chain.then(() => authLine(s, c, text));
      return;
    }
    if (text.toUpperCase() === "STARTTLS" && o.tls && !c.session.tls) c.upgrading = true;
    c.chain = c.chain.then(() => command(s, c, text));
  };

  const release = (s: Socket<undefined>, c: Conn | undefined) => {
    if (c?.idle) clearTimeout(c.idle);
    if (conns.delete(s) && c) {
      const ip = c.session.remote;
      const n = (open.get(ip) ?? 1) - 1;
      if (n <= 0) open.delete(ip);
      else open.set(ip, n);
    }
  };

  const handlers = {
    open(s: Socket<undefined>) {
      const ip = s.remoteAddress ?? "";
      const c: Conn = {
        buffer: "",
        data: null,
        size: 0,
        tooBig: false,
        from: null,
        rcpts: [],
        chain: Promise.resolve(),
        idle: null,
        upgrading: false,
        session: {
          remote: ip,
          tls: !!o.implicitTls,
          user: null,
          utf8: false,
          requiretls: false,
          helo: null,
        },
        messages: 0,
        authStep: null,
      };
      if ((open.get(ip) ?? 0) >= perIp) {
        reply(s, "421 4.7.0 Too many connections from your address");
        s.end();
        return;
      }
      if (isBanned(ip)) {
        reply(s, "421 4.7.0 Too many errors from your address, try again later");
        s.end();
        return;
      }
      if (blocked(ip)) {
        reply(s, "421 4.7.0 Too many failed logins, try again later");
        s.end();
        return;
      }
      open.set(ip, (open.get(ip) ?? 0) + 1);
      conns.set(s, c);
      touch(s, c);
      reply(s, `220 ${o.name} ${o.banner}`);
    },
    data(s: Socket<undefined>, chunk: Uint8Array) {
      const c = conns.get(s);
      if (!c || c.upgrading) return;
      touch(s, c);
      c.buffer += toBinary(chunk);
      let i = c.buffer.indexOf("\r\n");
      while (i >= 0) {
        const text = c.buffer.slice(0, i);
        c.buffer = c.buffer.slice(i + 2);
        line(s, c, text);
        if (c.upgrading) {
          c.buffer = "";
          return;
        }
        i = c.buffer.indexOf("\r\n");
      }
      if (c.data === null && c.buffer.length > MAX_LINE) {
        c.buffer = "";
        if (strike(s, c.session.remote)) return;
        reply(s, "500 5.5.6 Line too long");
      } else if (c.data !== null && c.buffer.length > maxSize) {
        c.tooBig = true;
        c.buffer = "";
      }
    },
    close(s: Socket<undefined>) {
      release(s, conns.get(s));
    },
    error(s: Socket<undefined>) {
      release(s, conns.get(s));
    },
  };
  const { open: _open, ...secureHandlers } = handlers;

  const listener: TCPSocketListener<undefined> = Bun.listen({
    hostname: o.hostname,
    port: o.port,
    socket: handlers,
    ...(o.implicitTls && o.tls ? { tls: o.tls } : {}),
  });
  return {
    port: listener.port,
    stop: () => {
      for (const c of conns.values()) if (c.idle) clearTimeout(c.idle);
      listener.stop(true);
    },
  };
}
