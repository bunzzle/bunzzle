import type { Socket, TCPSocketListener } from "bun";

export interface InboundHandlers {
  recipient(address: string): Promise<boolean>;
  message(recipients: string[], raw: string): Promise<"ok" | "retry" | "reject">;
}

export interface InboundOptions {
  hostname: string;
  port: number;
  name: string;
  handlers: InboundHandlers;
  maxSize?: number;
  maxRecipients?: number;
  idleMs?: number;
  tls?: { cert: string; key: string } | null;
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
  tls: boolean;
  upgrading: boolean;
}

const MAX_LINE = 4096;
const dec = new TextDecoder("latin1");

export function startInboundServer(o: InboundOptions): { port: number; stop(): void } {
  const maxSize = o.maxSize ?? 1024 * 1024;
  const maxRcpts = o.maxRecipients ?? 10;
  const idleMs = o.idleMs ?? 60_000;
  const conns = new Map<Socket<undefined>, Conn>();

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
      reply(s, "421 4.4.2 Idle too long, closing");
      s.end();
    }, idleMs);
  };

  const command = async (s: Socket<undefined>, c: Conn, line: string) => {
    const upper = line.toUpperCase();
    if (upper.startsWith("EHLO")) {
      reset(c);
      const starttls = o.tls && !c.tls ? "250-STARTTLS\r\n" : "";
      s.write(
        `250-${o.name}\r\n250-PIPELINING\r\n250-SIZE ${maxSize}\r\n${starttls}250 8BITMIME\r\n`,
      );
    } else if (upper === "STARTTLS" || upper.startsWith("STARTTLS ")) {
      if (!o.tls) return reply(s, "502 5.5.1 STARTTLS not available");
      if (c.tls) return reply(s, "503 5.5.1 TLS already active");
      if (upper !== "STARTTLS") return reply(s, "501 5.5.4 No parameters allowed");
      upgrade(s, c, o.tls);
    } else if (upper.startsWith("HELO")) {
      reply(s, `250 ${o.name}`);
    } else if (upper.startsWith("MAIL FROM:")) {
      reset(c);
      c.from = /<([^>]*)>/.exec(line)?.[1] ?? "";
      reply(s, "250 2.1.0 Ok");
    } else if (upper.startsWith("RCPT TO:")) {
      if (c.from === null) return reply(s, "503 5.5.1 MAIL first");
      if (c.rcpts.length >= maxRcpts) return reply(s, "452 4.5.3 Too many recipients");
      const address = /<([^>]*)>/.exec(line)?.[1]?.trim() ?? "";
      let ok: boolean;
      try {
        ok = address.length > 0 && address.length <= 320 && (await o.handlers.recipient(address));
      } catch {
        return reply(s, "451 4.3.0 Try again later");
      }
      if (!ok) return reply(s, "550 5.1.1 No such recipient here");
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
      c.tls = true;
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
    const tooBig = c.tooBig;
    reset(c);
    if (tooBig) return reply(s, `552 5.3.4 Message larger than ${maxSize} bytes`);
    let result: "ok" | "retry" | "reject";
    try {
      result = await o.handlers.message(rcpts, `${lines.join("\r\n")}\r\n`);
    } catch {
      result = "retry";
    }
    if (result === "ok") reply(s, "250 2.0.0 Ok: received");
    else if (result === "reject") reply(s, "550 5.6.0 Message not accepted");
    else reply(s, "451 4.3.0 Try again later");
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
    if (text.toUpperCase() === "STARTTLS" && o.tls && !c.tls) c.upgrading = true;
    c.chain = c.chain.then(() => command(s, c, text));
  };

  const handlers = {
    open(s: Socket<undefined>) {
      const c: Conn = {
        buffer: "",
        data: null,
        size: 0,
        tooBig: false,
        from: null,
        rcpts: [],
        chain: Promise.resolve(),
        idle: null,
        tls: false,
        upgrading: false,
      };
      conns.set(s, c);
      touch(s, c);
      reply(s, `220 ${o.name} ESMTP Bunzzle (bounces and feedback only)`);
    },
    data(s: Socket<undefined>, chunk: Uint8Array) {
      const c = conns.get(s);
      if (!c || c.upgrading) return;
      touch(s, c);
      c.buffer += dec.decode(chunk);
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
        reply(s, "500 5.5.6 Line too long");
      } else if (c.data !== null && c.buffer.length > maxSize) {
        c.tooBig = true;
        c.buffer = "";
      }
    },
    close(s: Socket<undefined>) {
      const c = conns.get(s);
      if (c?.idle) clearTimeout(c.idle);
      conns.delete(s);
    },
    error(s: Socket<undefined>) {
      const c = conns.get(s);
      if (c?.idle) clearTimeout(c.idle);
      conns.delete(s);
    },
  };
  const { open: _open, ...secureHandlers } = handlers;

  const listener: TCPSocketListener<undefined> = Bun.listen({
    hostname: o.hostname,
    port: o.port,
    socket: handlers,
  });
  return {
    port: listener.port,
    stop: () => {
      for (const c of conns.values()) if (c.idle) clearTimeout(c.idle);
      listener.stop(true);
    },
  };
}
