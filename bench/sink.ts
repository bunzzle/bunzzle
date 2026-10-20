import type { Socket } from "bun";

const TLS_DIR = `${import.meta.dir}/../test/fixtures/tls`;
const KEY = await Bun.file(`${TLS_DIR}/mx.key`).text();
const CERT = await Bun.file(`${TLS_DIR}/mx.pem`).text();

export type Behavior = "normal" | "slow" | "greylist" | "defer" | "drop";

export const behaviorOf = (domainIndex: number): Behavior => {
  const n = domainIndex % 20;
  if (n < 14) return "normal";
  if (n < 16) return "slow";
  if (n < 18) return "greylist";
  return n === 18 ? "defer" : "drop";
};

export interface SinkStats {
  messages: number;
  unique: number;
  duplicates: number;
  sessions: number;
  tlsSessions: number;
  active: number;
  peak: number;
  greylisted: number;
  deferred: number;
  dropped: number;
}

export interface Sink {
  port: number;
  received(): number;
  tlsSessions(): number;
  stats(): SinkStats;
  seen(n: number): boolean;
  probeAt(n: number): number | undefined;
  stop(): void;
}

interface State {
  active: Socket<undefined>;
  buffer: string;
  inData: boolean;
  from: string;
  behavior: Behavior;
  rcpts: number;
  tls: boolean;
}

const EXTENSIONS = ["PIPELINING", "SIZE 10485760", "8BITMIME", "ENHANCEDSTATUSCODES", "SMTPUTF8"];
const multiline = (lines: string[]) =>
  lines.map((l, i) => `250${i === lines.length - 1 ? " " : "-"}${l}\r\n`).join("");

export function startSink(total: number, o: { slowMs?: number; random?: () => number } = {}): Sink {
  const random = o.random ?? Math.random;
  const slowMs = o.slowMs ?? 3_000;
  const counts = new Uint8Array(total);
  const probes = new Map<number, number>();
  const greylist = new Set<string>();
  const states = new Map<Socket<undefined>, State>();
  const s: SinkStats = {
    messages: 0,
    unique: 0,
    duplicates: 0,
    sessions: 0,
    tlsSessions: 0,
    active: 0,
    peak: 0,
    greylisted: 0,
    deferred: 0,
    dropped: 0,
  };

  const accept = (body: string) => {
    s.messages++;
    const head = body.slice(0, body.indexOf("\r\n\r\n"));
    const probe = /^Subject: Probe #(\d+)/m.exec(head);
    if (probe) {
      const n = Number(probe[1]);
      if (!probes.has(n)) probes.set(n, performance.now());
      return;
    }
    const m = /^Subject: [^\r\n]*#(\d+)/m.exec(head);
    const n = m ? Number(m[1]) : -1;
    if (n < 0 || n >= total) return;
    if (counts[n] === 0) s.unique++;
    else s.duplicates++;
    counts[n] = Math.min(255, (counts[n] ?? 0) + 1);
  };

  const handle = (state: State, line: string) => {
    const sock = state.active;
    const cmd = line.slice(0, 10).toUpperCase();
    if (cmd.startsWith("EHLO")) {
      sock.write(multiline(["mx.sink.test", ...EXTENSIONS, ...(state.tls ? [] : ["STARTTLS"])]));
    } else if (cmd.startsWith("STARTTLS")) {
      sock.write("220 2.0.0 Ready to start TLS\r\n");
      const [, tls] = sock.upgradeTLS({ tls: { key: KEY, cert: CERT }, socket: tlsHandlers });
      states.delete(sock);
      state.active = tls;
      state.buffer = "";
      state.tls = true;
      states.set(tls, state);
      s.tlsSessions++;
    } else if (cmd.startsWith("MAIL FROM:")) {
      state.from = line.slice(10);
      state.rcpts = 0;
      sock.write("250 2.1.0 Ok\r\n");
    } else if (cmd.startsWith("RCPT TO:")) {
      const domain = /@d(\d+)\.example>/.exec(line);
      state.behavior = domain ? behaviorOf(Number(domain[1])) : "normal";
      if (state.behavior === "defer" && random() < 0.3) {
        s.deferred++;
        sock.write("421 4.7.0 Try again later, closing connection\r\n");
        sock.end();
        return;
      }
      if (state.behavior === "greylist" && !greylist.has(state.from)) {
        greylist.add(state.from);
        s.greylisted++;
        sock.write("451 4.7.1 Greylisted, please try again in 60 seconds\r\n");
        return;
      }
      state.rcpts++;
      sock.write("250 2.1.5 Ok\r\n");
    } else if (cmd.startsWith("DATA")) {
      if (state.rcpts === 0) {
        sock.write("554 5.5.1 No valid recipients\r\n");
        return;
      }
      state.inData = true;
      sock.write("354 End data with <CR><LF>.<CR><LF>\r\n");
    } else if (cmd.startsWith("QUIT")) {
      sock.write("221 2.0.0 Bye\r\n");
      sock.end();
    } else if (cmd.startsWith("RSET") || cmd.startsWith("NOOP")) {
      sock.write("250 2.0.0 Ok\r\n");
    } else {
      sock.write("502 5.5.2 Command not recognized\r\n");
    }
  };

  const finish = (state: State, body: string) => {
    const sock = state.active;
    if (state.behavior === "drop" && random() < 0.05) {
      s.dropped++;
      sock.terminate();
      return false;
    }
    accept(body);
    const reply = "250 2.0.0 Ok: queued\r\n";
    if (state.behavior === "slow") setTimeout(() => sock.write(reply), slowMs);
    else sock.write(reply);
    return true;
  };

  const pump = (state: State) => {
    for (;;) {
      if (state.inData) {
        const end = state.buffer.indexOf("\r\n.\r\n");
        if (end < 0) return;
        const body = state.buffer.slice(0, end + 2);
        state.buffer = state.buffer.slice(end + 5);
        state.inData = false;
        if (!finish(state, body)) return;
        continue;
      }
      const i = state.buffer.indexOf("\r\n");
      if (i < 0) return;
      const line = state.buffer.slice(0, i);
      state.buffer = state.buffer.slice(i + 2);
      handle(state, line);
    }
  };

  const decoder = new TextDecoder();
  const handlers = {
    open(sock: Socket<undefined>) {
      if (states.has(sock)) return;
      s.sessions++;
      s.active++;
      s.peak = Math.max(s.peak, s.active);
      states.set(sock, {
        active: sock,
        buffer: "",
        inData: false,
        from: "",
        behavior: "normal",
        rcpts: 0,
        tls: false,
      });
      sock.write("220 mx.sink.test ESMTP\r\n");
    },
    data(sock: Socket<undefined>, chunk: Uint8Array) {
      const state = states.get(sock);
      if (!state || state.active !== sock) return;
      state.buffer += decoder.decode(chunk);
      pump(state);
    },
    close(sock: Socket<undefined>) {
      if (states.has(sock)) s.active--;
      states.delete(sock);
    },
  };
  const { open: _open, ...tlsHandlers } = handlers;
  const server = Bun.listen({ hostname: "127.0.0.1", port: 0, socket: handlers });

  return {
    port: server.port,
    received: () => s.messages,
    tlsSessions: () => s.tlsSessions,
    stats: () => ({ ...s }),
    seen: (n) => (counts[n] ?? 0) > 0,
    probeAt: (n) => probes.get(n),
    stop: () => server.stop(true),
  };
}
