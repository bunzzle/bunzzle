import type { Socket, TCPSocketListener } from "bun";

const TLS_DIR = `${import.meta.dir}/../fixtures/tls`;
export const TEST_CA = await Bun.file(`${TLS_DIR}/ca.pem`).text();
const KEY = await Bun.file(`${TLS_DIR}/mx.key`).text();
const CERT = await Bun.file(`${TLS_DIR}/mx.pem`).text();

export interface MxScenario {
  greeting?: string | ((session: number) => string);
  extensions?: string[];
  ehlo?: string;
  starttls?: string;
  injectAfterStarttls?: boolean;
  mail?: string;
  rcpt?: (address: string) => string;
  data?: string;
  final?: string | "drop";
}

export interface MxSession {
  commands: string[];
  tls: boolean;
  messages: string[];
}

export interface FakeMx {
  port: number;
  sessions: MxSession[];
  stop(): void;
}

export const DEFAULT_EXTENSIONS = [
  "PIPELINING",
  "SIZE 10485760",
  "8BITMIME",
  "ENHANCEDSTATUSCODES",
  "SMTPUTF8",
  "STARTTLS",
];

interface State {
  session: MxSession;
  active: Socket<undefined>;
  buffer: string;
  inData: boolean;
  data: string;
  accepted: number;
}

function multiline(code: number, lines: string[]): string {
  return lines.map((l, i) => `${code}${i === lines.length - 1 ? " " : "-"}${l}\r\n`).join("");
}

export function startFakeMx(scenario: MxScenario = {}): FakeMx {
  const sessions: MxSession[] = [];
  const states = new Map<Socket<undefined>, State>();
  const extensions = scenario.extensions ?? DEFAULT_EXTENSIONS;

  const handle = (state: State, line: string) => {
    const s = state.active;
    const cmd = line.toUpperCase();
    state.session.commands.push(line);
    if (cmd.startsWith("EHLO")) {
      s.write(
        scenario.ehlo ??
          multiline(250, [
            "mx.example.test",
            ...(state.session.tls ? extensions.filter((e) => e !== "STARTTLS") : extensions),
          ]),
      );
    } else if (cmd.startsWith("HELO")) {
      s.write("250 mx.example.test\r\n");
    } else if (cmd === "STARTTLS") {
      const reply = scenario.starttls ?? "220 2.0.0 Ready to start TLS\r\n";
      s.write(scenario.injectAfterStarttls ? `${reply}250 injected\r\n` : reply);
      if (!reply.startsWith("220")) return;
      const [, tls] = s.upgradeTLS({
        tls: { key: KEY, cert: CERT },
        socket: tlsHandlers,
      });
      states.delete(s);
      state.active = tls;
      state.session.tls = true;
      states.set(tls, state);
    } else if (cmd.startsWith("MAIL FROM:")) {
      state.accepted = 0;
      s.write(scenario.mail ?? "250 2.1.0 Ok\r\n");
    } else if (cmd.startsWith("RCPT TO:")) {
      const address = /<([^>]*)>/.exec(line)?.[1] ?? "";
      const reply = scenario.rcpt?.(address) ?? "250 2.1.5 Ok\r\n";
      if (reply.startsWith("25")) state.accepted++;
      s.write(reply);
    } else if (cmd === "DATA") {
      if (state.accepted === 0) {
        s.write("554 5.5.1 No valid recipients\r\n");
        return;
      }
      const reply = scenario.data ?? "354 End data with <CR><LF>.<CR><LF>\r\n";
      s.write(reply);
      if (reply.startsWith("354")) {
        state.inData = true;
        state.data = "";
      }
    } else if (cmd === "QUIT") {
      s.write("221 2.0.0 Bye\r\n");
      s.end();
    } else if (cmd === "RSET" || cmd === "NOOP") {
      s.write("250 2.0.0 Ok\r\n");
    } else {
      s.write("502 5.5.2 Command not recognized\r\n");
    }
  };

  const pump = (state: State) => {
    for (;;) {
      if (state.inData) {
        const end = state.buffer.indexOf("\r\n.\r\n");
        const empty = state.data === "" && state.buffer.startsWith(".\r\n");
        if (end < 0 && !empty) return;
        const body = empty ? "" : state.buffer.slice(0, end + 2);
        state.buffer = state.buffer.slice(empty ? 3 : end + 5);
        state.inData = false;
        state.session.messages.push(body.replace(/^\.\./gm, "."));
        if (scenario.final === "drop") {
          state.active.terminate();
          return;
        }
        state.active.write(scenario.final ?? "250 2.0.0 Ok: queued as 12345\r\n");
        continue;
      }
      const i = state.buffer.indexOf("\r\n");
      if (i < 0) return;
      const line = state.buffer.slice(0, i);
      state.buffer = state.buffer.slice(i + 2);
      handle(state, line);
    }
  };

  const handlers = {
    open(s: Socket<undefined>) {
      if (states.has(s)) return;
      const session: MxSession = { commands: [], tls: false, messages: [] };
      sessions.push(session);
      states.set(s, { session, active: s, buffer: "", inData: false, data: "", accepted: 0 });
      const g = scenario.greeting;
      s.write(
        (typeof g === "function" ? g(sessions.length - 1) : g) ?? "220 mx.example.test ESMTP\r\n",
      );
    },
    data(s: Socket<undefined>, chunk: Uint8Array) {
      const state = states.get(s);
      if (!state || state.active !== s) return;
      state.buffer += new TextDecoder().decode(chunk);
      pump(state);
    },
    close(s: Socket<undefined>) {
      states.delete(s);
    },
  };

  const { open: _open, ...tlsHandlers } = handlers;

  const server: TCPSocketListener<undefined> = Bun.listen({
    hostname: "127.0.0.1",
    port: 0,
    socket: handlers,
  });

  return {
    port: server.port,
    sessions,
    stop: () => server.stop(true),
  };
}
