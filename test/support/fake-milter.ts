import { type Frame, FrameReader, frame } from "../../src/milter/protocol.ts";

export interface FakeMilterSession {
  frames: Frame[];
}

export interface FakeMilter {
  port: number;
  sessions: FakeMilterSession[];
  actions: number;
  steps: number;
  onEnd: () => Uint8Array[];
  stop(): void;
}

const NO_REPLY: Record<string, number> = {
  C: 0x1000,
  H: 0x2000,
  M: 0x4000,
  R: 0x8000,
  T: 0x10000,
  L: 0x80,
  N: 0x40000,
  B: 0x80000,
};

const u32 = (n: number) => {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n);
  return b;
};

export function startFakeMilter(): FakeMilter {
  const fake: FakeMilter = {
    port: 0,
    sessions: [],
    actions: 0x01 | 0x02 | 0x10,
    steps: 0,
    onEnd: () => [frame("c")],
    stop: () => server.stop(true),
  };
  const server = Bun.listen<{ reader: FrameReader; session: FakeMilterSession }>({
    hostname: "127.0.0.1",
    port: 0,
    socket: {
      open(s) {
        const session = { frames: [] };
        fake.sessions.push(session);
        s.data = { reader: new FrameReader(), session };
      },
      data(s, chunk) {
        s.data.reader.push(chunk);
        for (let f = s.data.reader.next(); f; f = s.data.reader.next()) {
          s.data.session.frames.push(f);
          if (f.code === "O") s.write(frame("O", u32(6), u32(fake.actions), u32(fake.steps)));
          else if (f.code === "E") for (const r of fake.onEnd()) s.write(r);
          else if (f.code === "Q") s.end();
          else if (f.code !== "D" && !(fake.steps & (NO_REPLY[f.code] ?? 0))) s.write(frame("c"));
        }
      },
    },
  });
  fake.port = server.port;
  return fake;
}
