import {
  applyChanges,
  BODY_CHUNK,
  body,
  type Change,
  connect,
  data,
  encode,
  eob,
  eoh,
  type Frame,
  FrameReader,
  header,
  headerPairs,
  helo,
  MilterError,
  macros,
  mail,
  type Negotiated,
  NO_BODY,
  NO_CONNECT,
  NO_DATA,
  NO_EOH,
  NO_HDRS,
  NO_HELO,
  NO_MAIL,
  NO_RCPT,
  NR_BODY,
  NR_CONN,
  NR_DATA,
  NR_EOH,
  NR_HDR,
  NR_HELO,
  NR_MAIL,
  NR_RCPT,
  optneg,
  quit,
  rcpt,
  readChange,
  readOptneg,
  readVerdict,
  splitMessage,
} from "./protocol.ts";

export interface Conduit {
  write(bytes: Uint8Array): void;
  read(): Promise<Frame>;
  close(): void;
}

export interface MilterMessage {
  id: string;
  hostname: string;
  user: string;
  from: string;
  recipients: string[];
  data: string;
}

export type MilterResult =
  | { action: "accept"; data: string }
  | { action: "reject" | "tempfail"; text: string | null };

export type MilterAddress = { hostname: string; port: number } | { unix: string };

export function parseMilterAddress(input: string): MilterAddress | null {
  if (input.startsWith("unix:")) {
    const path = input.slice(5);
    return path.startsWith("/") ? { unix: path } : null;
  }
  const m = /^inet6?:(?:\[([0-9a-fA-F:.]+)\]|([^:[\]]+)):(\d{1,5})$/.exec(input);
  const port = Number(m?.[3]);
  if (!m || port < 1 || port > 65_535) return null;
  return { hostname: (m[1] ?? m[2]) as string, port };
}

export async function converse(c: Conduit, m: MilterMessage): Promise<MilterResult> {
  c.write(optneg());
  const neg: Negotiated = readOptneg(await c.read());
  const has = (bit: number) => (neg.steps & bit) !== 0;

  const verdict = async (skippable = false) => {
    for (;;) {
      const v = readVerdict(await c.read());
      if (v.action === "progress") continue;
      if (v.action === "skip" && !skippable) throw new MilterError("skip outside the body");
      return v;
    }
  };

  const step = async (bit: number, noReply: number, bytes: () => Uint8Array) => {
    if (has(bit)) return null;
    c.write(bytes());
    if (has(noReply)) return null;
    const v = await verdict();
    return v.action === "continue" ? null : v;
  };

  const end = (v: Awaited<ReturnType<typeof verdict>>): MilterResult => {
    if (v.action === "reject" || v.action === "tempfail") {
      return { action: v.action, text: v.text };
    }
    if (v.action === "discard") return { action: "reject", text: null };
    return { action: "accept", data: m.data };
  };

  const { fields, rest } = splitMessage(m.data);
  c.write(
    macros("C", [
      ["j", m.hostname],
      ["{daemon_name}", "bunzzle"],
    ]),
  );
  let v = await step(NO_CONNECT, NR_CONN, () => connect("localhost", "127.0.0.1"));
  if (v) return end(v);
  v = await step(NO_HELO, NR_HELO, () => helo("localhost"));
  if (v) return end(v);
  c.write(
    macros("M", [
      ["i", m.id],
      ["{auth_type}", "bunzzle"],
      ["{auth_authen}", m.user],
      ["{mail_addr}", m.from],
    ]),
  );
  v = await step(NO_MAIL, NR_MAIL, () => mail(m.from));
  if (v) return end(v);
  for (const to of m.recipients) {
    c.write(macros("R", [["{rcpt_addr}", to]]));
    v = await step(NO_RCPT, NR_RCPT, () => rcpt(to));
    if (v) return end(v);
  }
  v = await step(NO_DATA, NR_DATA, () => data());
  if (v) return end(v);
  if (!has(NO_HDRS)) {
    for (const [name, value] of headerPairs(fields)) {
      v = await step(0, NR_HDR, () => header(name, value));
      if (v) return end(v);
    }
  }
  v = await step(NO_EOH, NR_EOH, () => eoh());
  if (v) return end(v);
  if (!has(NO_BODY)) {
    const bytes = encode(rest.startsWith("\r\n") ? rest.slice(2) : rest);
    for (let at = 0; at < bytes.length; at += BODY_CHUNK) {
      c.write(body(bytes.subarray(at, at + BODY_CHUNK)));
      if (has(NR_BODY)) continue;
      const r = await verdict(true);
      if (r.action === "skip") break;
      if (r.action !== "continue") return end(r);
    }
  }
  c.write(eob());
  const changes: Change[] = [];
  for (;;) {
    const f = await c.read();
    const change = readChange(f, neg.actions);
    if (change) {
      changes.push(change);
      continue;
    }
    const r = readVerdict(f);
    if (r.action === "progress") continue;
    if (r.action === "skip") throw new MilterError("skip after the body");
    c.write(quit());
    if (r.action === "accept" || r.action === "continue") {
      return { action: "accept", data: applyChanges(m.data, changes) };
    }
    return end(r);
  }
}

export async function connectMilter(address: MilterAddress, deadline: number): Promise<Conduit> {
  const reader = new FrameReader();
  const frames: Frame[] = [];
  let out = new Uint8Array(0);
  let waiting: { resolve: (f: Frame) => void; reject: (e: Error) => void } | null = null;
  let failure: Error | null = null;
  const fail = (err: Error) => {
    failure ??= err;
    waiting?.reject(failure);
    waiting = null;
  };
  const wake = () => {
    if (!waiting) return;
    const f = frames.shift();
    if (!f) return;
    waiting.resolve(f);
    waiting = null;
  };
  let expire: (err: Error) => void = () => {};
  const expired = new Promise<never>((_, reject) => {
    expire = reject;
  });
  expired.catch(() => {});
  const timer = setTimeout(
    () => {
      const err = new MilterError("the milter timed out");
      fail(err);
      expire(err);
    },
    Math.max(0, deadline - Date.now()),
  );
  const connecting = Bun.connect({
    ...address,
    socket: {
      data(_s, chunk) {
        try {
          reader.push(chunk);
          for (let f = reader.next(); f; f = reader.next()) frames.push(f);
        } catch (err) {
          fail(err as Error);
          return;
        }
        wake();
      },
      drain(s) {
        if (out.length > 0) out = out.subarray(Math.max(0, s.write(out)));
      },
      error(_s, err) {
        fail(new MilterError((err as Error | undefined)?.message ?? "socket error"));
      },
      close() {
        fail(new MilterError("the milter closed the connection"));
      },
    },
  } as Parameters<typeof Bun.connect>[0]);
  const socket = await Promise.race([connecting, expired]).catch((err: Error) => {
    clearTimeout(timer);
    void connecting.then((s) => s.end()).catch(() => {});
    throw err instanceof MilterError ? err : new MilterError(err.message);
  });
  return {
    write: (bytes) => {
      if (failure) return;
      if (out.length > 0) {
        const next = new Uint8Array(out.length + bytes.length);
        next.set(out);
        next.set(bytes, out.length);
        out = next;
        return;
      }
      const n = socket.write(bytes);
      if (n < bytes.length) out = bytes.slice(Math.max(0, n));
    },
    read: () => {
      const f = frames.shift();
      if (f) return Promise.resolve(f);
      if (failure) return Promise.reject(failure);
      return new Promise((resolve, reject) => {
        waiting = { resolve, reject };
      });
    },
    close: () => {
      clearTimeout(timer);
      socket.end();
    },
  };
}

export async function runMilter(
  address: MilterAddress,
  timeoutMs: number,
  m: MilterMessage,
): Promise<MilterResult> {
  const c = await connectMilter(address, Date.now() + timeoutMs);
  try {
    return await converse(c, m);
  } finally {
    c.close();
  }
}
