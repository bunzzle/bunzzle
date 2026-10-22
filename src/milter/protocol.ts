const enc = new TextEncoder();
const dec = new TextDecoder();

export const VERSION = 6;
export const ACTIONS = 0x01 | 0x02 | 0x10;
export const STEPS = 0x1fffff & ~0x800 & ~0x100000;

export const NO_CONNECT = 0x01;
export const NO_HELO = 0x02;
export const NO_MAIL = 0x04;
export const NO_RCPT = 0x08;
export const NO_BODY = 0x10;
export const NO_HDRS = 0x20;
export const NO_EOH = 0x40;
export const NR_HDR = 0x80;
export const NO_DATA = 0x200;
export const NR_CONN = 0x1000;
export const NR_HELO = 0x2000;
export const NR_MAIL = 0x4000;
export const NR_RCPT = 0x8000;
export const NR_DATA = 0x10000;
export const NR_EOH = 0x40000;
export const NR_BODY = 0x80000;

export const MAX_FRAME = 1024 * 1024;
export const BODY_CHUNK = 65_535;

export class MilterError extends Error {}

export interface Frame {
  code: string;
  data: Uint8Array;
}

const join = (parts: (Uint8Array | string)[]): Uint8Array => {
  const bytes = parts.map((p) => (typeof p === "string" ? enc.encode(p) : p));
  const out = new Uint8Array(bytes.reduce((n, b) => n + b.length, 0));
  let at = 0;
  for (const b of bytes) {
    out.set(b, at);
    at += b.length;
  }
  return out;
};

const u32 = (n: number) => {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n);
  return b;
};

const z = (s: string) => `${s.replaceAll("\0", "")}\0`;

export function frame(code: string, ...parts: (Uint8Array | string)[]): Uint8Array {
  const data = join(parts);
  return join([u32(data.length + 1), code, data]);
}

export const optneg = () => frame("O", u32(VERSION), u32(ACTIONS), u32(STEPS));

export const macros = (stage: string, pairs: [string, string][]) =>
  frame("D", stage, ...pairs.flatMap(([k, v]) => [z(k), z(v)]));

export const connect = (host: string, addr: string) =>
  frame("C", z(host), addr.includes(":") ? "6" : "4", new Uint8Array(2), z(addr));

export const helo = (name: string) => frame("H", z(name));
export const mail = (from: string) => frame("M", z(`<${from}>`));
export const rcpt = (to: string) => frame("R", z(`<${to}>`));
export const data = () => frame("T");
export const header = (name: string, value: string) => frame("L", z(name), z(value));
export const eoh = () => frame("N");
export const body = (chunk: Uint8Array) => frame("B", chunk);
export const eob = () => frame("E");
export const quit = () => frame("Q");

export class FrameReader {
  #buf: Uint8Array = new Uint8Array(0);

  push(chunk: Uint8Array): void {
    this.#buf = join([this.#buf, chunk]);
  }

  next(): Frame | null {
    if (this.#buf.length < 4) return null;
    const len = new DataView(this.#buf.buffer, this.#buf.byteOffset).getUint32(0);
    if (len < 1 || len > MAX_FRAME) throw new MilterError(`frame of ${len} bytes`);
    if (this.#buf.length < len + 4) return null;
    const f = {
      code: String.fromCharCode(this.#buf[4] as number),
      data: this.#buf.slice(5, len + 4),
    };
    this.#buf = this.#buf.slice(len + 4);
    return f;
  }
}

export interface Negotiated {
  actions: number;
  steps: number;
}

export function readOptneg(f: Frame): Negotiated {
  if (f.code !== "O" || f.data.length < 12) throw new MilterError("bad option negotiation");
  const v = new DataView(f.data.buffer, f.data.byteOffset);
  const version = v.getUint32(0);
  const actions = v.getUint32(4);
  const steps = v.getUint32(8);
  if (version < 2 || version > VERSION) throw new MilterError(`protocol version ${version}`);
  if ((actions & ~ACTIONS) !== 0) {
    throw new MilterError(`asks for actions 0x${actions.toString(16)} that are not offered`);
  }
  if ((steps & ~STEPS) !== 0) {
    throw new MilterError(`asks for protocol steps 0x${steps.toString(16)} that are not offered`);
  }
  return { actions, steps };
}

const strings = (d: Uint8Array): string[] => {
  const s = dec.decode(d);
  return (s.endsWith("\0") ? s.slice(0, -1) : s).split("\0");
};

export type Change =
  | { kind: "add"; name: string; value: string }
  | { kind: "insert"; index: number; name: string; value: string }
  | { kind: "change"; index: number; name: string; value: string }
  | { kind: "body"; chunk: Uint8Array };

export function readChange(f: Frame, allowed: number): Change | null {
  const indexed = () => {
    if (f.data.length < 4) throw new MilterError(`short ${f.code} reply`);
    const index = new DataView(f.data.buffer, f.data.byteOffset).getUint32(0);
    const [name = "", value = ""] = strings(f.data.slice(4));
    return { index, name, value };
  };
  const need = (bit: number) => {
    if ((allowed & bit) === 0) throw new MilterError(`${f.code} reply without permission`);
  };
  switch (f.code) {
    case "h": {
      need(0x01);
      const [name = "", value = ""] = strings(f.data);
      return { kind: "add", name, value };
    }
    case "i":
      need(0x01);
      return { kind: "insert", ...indexed() };
    case "m":
      need(0x10);
      return { kind: "change", ...indexed() };
    case "b":
      need(0x02);
      return { kind: "body", chunk: f.data };
    default:
      return null;
  }
}

export type Verdict =
  | { action: "accept" | "continue" | "skip" | "progress" }
  | { action: "reject" | "tempfail" | "discard"; text: string | null };

export function readVerdict(f: Frame): Verdict {
  switch (f.code) {
    case "a":
      return { action: "accept" };
    case "c":
      return { action: "continue" };
    case "s":
      return { action: "skip" };
    case "p":
      return { action: "progress" };
    case "r":
      return { action: "reject", text: null };
    case "t":
      return { action: "tempfail", text: null };
    case "d":
      return { action: "discard", text: null };
    case "y": {
      const text = strings(f.data)[0]?.trim() ?? "";
      if (!/^[45]\d\d[ -]/.test(`${text} `)) throw new MilterError("bad reply code");
      return { action: text.startsWith("4") ? "tempfail" : "reject", text };
    }
    default:
      throw new MilterError(`unexpected reply ${JSON.stringify(f.code)}`);
  }
}

const NAME = /^[!-9;-~]+$/;

const field = (name: string, value: string) => {
  if (!NAME.test(name)) throw new MilterError(`bad header name ${JSON.stringify(name)}`);
  return `${name}: ${value.replace(/\r?\n/g, "\r\n")}\r\n`;
};

export function splitMessage(message: string): { fields: string[]; rest: string } {
  const end = message.indexOf("\r\n\r\n");
  const head = end < 0 ? message : message.slice(0, end + 2);
  const rest = end < 0 ? "" : message.slice(end + 2);
  const fields: string[] = [];
  for (const line of head.split(/(?<=\r\n)/)) {
    if (line === "") continue;
    if ((line[0] === " " || line[0] === "\t") && fields.length > 0) {
      fields[fields.length - 1] += line;
    } else fields.push(line);
  }
  return { fields, rest };
}

export const fieldName = (f: string) => f.slice(0, Math.max(0, f.indexOf(":"))).trim();

export function headerPairs(fields: string[]): [string, string][] {
  return fields.map((f) => {
    const colon = f.indexOf(":");
    const value = f
      .slice(colon + 1)
      .replace(/\r\n$/, "")
      .replace(/^ /, "")
      .replace(/\r\n/g, "\n");
    return [fieldName(f), value];
  });
}

export function applyChanges(message: string, changes: Change[]): string {
  if (changes.length === 0) return message;
  const { fields, rest } = splitMessage(message);
  const chunks: Uint8Array[] = [];
  for (const c of changes) {
    if (c.kind === "add") fields.push(field(c.name, c.value));
    else if (c.kind === "insert") {
      fields.splice(Math.min(c.index, fields.length), 0, field(c.name, c.value));
    } else if (c.kind === "change") {
      const lower = c.name.toLowerCase();
      let seen = 0;
      const at = fields.findIndex(
        (f) => fieldName(f).toLowerCase() === lower && ++seen === Math.max(1, c.index),
      );
      if (at < 0) {
        if (c.value !== "") fields.push(field(c.name, c.value));
      } else if (c.value === "") fields.splice(at, 1);
      else fields[at] = field(fieldName(fields[at] as string), c.value);
    } else chunks.push(c.chunk);
  }
  const newBody = chunks.length > 0 ? dec.decode(join(chunks)).replace(/\r?\n/g, "\r\n") : null;
  return `${fields.join("")}${newBody === null ? rest : `\r\n${newBody}`}`;
}

export const encode = (s: string) => enc.encode(s);
