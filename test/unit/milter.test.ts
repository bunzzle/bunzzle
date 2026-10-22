import { afterAll, describe, expect, test } from "bun:test";
import { parseMilterAddress, runMilter } from "../../src/milter/client.ts";
import {
  applyChanges,
  FrameReader,
  frame,
  headerPairs,
  readChange,
  readOptneg,
  readVerdict,
  splitMessage,
} from "../../src/milter/protocol.ts";
import { startFakeMilter } from "../support/fake-milter.ts";

const dec = new TextDecoder();
const u32 = (n: number) => {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n);
  return b;
};
const message = [
  "From: a@acme.test",
  "To: b@example.test",
  "Subject: hi",
  " there",
  "",
  "Hello",
  "",
].join("\r\n");

const milter = startFakeMilter();
afterAll(() => milter.stop());

const run = (data = message, timeoutMs = 2_000) =>
  runMilter({ hostname: "127.0.0.1", port: milter.port }, timeoutMs, {
    id: "m1",
    hostname: "out.bunzzle.test",
    user: "key1",
    from: "a@acme.test",
    recipients: ["b@example.test", "c@example.test"],
    data,
  });

describe("milter protocol", () => {
  test("frames carry a length, a code and NUL-terminated strings", () => {
    const f = frame("L", "Subject\0", "hi\0");
    expect([...f.slice(0, 5)]).toEqual([0, 0, 0, 12, 76]);
    const r = new FrameReader();
    r.push(f.slice(0, 7));
    expect(r.next()).toBeNull();
    r.push(f.slice(7));
    expect(dec.decode(r.next()?.data)).toBe("Subject\0hi\0");
    expect(r.next()).toBeNull();
  });

  test("oversized frames and unoffered options are refused", () => {
    const r = new FrameReader();
    r.push(u32(2 * 1024 * 1024));
    expect(() => r.next()).toThrow("frame of");
    expect(() =>
      readOptneg({ code: "O", data: new Uint8Array([...u32(6), ...u32(0x04), ...u32(0)]) }),
    ).toThrow("actions");
    expect(() =>
      readOptneg({ code: "O", data: new Uint8Array([...u32(6), ...u32(0), ...u32(0x800)]) }),
    ).toThrow("steps");
  });

  test("reply codes map to reject or tempfail; header changes need permission", () => {
    const y = (t: string) => readVerdict({ code: "y", data: new TextEncoder().encode(`${t}\0`) });
    expect(y("550 5.7.1 spam")).toEqual({ action: "reject", text: "550 5.7.1 spam" });
    expect(y("451 4.7.1 later")).toEqual({ action: "tempfail", text: "451 4.7.1 later" });
    expect(() => y("250 ok")).toThrow("bad reply code");
    expect(() => readChange({ code: "m", data: new Uint8Array(8) }, 0x01)).toThrow("permission");
    expect(() => readVerdict({ code: "+", data: new Uint8Array() })).toThrow("unexpected");
  });

  test("headers are sent unfolded with LF and without the leading space", () => {
    expect(headerPairs(splitMessage(message).fields)).toEqual([
      ["From", "a@acme.test"],
      ["To", "b@example.test"],
      ["Subject", "hi\n there"],
    ]);
  });

  test("add, insert, change, delete and body replacement", () => {
    const out = applyChanges(message, [
      { kind: "add", name: "X-Spam", value: "no" },
      { kind: "insert", index: 0, name: "X-First", value: "1" },
      { kind: "change", index: 1, name: "subject", value: "new\n folded" },
      { kind: "change", index: 1, name: "To", value: "" },
      { kind: "change", index: 2, name: "From", value: "" },
      { kind: "body", chunk: new TextEncoder().encode("Bye\n") },
    ]);
    expect(out).toBe(
      [
        "X-First: 1",
        "From: a@acme.test",
        "Subject: new",
        " folded",
        "X-Spam: no",
        "",
        "Bye",
        "",
      ].join("\r\n"),
    );
  });

  test("addresses are inet:host:port or unix:/path", () => {
    expect(parseMilterAddress("inet:127.0.0.1:11332")).toEqual({
      hostname: "127.0.0.1",
      port: 11332,
    });
    expect(parseMilterAddress("inet6:[::1]:8891")).toEqual({ hostname: "::1", port: 8891 });
    expect(parseMilterAddress("unix:/run/m.sock")).toEqual({ unix: "/run/m.sock" });
    expect(parseMilterAddress("inet:host")).toBeNull();
    expect(parseMilterAddress("unix:rel.sock")).toBeNull();
    expect(parseMilterAddress("http://x")).toBeNull();
  });
});

describe("milter conversation", () => {
  test("every step is sent and header changes come back", async () => {
    milter.onEnd = () => [frame("h", "X-Checked\0", "yes\0"), frame("a")];
    const r = await run();
    expect(r).toEqual({
      action: "accept",
      data: message.replace("\r\n\r\n", "\r\nX-Checked: yes\r\n\r\n"),
    });
    await Bun.sleep(20);
    const s = milter.sessions.at(-1);
    expect(s?.frames.map((f) => f.code).join("")).toBe("ODCHDMDRDRTLLLNBEQ");
    const text = (code: string) =>
      s?.frames.filter((f) => f.code === code).map((f) => dec.decode(f.data));
    expect(text("M")).toEqual(["<a@acme.test>\0"]);
    expect(text("R")).toEqual(["<b@example.test>\0", "<c@example.test>\0"]);
    expect(text("B")).toEqual(["Hello\r\n"]);
    expect(text("D")?.[1]).toContain("{auth_authen}\0key1\0");
  });

  test("steps the milter turns off are skipped", async () => {
    milter.steps = 0x01 | 0x02 | 0x10 | 0x80 | 0x1000 | 0x2000 | 0x4000 | 0x8000 | 0x10000;
    milter.onEnd = () => [frame("c")];
    try {
      expect((await run()).action).toBe("accept");
      await Bun.sleep(20);
      expect(
        milter.sessions
          .at(-1)
          ?.frames.map((f) => f.code)
          .join(""),
      ).toBe("ODDMDRDRTLLLNEQ");
    } finally {
      milter.steps = 0;
    }
  });

  test("reject, reply code, tempfail and discard", async () => {
    milter.onEnd = () => [frame("r")];
    expect(await run()).toEqual({ action: "reject", text: null });
    milter.onEnd = () => [frame("y", "554 5.7.1 virus found\0")];
    expect(await run()).toEqual({ action: "reject", text: "554 5.7.1 virus found" });
    milter.onEnd = () => [frame("t")];
    expect(await run()).toEqual({ action: "tempfail", text: null });
    milter.onEnd = () => [frame("d")];
    expect(await run()).toEqual({ action: "reject", text: null });
  });

  test("a large body goes in 64 KB chunks", async () => {
    milter.onEnd = () => [frame("a")];
    const big = `Subject: big\r\n\r\n${"x".repeat(200_000)}`;
    expect((await run(big)).action).toBe("accept");
    const chunks = milter.sessions.at(-1)?.frames.filter((f) => f.code === "B") ?? [];
    expect(chunks.map((c) => c.data.length)).toEqual([65_535, 65_535, 65_535, 3_395]);
  });

  test("a milter that does not answer times out; a closed port fails", async () => {
    milter.onEnd = () => [];
    await expect(run(message, 300)).rejects.toThrow("timed out");
    const closed = Bun.listen({ hostname: "127.0.0.1", port: 0, socket: { data() {} } });
    const port = closed.port;
    closed.stop(true);
    await expect(
      runMilter({ hostname: "127.0.0.1", port }, 1_000, {
        id: "m",
        hostname: "h",
        user: "u",
        from: "a@b.test",
        recipients: ["c@d.test"],
        data: message,
      }),
    ).rejects.toThrow();
  });
});
