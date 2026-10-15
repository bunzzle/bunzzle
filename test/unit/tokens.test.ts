import { describe, expect, test } from "bun:test";
import { generateMasterKey, masterKeyFrom } from "../../src/crypto/master.ts";
import { base32, makeToken, readToken, unbase32 } from "../../src/signer/tokens.ts";

const master = await masterKeyFrom(generateMasterKey());
const ID = "01a13f75-7780-77d7-b8a2-1429340b86fe";

describe("signed tokens (return path, ref header, unsubscribe)", () => {
  test("round trip for uuid and short text ids, short enough for an address local part", async () => {
    const t = await makeToken(master, "b", ID);
    expect(t).toMatch(/^[a-z2-7]+$/);
    expect(`b-${t}`.length).toBeLessThanOrEqual(64);
    expect(await readToken(master, t)).toEqual({ purpose: "b", messageId: ID });
    expect(await readToken(master, t.toUpperCase())).toEqual({ purpose: "b", messageId: ID });
    const short = await makeToken(master, "u", "e42");
    expect(await readToken(master, short)).toEqual({ purpose: "u", messageId: "e42" });
  });

  test("forged, altered or foreign tokens are rejected", async () => {
    const t = await makeToken(master, "b", ID);
    const flipped = `${t.slice(0, 10)}${t[10] === "a" ? "b" : "a"}${t.slice(11)}`;
    expect(await readToken(master, flipped)).toBeNull();
    expect(await readToken(master, t.slice(0, -1))).toBeNull();
    expect(await readToken(master, "a".repeat(44))).toBeNull();
    expect(await readToken(master, "not base32!")).toBeNull();
    const other = await masterKeyFrom(generateMasterKey());
    expect(await readToken(other, t)).toBeNull();
  });

  test("a bounce token cannot be used as an unsubscribe token", async () => {
    const b = await makeToken(master, "b", ID);
    const bytes = unbase32(b) as Uint8Array;
    bytes[0] = "u".charCodeAt(0);
    expect(await readToken(master, base32(bytes))).toBeNull();
  });
});
