import { describe, expect, test } from "bun:test";
import {
  BodySealer,
  epochKeyPair,
  newEpochSeed,
  openBody,
  sealBody,
} from "../../src/crypto/envelope.ts";
import { generateMasterKey, MasterKeyError, masterKeyFrom } from "../../src/crypto/master.ts";
import { Keystore } from "../../src/signer/keystore.ts";

const dir = `${Bun.env["TMPDIR"] ?? "/tmp"}/bunzzle-crypto-${crypto.randomUUID()}`;
await Bun.$`mkdir -p ${dir}`.quiet();
const DAY = 86_400_000;

describe("master key", () => {
  test("seals and opens, bound to its context", async () => {
    const m = await masterKeyFrom(generateMasterKey());
    const sealed = await m.seal(new TextEncoder().encode("secret"), "ctx-a");
    expect(new TextDecoder().decode(await m.open(sealed, "ctx-a"))).toBe("secret");
    expect(m.open(sealed, "ctx-b")).rejects.toThrow(MasterKeyError);
    const other = await masterKeyFrom(generateMasterKey());
    expect(other.open(sealed, "ctx-a")).rejects.toThrow(MasterKeyError);
    expect(other.id).not.toBe(m.id);
  });

  test("rejects keys that are not 32 bytes of base64", async () => {
    expect(masterKeyFrom("short")).rejects.toThrow(MasterKeyError);
    expect(masterKeyFrom(new Uint8Array(16).toBase64())).rejects.toThrow("32 bytes");
  });
});

describe("body sealer", () => {
  test("bodies sealed in one window share the ephemeral key but not the wrapped key, and open as before", async () => {
    const pair = await epochKeyPair(20_000, newEpochSeed());
    let t = 0;
    const sealer = new BodySealer({ reuseMs: 1_000, now: () => t });
    const [a, b] = await Promise.all([
      sealer.seal(pair, "m1", "Subject: a\r\n\r\none"),
      sealer.seal(pair, "m2", "Subject: b\r\n\r\ntwo"),
    ]);
    expect(a.wrapped.subarray(0, 32)).toEqual(b.wrapped.subarray(0, 32));
    expect(a.wrapped.subarray(32)).not.toEqual(b.wrapped.subarray(32));
    expect(await openBody(pair, "m1", a)).toBe("Subject: a\r\n\r\none");
    expect(await openBody(pair, "m2", b)).toBe("Subject: b\r\n\r\ntwo");
    expect(openBody(pair, "m2", a)).rejects.toThrow();
    t = 1_000;
    const c = await sealer.seal(pair, "m3", "three");
    expect(c.wrapped.subarray(0, 32)).not.toEqual(a.wrapped.subarray(0, 32));
    expect(await openBody(pair, "m3", c)).toBe("three");
  });

  test("a new epoch gets a new ephemeral key at once", async () => {
    const one = await epochKeyPair(20_000, newEpochSeed());
    const two = await epochKeyPair(20_001, newEpochSeed());
    const sealer = new BodySealer({ reuseMs: 60_000 });
    const a = await sealer.seal(one, "m1", "x");
    const b = await sealer.seal(two, "m2", "y");
    expect(b.epoch).toBe(20_001);
    expect(b.wrapped.subarray(0, 32)).not.toEqual(a.wrapped.subarray(0, 32));
    expect(await openBody(two, "m2", b)).toBe("y");
    expect(openBody(one, "m2", b)).rejects.toThrow();
  });
});

describe("body envelope", () => {
  test("anyone with the public key can seal, only the private key opens", async () => {
    const pair = await epochKeyPair(20_000, newEpochSeed());
    const sealed = await sealBody(pair, "m1", "Subject: hi\r\n\r\nbody");
    expect(new TextDecoder().decode(sealed.body)).not.toContain("body");
    expect(await openBody(pair, "m1", sealed)).toBe("Subject: hi\r\n\r\nbody");
  });

  test("a body cannot be moved to another message id or opened with another key", async () => {
    const pair = await epochKeyPair(20_000, newEpochSeed());
    const sealed = await sealBody(pair, "m1", "x");
    expect(openBody(pair, "m2", sealed)).rejects.toThrow();
    const other = await epochKeyPair(20_000, newEpochSeed());
    expect(openBody(other, "m1", sealed)).rejects.toThrow();
  });

  test("the same seed always gives the same key pair", async () => {
    const seed = newEpochSeed();
    const a = await epochKeyPair(1, seed);
    const b = await epochKeyPair(1, seed);
    expect(a.publicKey.toHex()).toBe(b.publicKey.toHex());
  });
});

describe("keystore", () => {
  test("concurrent requests for a new day get one key, and it survives a restart", async () => {
    const m = await masterKeyFrom(generateMasterKey());
    const path = `${dir}/${crypto.randomUUID()}.json`;
    const store = await Keystore.open(path, m);
    const keys = await Promise.all(Array.from({ length: 20 }, () => store.current(5 * DAY)));
    expect(new Set(keys.map((k) => k.publicKey.toHex())).size).toBe(1);
    const reopened = await Keystore.open(path, m);
    const again = await reopened.get(5);
    expect(again?.publicKey.toHex()).toBe(keys[0]?.publicKey.toHex());
  });

  test("seeds are stored encrypted, and another master key cannot open the store", async () => {
    const m = await masterKeyFrom(generateMasterKey());
    const path = `${dir}/${crypto.randomUUID()}.json`;
    const store = await Keystore.open(path, m);
    await store.current(9 * DAY);
    expect(((await Bun.file(path).stat()).mode & 0o777).toString(8)).toBe("600");
    expect(Keystore.open(path, await masterKeyFrom(generateMasterKey()))).rejects.toThrow(
      "another master key",
    );
  });

  test("shredding destroys old days for good", async () => {
    const m = await masterKeyFrom(generateMasterKey());
    const path = `${dir}/${crypto.randomUUID()}.json`;
    const store = await Keystore.open(path, m);
    for (const day of [1, 2, 3]) await store.current(day * DAY);
    expect(await store.shred(3)).toEqual([1, 2]);
    expect(store.epochs()).toEqual([3]);
    const reopened = await Keystore.open(path, m);
    expect(await reopened.get(1)).toBeNull();
    expect(await reopened.get(3)).not.toBeNull();
  });
});
