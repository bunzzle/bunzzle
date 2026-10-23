import { afterAll, describe, expect, test } from "bun:test";
import { loadLinkTls } from "../../src/roles/node-link.ts";

const fixtures = `${import.meta.dir}/../fixtures/node`;
const dir = `${Bun.env["TMPDIR"] ?? "/tmp"}/bunzzle-node-link-${crypto.randomUUID()}`;
const pin = "sha256/47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";

afterAll(async () => {
  await Bun.$`rm -rf ${dir}`.quiet();
});

async function nodeDir(name: string, pins: string, keyMode = "600") {
  const d = `${dir}/${name}`;
  await Bun.$`mkdir -p ${d} && cp ${fixtures}/node.pem ${d}/cert.pem && cp ${fixtures}/node.key ${d}/key.pem && cp ${fixtures}/ca.pem ${d}/ca.pem && chmod ${keyMode} ${d}/key.pem`.quiet();
  await Bun.write(`${d}/peer.pin`, pins);
  return d;
}

describe("loadLinkTls", () => {
  test("reads certificate, key, CA and pins", async () => {
    const tls = await loadLinkTls(await nodeDir("ok", `${pin}\n\n${pin.replace("47", "48")}\n`));
    expect(tls.pins).toEqual([pin, pin.replace("47", "48")]);
    expect(tls.cert).toContain("BEGIN CERTIFICATE");
    expect(tls.key).toContain("PRIVATE KEY");
  });

  test("refuses a missing file, a readable key and bad pins", async () => {
    await expect(loadLinkTls(`${dir}/none`)).rejects.toThrow(/missing/);
    await expect(loadLinkTls(await nodeDir("open", pin, "640"))).rejects.toThrow(/readable/);
    await expect(loadLinkTls(await nodeDir("empty", "\n"))).rejects.toThrow(/peer.pin/);
    await expect(loadLinkTls(await nodeDir("bad", "sha1/abc"))).rejects.toThrow(/peer.pin/);
  });
});
