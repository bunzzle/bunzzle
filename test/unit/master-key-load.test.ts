import { describe, expect, test } from "bun:test";
import { readMasterKeyText } from "../../src/crypto/load.ts";

const dir = `${Bun.env["TMPDIR"] ?? "/tmp"}/bunzzle-creds-${crypto.randomUUID().slice(0, 8)}`;

describe("master key file", () => {
  test("says when systemd passed no credentials", async () => {
    const err = await readMasterKeyText(
      { masterKey: null, masterKeyFile: `${dir}/master.key` },
      dir,
    ).catch((e: Error) => e);
    expect((err as Error).message).toContain("systemd passed no credentials");
  });

  test("names only the file when the credentials directory exists", async () => {
    await Bun.$`mkdir -p ${dir}`.quiet();
    const err = await readMasterKeyText(
      { masterKey: null, masterKeyFile: `${dir}/master.key` },
      dir,
    ).catch((e: Error) => e);
    expect((err as Error).message).toBe(`master key file not found: ${dir}/master.key`);
    await Bun.$`rm -rf ${dir}`.quiet();
  });
});
