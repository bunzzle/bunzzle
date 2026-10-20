import { describe, expect, test } from "bun:test";
import { roleEnv } from "../../src/roles/env.ts";
import { ROLES } from "../../src/roles/wire.ts";

const SUPERVISOR_ONLY = new Set(["BUNZZLE_MASTER_KEY", "BUNZZLE_MASTER_KEY_FILE"]);

const settings = async () => {
  const source = await Bun.file(`${import.meta.dir}/../../src/config.ts`).text();
  return [
    ...new Set([...source.matchAll(/^\s+(BUNZZLE_[A-Z0-9_]+):/gm)].map((m) => m[1] as string)),
  ];
};

const rolesGetting = (name: string) =>
  ROLES.filter((role) => roleEnv(role, { [name]: "x" })[name] === "x");

describe("role environments under bunzzle serve", () => {
  test("every setting reaches at least one role", async () => {
    const all = await settings();
    expect(all.length).toBeGreaterThan(50);
    const missing = all.filter(
      (name) => !SUPERVISOR_ONLY.has(name) && rolesGetting(name).length === 0,
    );
    expect(missing).toEqual([]);
  });

  test("the master key reaches no role through the environment", () => {
    for (const name of SUPERVISOR_ONLY) expect(rolesGetting(name)).toEqual([]);
  });

  test("credentials reach only the role that uses them", () => {
    expect(rolesGetting("BUNZZLE_RELAY_PASSWORD_FILE")).toEqual(["delivery"]);
    expect(rolesGetting("BUNZZLE_SPAMHAUS_KEY_FILE")).toEqual(["delivery"]);
    for (const name of [
      "BUNZZLE_CLOUDFLARE_API_TOKEN",
      "BUNZZLE_CLOUDFLARE_API_TOKEN_FILE",
      "BUNZZLE_DNS_UPDATE_KEY_FILE",
      "BUNZZLE_ROUTE53_SECRET_ACCESS_KEY_FILE",
      "BUNZZLE_DESEC_TOKEN_FILE",
      "BUNZZLE_POSTMASTER_CLIENT_SECRET_FILE",
      "BUNZZLE_POSTMASTER_REFRESH_TOKEN_FILE",
    ]) {
      expect(rolesGetting(name)).toEqual(["dns"]);
    }
  });
});
