import { describe, expect, test } from "bun:test";
import { loadConfig } from "../../src/config.ts";
import { createLogger } from "../../src/core/log.ts";
import { parseEnvFile, Reloader } from "../../src/roles/reload.ts";

describe("env file", () => {
  test("KEY=VALUE lines, quotes, comments and blanks like systemd and shells", () => {
    expect(
      parseEnvFile(
        [
          "# comment",
          "; also a comment",
          "",
          "BUNZZLE_LOG_LEVEL=debug",
          '  BUNZZLE_TLSRPT_ORG="Acme \\"Mail\\""',
          "BUNZZLE_PUBLIC_URL='https://mail.acme.test'",
          "export BUNZZLE_EHLO_NAME = mail.acme.test",
          "not a line",
          "BUNZZLE_EMPTY=",
        ].join("\n"),
      ),
    ).toEqual({
      BUNZZLE_LOG_LEVEL: "debug",
      BUNZZLE_TLSRPT_ORG: 'Acme "Mail"',
      BUNZZLE_PUBLIC_URL: "https://mail.acme.test",
      BUNZZLE_EHLO_NAME: "mail.acme.test",
      BUNZZLE_EMPTY: "",
    });
  });
});

function setup(role: "core" | "delivery", start: Record<string, string>, files: string[]) {
  const lines: Record<string, unknown>[] = [];
  const log = createLogger("info", {}, (l) => lines.push(JSON.parse(l)));
  const env = { BUNZZLE_ENV_FILE: "/etc/bunzzle/bunzzle.env", ...start };
  const config = loadConfig(env);
  let n = 0;
  const reloader = new Reloader(
    role,
    config,
    log,
    env,
    async () => {
      const f = files[n++];
      if (f === undefined) throw new Error("gone");
      return f;
    },
    start,
  );
  return { config, reloader, lines, log };
}

describe("reload", () => {
  test("live settings change in place; the rest is named as needing a restart", async () => {
    const r = setup("core", { BUNZZLE_MIN_FREE_MB: "100", BUNZZLE_EHLO_NAME: "a.test" }, [
      "BUNZZLE_MIN_FREE_MB=5\nBUNZZLE_EHLO_NAME=b.test\nBUNZZLE_GUARD_MIN_VOLUME=50\nBUNZZLE_LOG_LEVEL=debug",
    ]);
    const before = r.config;
    const done = await r.reloader.reload();
    expect(done?.applied.sort()).toEqual(["guardMinVolume", "logLevel", "minFreeMb"]);
    expect(done?.needRestart.sort()).toEqual(["ehloName", "inboundHostname", "tlsrpt"]);
    expect(r.config).toBe(before);
    expect(r.config.minFreeMb).toBe(5);
    expect(r.config.guardMinVolume).toBe(50);
    expect(r.config.ehloName).toBe("a.test");
    r.log.debug("now visible");
    expect(r.lines.map((l) => l["msg"])).toContain("now visible");
    expect(r.lines.find((l) => l["msg"] === "configuration reloaded")?.["need_restart"]).toContain(
      "ehloName",
    );
  });

  test("a setting removed from the file goes back to its default", async () => {
    const r = setup("core", { BUNZZLE_MIN_FREE_MB: "100" }, [""]);
    expect((await r.reloader.reload())?.applied).toEqual(["minFreeMb"]);
    expect(r.config.minFreeMb).toBe(1024);
  });

  test("an invalid or unreadable file keeps the running configuration", async () => {
    const r = setup("core", { BUNZZLE_MIN_FREE_MB: "100" }, ["BUNZZLE_MIN_FREE_MB=lots"]);
    expect(await r.reloader.reload()).toBeNull();
    expect(r.config.minFreeMb).toBe(100);
    expect(await r.reloader.reload()).toBeNull();
    expect(r.lines.map((l) => l["msg"])).toEqual([
      "configuration not reloaded: it is not valid",
      "configuration not reloaded: the file cannot be read",
    ]);
  });

  test("each role applies only its own live settings", async () => {
    const r = setup("delivery", {}, ["BUNZZLE_MIN_FREE_MB=5"]);
    expect(await r.reloader.reload()).toEqual({ applied: [], needRestart: ["minFreeMb"] });
    expect(r.config.minFreeMb).toBe(1024);
  });

  test("without BUNZZLE_ENV_FILE nothing is reloaded", async () => {
    const lines: Record<string, unknown>[] = [];
    const log = createLogger("info", {}, (l) => lines.push(JSON.parse(l)));
    const reloader = new Reloader("core", loadConfig({}), log, {});
    expect(await reloader.reload()).toBeNull();
    expect(lines[0]?.["msg"]).toBe(
      "reload needs BUNZZLE_ENV_FILE: the configuration was not reloaded",
    );
  });
});
