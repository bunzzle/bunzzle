import { describe, expect, test } from "bun:test";
import { ConfigError, loadConfig } from "../../src/config.ts";

describe("loadConfig", () => {
  test("uses safe defaults", () => {
    expect(loadConfig({})).toEqual({
      host: "127.0.0.1",
      port: 3000,
      dataDir: "./data",
      dbPath: "./data/bunzzle.db",
      logLevel: "info",
    });
  });

  test("reads environment variables", () => {
    const c = loadConfig({
      BUNZZLE_HOST: "0.0.0.0",
      BUNZZLE_PORT: "8080",
      BUNZZLE_DATA_DIR: "/var/lib/bunzzle/",
      BUNZZLE_LOG_LEVEL: "debug",
    });
    expect(c.host).toBe("0.0.0.0");
    expect(c.port).toBe(8080);
    expect(c.dbPath).toBe("/var/lib/bunzzle/bunzzle.db");
    expect(c.logLevel).toBe("debug");
  });

  test("reports every invalid value at once", () => {
    try {
      loadConfig({ BUNZZLE_PORT: "99999", BUNZZLE_LOG_LEVEL: "loud" });
      throw new Error("expected ConfigError");
    } catch (err) {
      expect(err).toBeInstanceOf(ConfigError);
      expect((err as Error).message).toContain("BUNZZLE_PORT");
      expect((err as Error).message).toContain("BUNZZLE_LOG_LEVEL");
    }
  });
});
