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
      ehloName: null,
      sourceIp: null,
      dnsServers: [],
      dkimKeyFile: null,
      ipv6: false,
      smtpPort: 25,
      allowPrivateDestinations: false,
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

  test("reads sending settings", () => {
    const c = loadConfig({
      BUNZZLE_EHLO_NAME: "mail.bunzzle.com",
      BUNZZLE_SOURCE_IP: "203.0.113.7",
      BUNZZLE_DNS_SERVERS: "1.1.1.1, 9.9.9.9:53",
      BUNZZLE_IPV6: "true",
      BUNZZLE_ALLOW_PRIVATE_DESTINATIONS: "1",
    });
    expect(c.ehloName).toBe("mail.bunzzle.com");
    expect(c.sourceIp).toBe("203.0.113.7");
    expect(c.dnsServers).toEqual(["1.1.1.1", "9.9.9.9:53"]);
    expect(c.ipv6).toBe(true);
    expect(c.allowPrivateDestinations).toBe(true);
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
