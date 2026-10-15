import { z } from "zod";

const bool = z
  .enum(["true", "false", "1", "0"])
  .default("false")
  .transform((v) => v === "true" || v === "1");

const optional = z
  .string()
  .optional()
  .transform((v) => (v?.trim() ? v.trim() : null));

const schema = z.object({
  BUNZZLE_HOST: z.string().min(1).default("127.0.0.1"),
  BUNZZLE_PORT: z.coerce.number().int().min(0).max(65535).default(3000),
  BUNZZLE_DATA_DIR: z.string().min(1).default("./data"),
  BUNZZLE_LOG_LEVEL: z.enum(["debug", "info", "warn", "error"]).default("info"),
  BUNZZLE_EHLO_NAME: optional,
  BUNZZLE_SOURCE_IP: optional,
  BUNZZLE_DNS_SERVERS: optional,
  BUNZZLE_DKIM_KEY_FILE: optional,
  BUNZZLE_IPV6: bool,
  BUNZZLE_SMTP_PORT: z.coerce.number().int().min(1).max(65535).default(25),
  BUNZZLE_ALLOW_PRIVATE_DESTINATIONS: bool,
});

export interface Config {
  host: string;
  port: number;
  dataDir: string;
  dbPath: string;
  logLevel: "debug" | "info" | "warn" | "error";
  ehloName: string | null;
  sourceIp: string | null;
  dnsServers: string[];
  dkimKeyFile: string | null;
  ipv6: boolean;
  smtpPort: number;
  allowPrivateDestinations: boolean;
}

export class ConfigError extends Error {}

export function loadConfig(env: Record<string, string | undefined> = process.env): Config {
  const parsed = schema.safeParse(env);
  if (!parsed.success) {
    const problems = parsed.error.issues.map((i) => `  ${i.path.join(".")}: ${i.message}`);
    throw new ConfigError(`invalid configuration:\n${problems.join("\n")}`);
  }
  const c = parsed.data;
  return {
    host: c.BUNZZLE_HOST,
    port: c.BUNZZLE_PORT,
    dataDir: c.BUNZZLE_DATA_DIR,
    dbPath: `${c.BUNZZLE_DATA_DIR.replace(/\/+$/, "")}/bunzzle.db`,
    logLevel: c.BUNZZLE_LOG_LEVEL,
    ehloName: c.BUNZZLE_EHLO_NAME,
    sourceIp: c.BUNZZLE_SOURCE_IP,
    dnsServers: (c.BUNZZLE_DNS_SERVERS ?? "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean),
    dkimKeyFile: c.BUNZZLE_DKIM_KEY_FILE,
    ipv6: c.BUNZZLE_IPV6,
    smtpPort: c.BUNZZLE_SMTP_PORT,
    allowPrivateDestinations: c.BUNZZLE_ALLOW_PRIVATE_DESTINATIONS,
  };
}
