import { z } from "zod";
import { familyOf } from "./dns/ip.ts";

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
  BUNZZLE_MASTER_KEY: optional,
  BUNZZLE_MASTER_KEY_FILE: optional,
  BUNZZLE_KEYS_DIR: z.string().min(1).default("./keys"),
  BUNZZLE_RUN_DIR: z.string().min(1).default("./run"),
  BUNZZLE_RETENTION_DAYS: z.coerce.number().int().min(7).max(3650).default(30),
  BUNZZLE_INBOUND_HOST: z.string().min(1).default("0.0.0.0"),
  BUNZZLE_INBOUND_PORT: z.coerce.number().int().min(0).max(65535).optional(),
  BUNZZLE_RETRY_SCALE: z.coerce.number().positive().max(1).default(1),
  BUNZZLE_PUBLIC_URL: optional.refine((v) => v === null || /^https?:\/\/[^\s/]+/.test(v), {
    message: "must be an http(s) URL like https://mail.example.com",
  }),
  BUNZZLE_INBOUND_HOSTNAME: optional,
  BUNZZLE_SOURCE_IPS: optional,
  BUNZZLE_ESTABLISHED_IPS: optional,
  BUNZZLE_GUARD_MIN_VOLUME: z.coerce.number().int().min(1).default(300),
  BUNZZLE_ANOMALY_FLOOR: z.coerce.number().int().min(1).default(500),
  BUNZZLE_DKIM_ROTATE_DAYS: z.coerce.number().int().min(7).max(3650).default(90),
  BUNZZLE_CLOUDFLARE_API_TOKEN: optional,
  BUNZZLE_CLOUDFLARE_API_TOKEN_FILE: optional,
  BUNZZLE_CLOUDFLARE_API_URL: z.string().url().default("https://api.cloudflare.com/client/v4"),
});

export interface SourceIp {
  ip: string;
  pool: string;
  established: boolean;
}

function sourceIps(
  list: string | null,
  single: string | null,
  established: string | null,
): SourceIp[] {
  const done = new Set(
    (established ?? "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean),
  );
  const entries = (list ?? single ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const out: SourceIp[] = [];
  for (const e of entries) {
    const [ip = "", pool = "main"] = e.split("=").map((x) => x.trim());
    if (!familyOf(ip))
      throw new ConfigError(
        `invalid configuration:\n  BUNZZLE_SOURCE_IPS: ${ip} is not an IP address`,
      );
    if (!/^[a-z0-9-]{1,32}$/.test(pool))
      throw new ConfigError(
        `invalid configuration:\n  BUNZZLE_SOURCE_IPS: invalid pool name ${pool}`,
      );
    if (!out.some((x) => x.ip === ip)) out.push({ ip, pool, established: done.has(ip) });
  }
  return out;
}

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
  masterKey: string | null;
  masterKeyFile: string | null;
  keysDir: string;
  runDir: string;
  retentionDays: number;
  inboundHost: string;
  inboundPort: number | null;
  retryScale: number;
  publicUrl: string | null;
  inboundHostname: string | null;
  sourceIps: SourceIp[];
  guardMinVolume: number;
  anomalyFloor: number;
  dkimRotateDays: number;
  cloudflareToken: string | null;
  cloudflareTokenFile: string | null;
  cloudflareUrl: string;
}

export class ConfigError extends Error {}

export function loadConfig(env: Record<string, string | undefined> = process.env): Config {
  const parsed = schema.safeParse(env);
  if (!parsed.success) {
    const problems = parsed.error.issues.map((i) => `  ${i.path.join(".")}: ${i.message}`);
    throw new ConfigError(`invalid configuration:\n${problems.join("\n")}`);
  }
  const c = parsed.data;
  if (c.BUNZZLE_CLOUDFLARE_API_TOKEN && c.BUNZZLE_CLOUDFLARE_API_TOKEN_FILE) {
    throw new ConfigError(
      "invalid configuration:\n  set BUNZZLE_CLOUDFLARE_API_TOKEN or BUNZZLE_CLOUDFLARE_API_TOKEN_FILE, not both",
    );
  }
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
    masterKey: c.BUNZZLE_MASTER_KEY,
    masterKeyFile: c.BUNZZLE_MASTER_KEY_FILE,
    keysDir: c.BUNZZLE_KEYS_DIR.replace(/\/+$/, ""),
    runDir: c.BUNZZLE_RUN_DIR.replace(/\/+$/, ""),
    retentionDays: c.BUNZZLE_RETENTION_DAYS,
    inboundHost: c.BUNZZLE_INBOUND_HOST,
    inboundPort: c.BUNZZLE_INBOUND_PORT ?? null,
    retryScale: c.BUNZZLE_RETRY_SCALE,
    publicUrl: c.BUNZZLE_PUBLIC_URL?.replace(/\/+$/, "") ?? null,
    inboundHostname: c.BUNZZLE_INBOUND_HOSTNAME ?? c.BUNZZLE_EHLO_NAME,
    sourceIps: sourceIps(c.BUNZZLE_SOURCE_IPS, c.BUNZZLE_SOURCE_IP, c.BUNZZLE_ESTABLISHED_IPS),
    guardMinVolume: c.BUNZZLE_GUARD_MIN_VOLUME,
    anomalyFloor: c.BUNZZLE_ANOMALY_FLOOR,
    dkimRotateDays: c.BUNZZLE_DKIM_ROTATE_DAYS,
    cloudflareToken: c.BUNZZLE_CLOUDFLARE_API_TOKEN,
    cloudflareTokenFile: c.BUNZZLE_CLOUDFLARE_API_TOKEN_FILE,
    cloudflareUrl: c.BUNZZLE_CLOUDFLARE_API_URL.replace(/\/+$/, ""),
  };
}
