import { familyOf } from "./dns/ip.ts";
import { b } from "./validate/schema.ts";

const bool = b
  .enum(["true", "false", "1", "0"])
  .default("false")
  .transform((v) => v === "true" || v === "1");

const optional = b
  .string()
  .optional()
  .transform((v) => (v?.trim() ? v.trim() : null));

const schema = b.object({
  BUNZZLE_HOST: b.string().min(1).default("127.0.0.1"),
  BUNZZLE_PORT: b.coerce.number().int().min(0).max(65535).default(3000),
  BUNZZLE_DATA_DIR: b.string().min(1).default("./data"),
  BUNZZLE_LOG_LEVEL: b.enum(["debug", "info", "warn", "error"]).default("info"),
  BUNZZLE_EHLO_NAME: optional,
  BUNZZLE_SOURCE_IP: optional,
  BUNZZLE_DNS_SERVERS: optional,
  BUNZZLE_DKIM_KEY_FILE: optional,
  BUNZZLE_IPV6: bool,
  BUNZZLE_SMTP_PORT: b.coerce.number().int().min(1).max(65535).default(25),
  BUNZZLE_ALLOW_PRIVATE_DESTINATIONS: bool,
  BUNZZLE_MASTER_KEY: optional,
  BUNZZLE_MASTER_KEY_FILE: optional,
  BUNZZLE_KEYS_DIR: b.string().min(1).default("./keys"),
  BUNZZLE_RUN_DIR: b.string().min(1).default("./run"),
  BUNZZLE_RETENTION_DAYS: b.coerce.number().int().min(7).max(3650).default(30),
  BUNZZLE_EVENT_LOG: bool,
  BUNZZLE_EVENT_LOG_DIR: b.string().min(1).default("./logs/events"),
  BUNZZLE_EVENT_LOG_MAX_MB: b.coerce.number().int().min(1).max(100_000).default(100),
  BUNZZLE_EVENT_LOG_DAYS: b.coerce.number().int().min(1).max(3650).default(30),
  BUNZZLE_INBOUND_HOST: b.string().min(1).default("0.0.0.0"),
  BUNZZLE_INBOUND_PORT: b.coerce.number().int().min(0).max(65535).optional(),
  BUNZZLE_RETRY_SCALE: b.coerce.number().positive().max(1).default(1),
  BUNZZLE_PUBLIC_URL: optional.refine((v) => v === null || /^https?:\/\/[^\s/]+/.test(v), {
    message: "must be an http(s) URL like https://mail.example.com",
  }),
  BUNZZLE_INBOUND_HOSTNAME: optional,
  BUNZZLE_INBOUND_TLS_CERT_FILE: optional,
  BUNZZLE_INBOUND_TLS_KEY_FILE: optional,
  BUNZZLE_DANE: b.enum(["auto", "off"]).default("auto"),
  BUNZZLE_REQUIRETLS: b.enum(["enforce", "relaxed"]).default("enforce"),
  BUNZZLE_DNS_UPDATE_SERVER: optional,
  BUNZZLE_DNS_UPDATE_KEY_NAME: optional,
  BUNZZLE_DNS_UPDATE_KEY_FILE: optional,
  BUNZZLE_DNS_UPDATE_ALGORITHM: b.enum(["hmac-sha256", "hmac-sha512"]).default("hmac-sha256"),
  BUNZZLE_RELAY_HOST: optional,
  BUNZZLE_RELAY_USERNAME: optional,
  BUNZZLE_RELAY_PASSWORD_FILE: optional,
  BUNZZLE_ACME_EMAIL: optional,
  BUNZZLE_ACME_DIRECTORY: b
    .string()
    .url()
    .default("https://acme-v02.api.letsencrypt.org/directory"),
  BUNZZLE_CERTS_DIR: b.string().min(1).default("./certs"),
  BUNZZLE_TLSRPT_FROM: optional,
  BUNZZLE_TLSRPT_ORG: optional,
  BUNZZLE_TLSRPT_CONTACT: optional,
  BUNZZLE_SUBMISSION_HOST: b.string().min(1).default("0.0.0.0"),
  BUNZZLE_SUBMISSION_PORT: b.coerce.number().int().min(0).max(65535).optional(),
  BUNZZLE_SUBMISSION_TLS_PORT: b.coerce.number().int().min(0).max(65535).optional(),
  BUNZZLE_SUBMISSION_HOSTNAME: optional,
  BUNZZLE_SUBMISSION_TLS_CERT_FILE: optional,
  BUNZZLE_SUBMISSION_TLS_KEY_FILE: optional,
  BUNZZLE_SOURCE_IPS: optional,
  BUNZZLE_ESTABLISHED_IPS: optional,
  BUNZZLE_GUARD_MIN_VOLUME: b.coerce.number().int().min(1).default(300),
  BUNZZLE_ANOMALY_FLOOR: b.coerce.number().int().min(1).default(500),
  BUNZZLE_DKIM_ROTATE_DAYS: b.coerce.number().int().min(7).max(3650).default(90),
  BUNZZLE_CLOUDFLARE_API_TOKEN: optional,
  BUNZZLE_CLOUDFLARE_API_TOKEN_FILE: optional,
  BUNZZLE_CLOUDFLARE_API_URL: b.string().url().default("https://api.cloudflare.com/client/v4"),
  BUNZZLE_ROUTE53_ACCESS_KEY_ID: optional,
  BUNZZLE_ROUTE53_SECRET_ACCESS_KEY_FILE: optional,
  BUNZZLE_ROUTE53_API_URL: b.string().url().default("https://route53.amazonaws.com"),
  BUNZZLE_DESEC_TOKEN_FILE: optional,
  BUNZZLE_DESEC_API_URL: b.string().url().default("https://desec.io/api/v1"),
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
  eventLog: { dir: string; maxBytes: number; keepDays: number } | null;
  inboundHost: string;
  inboundPort: number | null;
  retryScale: number;
  publicUrl: string | null;
  inboundHostname: string | null;
  inboundTlsCertFile: string | null;
  inboundTlsKeyFile: string | null;
  dane: "auto" | "off";
  requiretls: "enforce" | "relaxed";
  dnsUpdate: {
    server: string;
    keyName: string;
    keyFile: string;
    algorithm: "hmac-sha256" | "hmac-sha512";
  } | null;
  relay: {
    host: string;
    port: number;
    username: string | null;
    passwordFile: string | null;
  } | null;
  acme: { email: string; directory: string; dir: string; hosts: string[] } | null;
  tlsrpt: { from: string | null; org: string; contact: string };
  submission: {
    host: string;
    port: number | null;
    tlsPort: number | null;
    hostname: string | null;
    certFile: string;
    keyFile: string;
  } | null;
  sourceIps: SourceIp[];
  guardMinVolume: number;
  anomalyFloor: number;
  dkimRotateDays: number;
  cloudflareToken: string | null;
  cloudflareTokenFile: string | null;
  cloudflareUrl: string;
  route53: { accessKeyId: string; secretKeyFile: string; url: string } | null;
  desec: { tokenFile: string; url: string } | null;
}

export class ConfigError extends Error {}

export function loadConfig(env: Record<string, string | undefined> = Bun.env): Config {
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
  const update = [
    c.BUNZZLE_DNS_UPDATE_SERVER,
    c.BUNZZLE_DNS_UPDATE_KEY_NAME,
    c.BUNZZLE_DNS_UPDATE_KEY_FILE,
  ];
  if (update.some(Boolean) && !update.every(Boolean)) {
    throw new ConfigError(
      "invalid configuration:\n  DNS updates need BUNZZLE_DNS_UPDATE_SERVER, BUNZZLE_DNS_UPDATE_KEY_NAME and BUNZZLE_DNS_UPDATE_KEY_FILE together",
    );
  }
  if (!!c.BUNZZLE_ROUTE53_ACCESS_KEY_ID !== !!c.BUNZZLE_ROUTE53_SECRET_ACCESS_KEY_FILE) {
    throw new ConfigError(
      "invalid configuration:\n  set BUNZZLE_ROUTE53_ACCESS_KEY_ID and BUNZZLE_ROUTE53_SECRET_ACCESS_KEY_FILE together",
    );
  }
  const providers = [
    c.BUNZZLE_CLOUDFLARE_API_TOKEN || c.BUNZZLE_CLOUDFLARE_API_TOKEN_FILE,
    update.every(Boolean),
    c.BUNZZLE_ROUTE53_ACCESS_KEY_ID,
    c.BUNZZLE_DESEC_TOKEN_FILE,
  ].filter(Boolean);
  if (providers.length > 1) {
    throw new ConfigError(
      "invalid configuration:\n  publish DNS records through one provider: Cloudflare, DNS updates, Route 53 or deSEC",
    );
  }
  if ((c.BUNZZLE_RELAY_USERNAME || c.BUNZZLE_RELAY_PASSWORD_FILE) && !c.BUNZZLE_RELAY_HOST) {
    throw new ConfigError(
      "invalid configuration:\n  BUNZZLE_RELAY_USERNAME needs BUNZZLE_RELAY_HOST",
    );
  }
  if (!!c.BUNZZLE_RELAY_USERNAME !== !!c.BUNZZLE_RELAY_PASSWORD_FILE) {
    throw new ConfigError(
      "invalid configuration:\n  set BUNZZLE_RELAY_USERNAME and BUNZZLE_RELAY_PASSWORD_FILE together",
    );
  }
  const relayMatch = c.BUNZZLE_RELAY_HOST
    ? /^(\[[^\]]+\]|[^:]+)(?::(\d{1,5}))?$/.exec(c.BUNZZLE_RELAY_HOST.trim())
    : null;
  if (c.BUNZZLE_RELAY_HOST && !relayMatch) {
    throw new ConfigError("invalid configuration:\n  BUNZZLE_RELAY_HOST must be host or host:port");
  }
  const certsDir = c.BUNZZLE_CERTS_DIR.replace(/\/+$/, "");
  const acmeHosts = [
    ...(c.BUNZZLE_INBOUND_PORT !== undefined
      ? [c.BUNZZLE_INBOUND_HOSTNAME ?? c.BUNZZLE_EHLO_NAME]
      : []),
    ...(c.BUNZZLE_SUBMISSION_PORT !== undefined || c.BUNZZLE_SUBMISSION_TLS_PORT !== undefined
      ? [c.BUNZZLE_SUBMISSION_HOSTNAME ?? c.BUNZZLE_INBOUND_HOSTNAME ?? c.BUNZZLE_EHLO_NAME]
      : []),
  ].filter((h): h is string => !!h);
  const acme = c.BUNZZLE_ACME_EMAIL
    ? {
        email: c.BUNZZLE_ACME_EMAIL,
        directory: c.BUNZZLE_ACME_DIRECTORY,
        dir: certsDir,
        hosts: [...new Set(acmeHosts.map((h) => h.toLowerCase()))],
      }
    : null;
  if (acme) {
    if (acme.hosts.length === 0) {
      throw new ConfigError(
        "invalid configuration:\n  BUNZZLE_ACME_EMAIL needs the inbound or submission port and a hostname",
      );
    }
  }
  const wantsSubmission =
    c.BUNZZLE_SUBMISSION_PORT !== undefined || c.BUNZZLE_SUBMISSION_TLS_PORT !== undefined;
  const certFile = c.BUNZZLE_SUBMISSION_TLS_CERT_FILE ?? (acme ? `${certsDir}/cert.pem` : null);
  const keyFile = c.BUNZZLE_SUBMISSION_TLS_KEY_FILE ?? (acme ? `${certsDir}/key.pem` : null);
  if (wantsSubmission && (!certFile || !keyFile)) {
    throw new ConfigError(
      "invalid configuration:\n  SMTP submission needs a certificate: set BUNZZLE_SUBMISSION_TLS_CERT_FILE and BUNZZLE_SUBMISSION_TLS_KEY_FILE",
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
    eventLog: c.BUNZZLE_EVENT_LOG
      ? {
          dir: c.BUNZZLE_EVENT_LOG_DIR,
          maxBytes: c.BUNZZLE_EVENT_LOG_MAX_MB * 1024 * 1024,
          keepDays: c.BUNZZLE_EVENT_LOG_DAYS,
        }
      : null,
    inboundHost: c.BUNZZLE_INBOUND_HOST,
    inboundPort: c.BUNZZLE_INBOUND_PORT ?? null,
    retryScale: c.BUNZZLE_RETRY_SCALE,
    publicUrl: c.BUNZZLE_PUBLIC_URL?.replace(/\/+$/, "") ?? null,
    inboundHostname: c.BUNZZLE_INBOUND_HOSTNAME ?? c.BUNZZLE_EHLO_NAME,
    inboundTlsCertFile: c.BUNZZLE_INBOUND_TLS_CERT_FILE ?? (acme ? `${certsDir}/cert.pem` : null),
    inboundTlsKeyFile: c.BUNZZLE_INBOUND_TLS_KEY_FILE ?? (acme ? `${certsDir}/key.pem` : null),
    acme,
    dane: c.BUNZZLE_DANE,
    requiretls: c.BUNZZLE_REQUIRETLS,
    dnsUpdate:
      c.BUNZZLE_DNS_UPDATE_SERVER && c.BUNZZLE_DNS_UPDATE_KEY_NAME && c.BUNZZLE_DNS_UPDATE_KEY_FILE
        ? {
            server: c.BUNZZLE_DNS_UPDATE_SERVER,
            keyName: c.BUNZZLE_DNS_UPDATE_KEY_NAME,
            keyFile: c.BUNZZLE_DNS_UPDATE_KEY_FILE,
            algorithm: c.BUNZZLE_DNS_UPDATE_ALGORITHM,
          }
        : null,
    relay: relayMatch
      ? {
          host: (relayMatch[1] as string).replace(/^\[|\]$/g, ""),
          port: Number(relayMatch[2] ?? 587),
          username: c.BUNZZLE_RELAY_USERNAME,
          passwordFile: c.BUNZZLE_RELAY_PASSWORD_FILE,
        }
      : null,
    tlsrpt: {
      from: c.BUNZZLE_TLSRPT_FROM,
      org: c.BUNZZLE_TLSRPT_ORG ?? c.BUNZZLE_EHLO_NAME ?? "bunzzle",
      contact:
        c.BUNZZLE_TLSRPT_CONTACT ??
        (c.BUNZZLE_TLSRPT_FROM
          ? `mailto:${c.BUNZZLE_TLSRPT_FROM}`
          : (c.BUNZZLE_EHLO_NAME ?? "bunzzle")),
    },
    submission:
      wantsSubmission && certFile && keyFile
        ? {
            host: c.BUNZZLE_SUBMISSION_HOST,
            port: c.BUNZZLE_SUBMISSION_PORT ?? null,
            tlsPort: c.BUNZZLE_SUBMISSION_TLS_PORT ?? null,
            hostname:
              c.BUNZZLE_SUBMISSION_HOSTNAME ?? c.BUNZZLE_INBOUND_HOSTNAME ?? c.BUNZZLE_EHLO_NAME,
            certFile,
            keyFile,
          }
        : null,
    sourceIps: sourceIps(c.BUNZZLE_SOURCE_IPS, c.BUNZZLE_SOURCE_IP, c.BUNZZLE_ESTABLISHED_IPS),
    guardMinVolume: c.BUNZZLE_GUARD_MIN_VOLUME,
    anomalyFloor: c.BUNZZLE_ANOMALY_FLOOR,
    dkimRotateDays: c.BUNZZLE_DKIM_ROTATE_DAYS,
    cloudflareToken: c.BUNZZLE_CLOUDFLARE_API_TOKEN,
    cloudflareTokenFile: c.BUNZZLE_CLOUDFLARE_API_TOKEN_FILE,
    cloudflareUrl: c.BUNZZLE_CLOUDFLARE_API_URL.replace(/\/+$/, ""),
    route53:
      c.BUNZZLE_ROUTE53_ACCESS_KEY_ID && c.BUNZZLE_ROUTE53_SECRET_ACCESS_KEY_FILE
        ? {
            accessKeyId: c.BUNZZLE_ROUTE53_ACCESS_KEY_ID,
            secretKeyFile: c.BUNZZLE_ROUTE53_SECRET_ACCESS_KEY_FILE,
            url: c.BUNZZLE_ROUTE53_API_URL.replace(/\/+$/, ""),
          }
        : null,
    desec: c.BUNZZLE_DESEC_TOKEN_FILE
      ? { tokenFile: c.BUNZZLE_DESEC_TOKEN_FILE, url: c.BUNZZLE_DESEC_API_URL.replace(/\/+$/, "") }
      : null,
  };
}
