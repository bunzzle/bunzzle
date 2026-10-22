import { familyOf } from "./dns/ip.ts";
import { blocklists } from "./ips/blocklists.ts";
import { b } from "./validate/schema.ts";

const INBOUND_BLOCKLISTS = blocklists(null).map((l) => l.id);
const INBOUND_REFUSE = ["spf", "dmarc", "blocklist"];

const bool = b
  .enum(["true", "false", "1", "0"])
  .default("false")
  .transform((v) => v === "true" || v === "1");

const boolOn = b
  .enum(["true", "false", "1", "0"])
  .default("true")
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
  BUNZZLE_DKIM_STORE_SOCKET: optional,
  BUNZZLE_DKIM_STORE_MOUNT: b
    .string()
    .regex(/^[A-Za-z0-9_-]+(\/[A-Za-z0-9_-]+)*$/)
    .default("transit"),
  BUNZZLE_IPV6: bool,
  BUNZZLE_SMTP_PORT: b.coerce.number().int().min(1).max(65535).default(25),
  BUNZZLE_ALLOW_PRIVATE_DESTINATIONS: bool,
  BUNZZLE_MASTER_KEY: optional,
  BUNZZLE_MASTER_KEY_FILE: optional,
  BUNZZLE_KEYS_DIR: b.string().min(1).default("./keys"),
  BUNZZLE_RUN_DIR: b.string().min(1).default("./run"),
  BUNZZLE_RETENTION_DAYS: b.coerce.number().int().min(7).max(3650).default(30),
  BUNZZLE_MIN_FREE_MB: b.coerce.number().int().min(0).default(1024),
  BUNZZLE_EVENT_LOG: bool,
  BUNZZLE_SHARED_BOUNCES: boolOn,
  BUNZZLE_EVENT_LOG_DIR: b.string().min(1).default("./logs/events"),
  BUNZZLE_EVENT_LOG_MAX_MB: b.coerce.number().int().min(1).max(100_000).default(100),
  BUNZZLE_EVENT_LOG_DAYS: b.coerce.number().int().min(1).max(3650).default(30),
  BUNZZLE_INBOUND_HOST: b.string().min(1).default("0.0.0.0"),
  BUNZZLE_INBOUND_PORT: b.coerce.number().int().min(0).max(65535).optional(),
  BUNZZLE_INBOUND_MAX_SIZE: b.coerce
    .number()
    .int()
    .min(64 * 1024)
    .max(40 * 1024 * 1024)
    .default(10 * 1024 * 1024),
  BUNZZLE_RETRY_SCALE: b.coerce.number().positive().max(1).default(1),
  BUNZZLE_TRACK_HOST: b.string().min(1).default("0.0.0.0"),
  BUNZZLE_TRACK_PORT: b.coerce.number().int().min(0).max(65535).optional(),
  BUNZZLE_PUBLIC_URL: optional.refine((v) => v === null || /^https?:\/\/[^\s/]+/.test(v), {
    message: "must be an http(s) URL like https://mail.example.com",
  }),
  BUNZZLE_INBOUND_HOSTNAME: optional,
  BUNZZLE_INBOUND_BLOCKLISTS: b.string().default(""),
  BUNZZLE_INBOUND_REFUSE: b.string().default(""),
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
  BUNZZLE_RELAY_FOR: b.string().default("all"),
  BUNZZLE_SPAMHAUS_KEY_FILE: optional,
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
  BUNZZLE_POSTMASTER_CLIENT_ID: optional,
  BUNZZLE_POSTMASTER_CLIENT_SECRET_FILE: optional,
  BUNZZLE_POSTMASTER_REFRESH_TOKEN_FILE: optional,
  BUNZZLE_POSTMASTER_API_URL: b
    .string()
    .url()
    .default("https://gmailpostmastertools.googleapis.com"),
  BUNZZLE_POSTMASTER_TOKEN_URL: b.string().url().default("https://oauth2.googleapis.com/token"),
  BUNZZLE_NS_ZONE: optional,
  BUNZZLE_NS_NAMES: optional,
  BUNZZLE_NS_LISTEN: optional,
  BUNZZLE_NS_PORT: b.coerce.number().int().min(0).max(65535).default(53),
  BUNZZLE_NS_RRL_V4_PREFIX: b.coerce.number().int().min(8).max(32).default(24),
  BUNZZLE_NS_RRL_V6_PREFIX: b.coerce.number().int().min(16).max(128).default(56),
  BUNZZLE_NS_RRL_SLIP: b.coerce.number().int().min(0).max(10).default(0),
  BUNZZLE_NS_TTL: b.coerce.number().int().min(60).max(86400).default(300),
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
  dkimStore: { socket: string; mount: string } | null;
  ipv6: boolean;
  smtpPort: number;
  allowPrivateDestinations: boolean;
  masterKey: string | null;
  masterKeyFile: string | null;
  keysDir: string;
  runDir: string;
  retentionDays: number;
  minFreeMb: number;
  eventLog: { dir: string; maxBytes: number; keepDays: number } | null;
  inboundHost: string;
  inboundPort: number | null;
  inboundMaxSize: number;
  retryScale: number;
  publicUrl: string | null;
  track: { host: string; port: number; dir: string } | null;
  inboundHostname: string | null;
  inboundBlocklists: string[];
  inboundRefuse: ("spf" | "dmarc" | "blocklist")[];
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
    for: { all: boolean; blocked: boolean; targets: string[] };
  } | null;
  spamhausKeyFile: string | null;
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
  sharedBounces: boolean;
  dkimRotateDays: number;
  cloudflareToken: string | null;
  cloudflareTokenFile: string | null;
  cloudflareUrl: string;
  route53: { accessKeyId: string; secretKeyFile: string; url: string } | null;
  desec: { tokenFile: string; url: string } | null;
  ns: {
    zone: string;
    names: string[];
    listen: string[];
    port: number;
    v4Prefix: number;
    v6Prefix: number;
    slip: number;
    ttl: number;
  } | null;
  postmaster: {
    clientId: string;
    clientSecretFile: string;
    refreshTokenFile: string;
    apiUrl: string;
    tokenUrl: string;
  } | null;
}

export class ConfigError extends Error {}

const HOSTNAME =
  /^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?)(\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;

function list(value: string | null): string[] {
  return (value ?? "")
    .split(",")
    .map((s) => s.trim().toLowerCase().replace(/\.$/, ""))
    .filter(Boolean);
}

function nsConfig(c: {
  BUNZZLE_NS_ZONE: string | null;
  BUNZZLE_NS_NAMES: string | null;
  BUNZZLE_NS_LISTEN: string | null;
  BUNZZLE_NS_PORT: number;
  BUNZZLE_NS_RRL_V4_PREFIX: number;
  BUNZZLE_NS_RRL_V6_PREFIX: number;
  BUNZZLE_NS_RRL_SLIP: number;
  BUNZZLE_NS_TTL: number;
}): Config["ns"] {
  const names = list(c.BUNZZLE_NS_NAMES);
  const listen = list(c.BUNZZLE_NS_LISTEN);
  if (!c.BUNZZLE_NS_ZONE) {
    if (names.length > 0 || listen.length > 0) {
      throw new ConfigError(
        "invalid configuration:\n  BUNZZLE_NS_NAMES and BUNZZLE_NS_LISTEN need BUNZZLE_NS_ZONE",
      );
    }
    return null;
  }
  const zone = list(c.BUNZZLE_NS_ZONE)[0] ?? "";
  if (!HOSTNAME.test(zone)) {
    throw new ConfigError(
      `invalid configuration:\n  BUNZZLE_NS_ZONE: ${zone} is not a domain name`,
    );
  }
  if (names.length === 0 || listen.length === 0) {
    throw new ConfigError(
      "invalid configuration:\n  BUNZZLE_NS_ZONE needs BUNZZLE_NS_NAMES and BUNZZLE_NS_LISTEN",
    );
  }
  for (const n of names) {
    if (!HOSTNAME.test(n)) {
      throw new ConfigError(`invalid configuration:\n  BUNZZLE_NS_NAMES: ${n} is not a host name`);
    }
    if (n === zone || n.endsWith(`.${zone}`)) {
      throw new ConfigError(
        `invalid configuration:\n  BUNZZLE_NS_NAMES: ${n} must be outside BUNZZLE_NS_ZONE`,
      );
    }
  }
  for (const ip of listen) {
    if (!familyOf(ip)) {
      throw new ConfigError(
        `invalid configuration:\n  BUNZZLE_NS_LISTEN: ${ip} is not an IP address`,
      );
    }
  }
  return {
    zone,
    names,
    listen,
    port: c.BUNZZLE_NS_PORT,
    v4Prefix: c.BUNZZLE_NS_RRL_V4_PREFIX,
    v6Prefix: c.BUNZZLE_NS_RRL_V6_PREFIX,
    slip: c.BUNZZLE_NS_RRL_SLIP,
    ttl: c.BUNZZLE_NS_TTL,
  };
}

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
  const postmaster = [
    c.BUNZZLE_POSTMASTER_CLIENT_ID,
    c.BUNZZLE_POSTMASTER_CLIENT_SECRET_FILE,
    c.BUNZZLE_POSTMASTER_REFRESH_TOKEN_FILE,
  ];
  if (postmaster.some(Boolean) && !postmaster.every(Boolean)) {
    throw new ConfigError(
      "invalid configuration:\n  Postmaster Tools needs BUNZZLE_POSTMASTER_CLIENT_ID, BUNZZLE_POSTMASTER_CLIENT_SECRET_FILE and BUNZZLE_POSTMASTER_REFRESH_TOKEN_FILE together",
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
  const relayFor = c.BUNZZLE_RELAY_FOR.split(",")
    .map((x) => x.trim().toLowerCase().replace(/\.$/, ""))
    .filter(Boolean);
  if (
    relayFor.length === 0 ||
    (relayFor.includes("all") && relayFor.length > 1) ||
    relayFor.some((x) => !/^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/.test(x))
  ) {
    throw new ConfigError(
      "invalid configuration:\n  BUNZZLE_RELAY_FOR is all, or a comma-separated list of domains, providers and blocked",
    );
  }
  if (c.BUNZZLE_RELAY_FOR !== "all" && !c.BUNZZLE_RELAY_HOST) {
    throw new ConfigError("invalid configuration:\n  BUNZZLE_RELAY_FOR needs BUNZZLE_RELAY_HOST");
  }
  const words = (v: string) =>
    v
      .split(",")
      .map((x) => x.trim().toLowerCase())
      .filter(Boolean);
  const inboundBlocklists = words(c.BUNZZLE_INBOUND_BLOCKLISTS);
  if (inboundBlocklists.some((x) => !INBOUND_BLOCKLISTS.includes(x))) {
    throw new ConfigError(
      `invalid configuration:\n  BUNZZLE_INBOUND_BLOCKLISTS is a comma-separated list of ${INBOUND_BLOCKLISTS.join(", ")}`,
    );
  }
  const inboundRefuse = words(c.BUNZZLE_INBOUND_REFUSE);
  if (inboundRefuse.some((x) => !INBOUND_REFUSE.includes(x))) {
    throw new ConfigError(
      `invalid configuration:\n  BUNZZLE_INBOUND_REFUSE is a comma-separated list of ${INBOUND_REFUSE.join(", ")}`,
    );
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
  if (c.BUNZZLE_TRACK_PORT !== undefined && !c.BUNZZLE_PUBLIC_URL) {
    throw new ConfigError("invalid configuration:\n  BUNZZLE_TRACK_PORT needs BUNZZLE_PUBLIC_URL");
  }
  if (acme) {
    if (acme.hosts.length === 0 && c.BUNZZLE_TRACK_PORT === undefined) {
      throw new ConfigError(
        "invalid configuration:\n  BUNZZLE_ACME_EMAIL needs the inbound, submission or tracking port and a hostname",
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
    dkimStore: c.BUNZZLE_DKIM_STORE_SOCKET
      ? { socket: c.BUNZZLE_DKIM_STORE_SOCKET, mount: c.BUNZZLE_DKIM_STORE_MOUNT }
      : null,
    ipv6: c.BUNZZLE_IPV6,
    smtpPort: c.BUNZZLE_SMTP_PORT,
    allowPrivateDestinations: c.BUNZZLE_ALLOW_PRIVATE_DESTINATIONS,
    masterKey: c.BUNZZLE_MASTER_KEY,
    masterKeyFile: c.BUNZZLE_MASTER_KEY_FILE,
    keysDir: c.BUNZZLE_KEYS_DIR.replace(/\/+$/, ""),
    runDir: c.BUNZZLE_RUN_DIR.replace(/\/+$/, ""),
    retentionDays: c.BUNZZLE_RETENTION_DAYS,
    minFreeMb: c.BUNZZLE_MIN_FREE_MB,
    eventLog: c.BUNZZLE_EVENT_LOG
      ? {
          dir: c.BUNZZLE_EVENT_LOG_DIR,
          maxBytes: c.BUNZZLE_EVENT_LOG_MAX_MB * 1024 * 1024,
          keepDays: c.BUNZZLE_EVENT_LOG_DAYS,
        }
      : null,
    inboundHost: c.BUNZZLE_INBOUND_HOST,
    inboundPort: c.BUNZZLE_INBOUND_PORT ?? null,
    inboundMaxSize: c.BUNZZLE_INBOUND_MAX_SIZE,
    retryScale: c.BUNZZLE_RETRY_SCALE,
    publicUrl: c.BUNZZLE_PUBLIC_URL?.replace(/\/+$/, "") ?? null,
    track:
      c.BUNZZLE_TRACK_PORT !== undefined
        ? { host: c.BUNZZLE_TRACK_HOST, port: c.BUNZZLE_TRACK_PORT, dir: `${certsDir}/track` }
        : null,
    inboundHostname: c.BUNZZLE_INBOUND_HOSTNAME ?? c.BUNZZLE_EHLO_NAME,
    inboundBlocklists,
    inboundRefuse: inboundRefuse as Config["inboundRefuse"],
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
          for: {
            all: relayFor.includes("all"),
            blocked: relayFor.includes("blocked"),
            targets: relayFor.filter((x) => x !== "all" && x !== "blocked"),
          },
        }
      : null,
    spamhausKeyFile: c.BUNZZLE_SPAMHAUS_KEY_FILE,
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
    sharedBounces: c.BUNZZLE_SHARED_BOUNCES,
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
    ns: nsConfig(c),
    postmaster:
      c.BUNZZLE_POSTMASTER_CLIENT_ID &&
      c.BUNZZLE_POSTMASTER_CLIENT_SECRET_FILE &&
      c.BUNZZLE_POSTMASTER_REFRESH_TOKEN_FILE
        ? {
            clientId: c.BUNZZLE_POSTMASTER_CLIENT_ID,
            clientSecretFile: c.BUNZZLE_POSTMASTER_CLIENT_SECRET_FILE,
            refreshTokenFile: c.BUNZZLE_POSTMASTER_REFRESH_TOKEN_FILE,
            apiUrl: c.BUNZZLE_POSTMASTER_API_URL.replace(/\/+$/, ""),
            tokenUrl: c.BUNZZLE_POSTMASTER_TOKEN_URL,
          }
        : null,
    desec: c.BUNZZLE_DESEC_TOKEN_FILE
      ? { tokenFile: c.BUNZZLE_DESEC_TOKEN_FILE, url: c.BUNZZLE_DESEC_API_URL.replace(/\/+$/, "") }
      : null,
  };
}
