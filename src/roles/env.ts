import type { Role } from "./wire.ts";

const COMMON = [
  "PATH",
  "HOME",
  "TMPDIR",
  "LANG",
  "BUNZZLE_LOG_LEVEL",
  "BUNZZLE_RUN_DIR",
  "BUNZZLE_RETRY_SCALE",
];

const BY_ROLE: Record<Role, string[]> = {
  signer: [
    "BUNZZLE_KEYS_DIR",
    "BUNZZLE_DKIM_KEY_FILE",
    "BUNZZLE_RETENTION_DAYS",
    "BUNZZLE_PUBLIC_URL",
  ],
  core: [
    "BUNZZLE_DATA_DIR",
    "BUNZZLE_RETENTION_DAYS",
    "BUNZZLE_SOURCE_IP",
    "BUNZZLE_EHLO_NAME",
    "BUNZZLE_INBOUND_HOSTNAME",
    "BUNZZLE_PUBLIC_URL",
    "BUNZZLE_SOURCE_IPS",
    "BUNZZLE_ESTABLISHED_IPS",
    "BUNZZLE_GUARD_MIN_VOLUME",
    "BUNZZLE_ANOMALY_FLOOR",
    "BUNZZLE_DKIM_ROTATE_DAYS",
  ],
  delivery: [
    "BUNZZLE_EHLO_NAME",
    "BUNZZLE_SOURCE_IP",
    "BUNZZLE_DNS_SERVERS",
    "BUNZZLE_IPV6",
    "BUNZZLE_SMTP_PORT",
    "BUNZZLE_ALLOW_PRIVATE_DESTINATIONS",
    "BUNZZLE_SOURCE_IPS",
  ],
  dns: [
    "BUNZZLE_DNS_SERVERS",
    "BUNZZLE_ALLOW_PRIVATE_DESTINATIONS",
    "BUNZZLE_CLOUDFLARE_API_TOKEN",
    "BUNZZLE_CLOUDFLARE_API_TOKEN_FILE",
    "BUNZZLE_CLOUDFLARE_API_URL",
  ],
  api: [
    "BUNZZLE_HOST",
    "BUNZZLE_PORT",
    "BUNZZLE_PUBLIC_URL",
    "BUNZZLE_EHLO_NAME",
    "BUNZZLE_INBOUND_HOSTNAME",
    "BUNZZLE_SUBMISSION_HOST",
    "BUNZZLE_SUBMISSION_PORT",
    "BUNZZLE_SUBMISSION_TLS_PORT",
    "BUNZZLE_SUBMISSION_HOSTNAME",
    "BUNZZLE_SUBMISSION_TLS_CERT_FILE",
    "BUNZZLE_SUBMISSION_TLS_KEY_FILE",
  ],
  inbound: [
    "BUNZZLE_INBOUND_HOST",
    "BUNZZLE_INBOUND_PORT",
    "BUNZZLE_INBOUND_HOSTNAME",
    "BUNZZLE_EHLO_NAME",
    "BUNZZLE_INBOUND_TLS_CERT_FILE",
    "BUNZZLE_INBOUND_TLS_KEY_FILE",
  ],
};

export function roleEnv(
  role: Role,
  env: Record<string, string | undefined>,
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const key of [...COMMON, ...BY_ROLE[role]]) {
    const value = env[key];
    if (value !== undefined) out[key] = value;
  }
  return out;
}
