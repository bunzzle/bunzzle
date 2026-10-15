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
  signer: ["BUNZZLE_KEYS_DIR", "BUNZZLE_DKIM_KEY_FILE", "BUNZZLE_RETENTION_DAYS"],
  core: ["BUNZZLE_DATA_DIR", "BUNZZLE_RETENTION_DAYS", "BUNZZLE_SOURCE_IP"],
  delivery: [
    "BUNZZLE_EHLO_NAME",
    "BUNZZLE_SOURCE_IP",
    "BUNZZLE_DNS_SERVERS",
    "BUNZZLE_IPV6",
    "BUNZZLE_SMTP_PORT",
    "BUNZZLE_ALLOW_PRIVATE_DESTINATIONS",
  ],
  api: ["BUNZZLE_HOST", "BUNZZLE_PORT"],
  inbound: ["BUNZZLE_INBOUND_HOST", "BUNZZLE_INBOUND_PORT"],
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
