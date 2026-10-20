#!/usr/bin/env bun
import { type Config, ConfigError, loadConfig } from "../config.ts";
import { createLogger } from "../core/log.ts";
import { readMasterKeyText } from "../crypto/load.ts";
import { generateMasterKey, MasterKeyError } from "../crypto/master.ts";
import { KeyFileError } from "../dkim/keys.ts";
import { openApi } from "../http/openapi.ts";
import { AddressError } from "../mime/address.ts";
import { MimeError } from "../mime/builder.ts";
import { runApi } from "../roles/api.ts";
import { runCore } from "../roles/core.ts";
import { runDelivery } from "../roles/delivery.ts";
import { runDns } from "../roles/dns.ts";
import { runInbound } from "../roles/inbound.ts";
import { Reloader } from "../roles/reload.ts";
import { runSigner } from "../roles/signer.ts";
import { runSupervisor } from "../roles/supervisor.ts";
import { ROLES, type Role } from "../roles/wire.ts";
import { VERSION } from "../version.ts";
import {
  doctorCommand,
  domainsCommand,
  emailsCommand,
  holdsCommand,
  ipsCommand,
  keysCommand,
  pathsCommand,
  queueCommand,
  routesCommand,
  statsCommand,
  suppressionsCommand,
  webhooksCommand,
} from "./admin.ts";
import { UsageError } from "./args.ts";
import { backupCommand, restoreCommand } from "./backup.ts";
import { dkimCommand } from "./dkim.ts";
import { dnsTestCommand } from "./dnstest.ts";
import { postmasterCommand } from "./postmaster.ts";
import { sendCommand } from "./send.ts";

const USAGE = `bunzzle ${VERSION}

Usage:
  bunzzle serve       Start Bunzzle (six sandboxed roles: api, core, delivery, dns, signer, inbound)
  bunzzle send        Send one email straight to the recipients' mail servers
  bunzzle dkim        Create DKIM keys and print their DNS records
  bunzzle master-key  Print a new random master key
  bunzzle openapi     Print the OpenAPI description of the API
  bunzzle domains     add|verify|show|list|reports sending domains and their DMARC reports (needs \`serve\` running)
  bunzzle keys        create|list|revoke API keys (needs \`serve\` running)
  bunzzle paths       sending speed per destination and why it changed (needs \`serve\` running)
  bunzzle webhooks    add|list|remove event webhooks (needs \`serve\` running)
  bunzzle routes      add|list|remove|retry inbound routes: mail for an address posted to a URL (needs \`serve\` running)
  bunzzle ips         source IPs, reverse DNS and warm-up progress (needs \`serve\` running)
  bunzzle doctor      check configuration, IPs, every DNS record and DKIM against live DNS
  bunzzle dns-test    DOMAIN: publish a test record through the DNS provider, check it, remove it
  bunzzle postmaster  auth: sign in once to read Gmail spam rates from Postmaster Tools
  bunzzle holds       bulk mail paused by the reputation or anomaly guard; release ID (needs \`serve\` running)
  bunzzle suppressions list|add|remove suppressed addresses (needs \`serve\` running)
  bunzzle emails      list: search emails by recipient, status, tag or domain (needs \`serve\` running)
  bunzzle stats       sent, delivered, deferred, bounced and complaints per day (needs \`serve\` running)
  bunzzle queue       what is waiting per destination; suspend|resume a destination; fail|cancel queued email (needs \`serve\` running)
  bunzzle backup      --to DIR: copy the database and keys, safe while Bunzzle runs
  bunzzle restore     --from DIR: put a backup back (stop \`serve\` first, needs the same master key)
  bunzzle --version   Print the version
  bunzzle --help      Show this help

bunzzle send:
  --from "Name <you@your.domain>"   sender (its domain must match the DKIM keys)
  --to, --cc, --bcc ADDRESS         repeat for several recipients
  --subject TEXT
  --text TEXT | --text-file PATH    plain text body
  --html TEXT | --html-file PATH    HTML body
  --attach PATH                     repeat for several files
  --reply-to ADDRESS
  --dkim-keys PATH                  key file from \`bunzzle dkim keygen\`
  --unsigned                        send without DKIM (most providers will reject it)
  --ehlo NAME                       reverse DNS name of the sending IP
  --source-ip IP                    send from this local IP
  --require-tls                     only deliver over TLS with a valid certificate
  --dry-run                         print the signed message instead of sending
  --json                            print the delivery report as JSON

bunzzle domains:
  add DOMAIN        create DKIM keys and print the DNS records to publish
  verify DOMAIN     check the DNS records now
  show DOMAIN | list
  rotate DOMAIN     start or continue DKIM key rotation (automatic every BUNZZLE_DKIM_ROTATE_DAYS)
  pool DOMAIN POOL  send only from the IPs in POOL (from BUNZZLE_SOURCE_IPS); none for the shared IPs
  tracking DOMAIN HOST [--opens] [--clicks]   track through HOST (a CNAME to BUNZZLE_PUBLIC_URL); none to stop

bunzzle keys:
  create --name NAME [--scope send|read|full] [--domain DOMAIN] [--rate-limit N] [--test] [--pool POOL]
  list | revoke ID

API (bunzzle serve):
  POST /emails            Idempotency-Key header; fields include expires_at, require_tls, lane
  GET  /paths             sending speed per destination, limits and recent changes
  GET|POST /webhooks, DELETE /webhooks/:id     signed in the Standard Webhooks format
  GET|POST /routes, DELETE /routes/:id, POST /routes/:id/retry   inbound mail to a URL
  GET|POST /suppressions, DELETE /suppressions/:email
  GET|POST /u/:token      one-click unsubscribe (public, added to bulk email)
  GET  /o/:token, /c/:token/:url   open and click tracking (public, signed)
  GET  /emails            search: to, status, tag, domain, since, until, limit, cursor
  GET  /emails/:id        status per recipient, every attempt with MX, TLS and the reply
  GET  /stats             per day: since, until, domain, tag
  GET|POST /domains, GET|PATCH /domains/:name, POST /domains/:name/verify

bunzzle dkim:
  keygen --domain DOMAIN --out PATH [--selector NAME] [--force] [--unencrypted]
  records --keys PATH

Configuration (environment variables):
  BUNZZLE_HOST        default 127.0.0.1
  BUNZZLE_PORT        default 3000
  BUNZZLE_DATA_DIR    default ./data
  BUNZZLE_LOG_LEVEL   debug | info | warn | error (default info)
  BUNZZLE_EHLO_NAME   default for --ehlo
  BUNZZLE_SOURCE_IP   default for --source-ip
  BUNZZLE_DKIM_KEY_FILE  default for --dkim-keys
  BUNZZLE_DNS_SERVERS comma-separated resolvers (default: /etc/resolv.conf)
  BUNZZLE_IPV6        also deliver over IPv6 (needs reverse DNS for the IPv6 address)
  BUNZZLE_MASTER_KEY  or BUNZZLE_MASTER_KEY_FILE: encrypts DKIM keys and every email body
  BUNZZLE_KEYS_DIR    signer's directory (default ./keys; DKIM key files go in keys/dkim/)
  BUNZZLE_RUN_DIR     sockets between the roles (default ./run)
  BUNZZLE_RETENTION_DAYS  email bodies become unreadable after this (default 30, min 7)
  BUNZZLE_INBOUND_PORT    port for bounces and feedback (off by default; 25 in production)
  BUNZZLE_INBOUND_HOSTNAME  name of this server for bounce MX records (default: EHLO name)
  BUNZZLE_INBOUND_TLS_CERT_FILE, BUNZZLE_INBOUND_TLS_KEY_FILE  PEM files: offer STARTTLS on the inbound port
  BUNZZLE_PUBLIC_URL      https URL of the API, used in unsubscribe links
`;

async function serve() {
  const config = loadConfig();
  const log = createLogger(config.logLevel, { service: "bunzzle", role: "supervisor" });
  log.info("starting", { version: VERSION });
  await runSupervisor(config, log);
}

async function signerMasterKey(config: Config): Promise<string> {
  const piped = (await Bun.stdin.text()).trim();
  if (piped) return piped;
  const text = await readMasterKeyText(config);
  if (!text) {
    throw new ConfigError(
      "the signer needs the master key: on its standard input from `bunzzle serve`, or BUNZZLE_MASTER_KEY_FILE",
    );
  }
  return text;
}

async function role(name: string | undefined) {
  if (!ROLES.includes(name as Role)) throw new UsageError(`unknown role: ${name}`);
  const config = loadConfig();
  const log = createLogger(config.logLevel, { service: "bunzzle", role: name });
  const reloader = await Reloader.start(name as Role, config, log);
  process.on("SIGHUP", () => void reloader.reload());
  switch (name as Role) {
    case "signer":
      return runSigner(config, log, await signerMasterKey(config));
    case "core":
      return runCore(config, log);
    case "delivery":
      return runDelivery(config, log);
    case "dns":
      return runDns(config, log);
    case "api":
      return runApi(config, log);
    case "inbound":
      return runInbound(config, log);
  }
}

async function main(argv: string[]) {
  const [command] = argv;
  switch (command) {
    case "serve":
      return serve();
    case "role":
      return role(argv[1]);
    case "send":
      process.exitCode = await sendCommand(argv.slice(1), loadConfig());
      return;
    case "dkim":
      return dkimCommand(argv.slice(1), loadConfig());
    case "domains":
      return domainsCommand(argv.slice(1), loadConfig());
    case "keys":
      return keysCommand(argv.slice(1), loadConfig());
    case "paths":
      return pathsCommand(argv.slice(1), loadConfig());
    case "doctor":
      process.exitCode = await doctorCommand(argv.slice(1), loadConfig());
      return;
    case "dns-test":
      process.exitCode = await dnsTestCommand(argv.slice(1), loadConfig());
      return;
    case "postmaster":
      process.exitCode = await postmasterCommand(argv.slice(1), loadConfig());
      return;
    case "ips":
      return ipsCommand(argv.slice(1), loadConfig());
    case "holds":
      return holdsCommand(argv.slice(1), loadConfig());
    case "webhooks":
      return webhooksCommand(argv.slice(1), loadConfig());
    case "routes":
      return routesCommand(argv.slice(1), loadConfig());
    case "suppressions":
      return suppressionsCommand(argv.slice(1), loadConfig());
    case "emails":
      return emailsCommand(argv.slice(1), loadConfig());
    case "stats":
      return statsCommand(argv.slice(1), loadConfig());
    case "queue":
      return queueCommand(argv.slice(1), loadConfig());
    case "backup":
      return backupCommand(argv.slice(1), loadConfig());
    case "restore":
      return restoreCommand(argv.slice(1), loadConfig());
    case "master-key":
      console.log(generateMasterKey());
      return;
    case "openapi":
      console.log(JSON.stringify(openApi(), null, 2));
      return;
    case "--version":
    case "-v":
      console.log(VERSION);
      return;
    case undefined:
    case "--help":
    case "-h":
      console.log(USAGE);
      return;
    default:
      console.error(`unknown command: ${command}\n\n${USAGE}`);
      process.exit(2);
  }
}

main(Bun.argv.slice(2)).catch((err) => {
  if (
    err instanceof ConfigError ||
    err instanceof UsageError ||
    err instanceof AddressError ||
    err instanceof MimeError ||
    err instanceof KeyFileError ||
    err instanceof MasterKeyError
  ) {
    console.error(err.message);
    process.exit(2);
  }
  console.error(err);
  process.exit(1);
});
