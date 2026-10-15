#!/usr/bin/env bun
import { ConfigError, loadConfig } from "../config.ts";
import { createLogger } from "../core/log.ts";
import { generateMasterKey, MasterKeyError } from "../crypto/master.ts";
import { KeyFileError } from "../dkim/keys.ts";
import { AddressError } from "../mime/address.ts";
import { MimeError } from "../mime/builder.ts";
import { runApi } from "../roles/api.ts";
import { runCore } from "../roles/core.ts";
import { runDelivery } from "../roles/delivery.ts";
import { runInbound } from "../roles/inbound.ts";
import { runSigner } from "../roles/signer.ts";
import { runSupervisor } from "../roles/supervisor.ts";
import { ROLES, type Role } from "../roles/wire.ts";
import { VERSION } from "../version.ts";
import { UsageError } from "./args.ts";
import { dkimCommand } from "./dkim.ts";
import { sendCommand } from "./send.ts";

const USAGE = `bunzzle ${VERSION}

Usage:
  bunzzle serve       Start Bunzzle (five sandboxed roles: api, core, delivery, signer, inbound)
  bunzzle send        Send one email straight to the recipients' mail servers
  bunzzle dkim        Create DKIM keys and print their DNS records
  bunzzle master-key  Print a new random master key
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
  BUNZZLE_INBOUND_PORT    port for incoming mail (off by default)
`;

async function serve() {
  const config = loadConfig();
  const log = createLogger(config.logLevel, { service: "bunzzle", role: "supervisor" });
  log.info("starting", { version: VERSION });
  await runSupervisor(config, log);
}

async function role(name: string | undefined) {
  if (!ROLES.includes(name as Role)) throw new UsageError(`unknown role: ${name}`);
  const config = loadConfig();
  const log = createLogger(config.logLevel, { service: "bunzzle", role: name });
  switch (name as Role) {
    case "signer":
      return runSigner(config, log, (await Bun.stdin.text()).trim());
    case "core":
      return runCore(config, log);
    case "delivery":
      return runDelivery(config, log);
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
    case "master-key":
      console.log(generateMasterKey());
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
