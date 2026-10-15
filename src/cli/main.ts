#!/usr/bin/env bun
import { ConfigError, loadConfig } from "../config.ts";
import { createLogger } from "../core/log.ts";
import { openDatabase } from "../core/store/db.ts";
import { KeyFileError } from "../dkim/keys.ts";
import { startServer } from "../http/server.ts";
import { AddressError } from "../mime/address.ts";
import { MimeError } from "../mime/builder.ts";
import { VERSION } from "../version.ts";
import { UsageError } from "./args.ts";
import { dkimCommand } from "./dkim.ts";
import { sendCommand } from "./send.ts";

const USAGE = `bunzzle ${VERSION}

Usage:
  bunzzle serve       Start the API server
  bunzzle send        Send one email straight to the recipients' mail servers
  bunzzle dkim        Create DKIM keys and print their DNS records
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
  keygen --domain DOMAIN --out PATH [--selector NAME] [--force]
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
`;

async function serve() {
  const config = loadConfig();
  const log = createLogger(config.logLevel, { service: "bunzzle" });

  await Bun.$`mkdir -p ${config.dataDir}`.quiet();
  const db = openDatabase({ path: config.dbPath });
  const server = startServer({ db, log, host: config.host, port: config.port });
  log.info("listening", { url: server.url.href, version: VERSION, db: config.dbPath });

  let stopping = false;
  const shutdown = async (signal: string) => {
    if (stopping) return;
    stopping = true;
    log.info("shutting down", { signal });
    await server.stop();
    db.close();
    process.exit(0);
  };
  process.on("SIGINT", () => void shutdown("SIGINT"));
  process.on("SIGTERM", () => void shutdown("SIGTERM"));
}

async function main(argv: string[]) {
  const [command] = argv;
  switch (command) {
    case "serve":
      return serve();
    case "send":
      process.exitCode = await sendCommand(argv.slice(1), loadConfig());
      return;
    case "dkim":
      return dkimCommand(argv.slice(1));
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
    err instanceof KeyFileError
  ) {
    console.error(err.message);
    process.exit(2);
  }
  console.error(err);
  process.exit(1);
});
