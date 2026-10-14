#!/usr/bin/env bun
import { ConfigError, loadConfig } from "../config.ts";
import { createLogger } from "../core/log.ts";
import { openDatabase } from "../core/store/db.ts";
import { startServer } from "../http/server.ts";
import { VERSION } from "../version.ts";

const USAGE = `bunzzle ${VERSION}

Usage:
  bunzzle serve       Start the API server
  bunzzle --version   Print the version
  bunzzle --help      Show this help

Configuration (environment variables):
  BUNZZLE_HOST        default 127.0.0.1
  BUNZZLE_PORT        default 3000
  BUNZZLE_DATA_DIR    default ./data
  BUNZZLE_LOG_LEVEL   debug | info | warn | error (default info)
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
  if (err instanceof ConfigError) {
    console.error(err.message);
    process.exit(2);
  }
  console.error(err);
  process.exit(1);
});
