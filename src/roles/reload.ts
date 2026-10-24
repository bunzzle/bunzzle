import { type Config, ConfigError, loadConfig } from "../config.ts";
import type { Logger } from "../core/log.ts";
import type { Role } from "./wire.ts";

export const LIVE: Record<Role, (keyof Config)[]> = {
  signer: ["logLevel", "retentionDays"],
  dns: ["logLevel"],
  link: ["logLevel"],
  core: [
    "logLevel",
    "retentionDays",
    "guardMinVolume",
    "anomalyFloor",
    "dkimRotateDays",
    "minFreeMb",
    "relay",
  ],
  delivery: ["logLevel"],
  api: ["logLevel"],
  inbound: ["logLevel"],
  ns: ["logLevel"],
};

export function parseEnvFile(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || line.startsWith(";")) continue;
    const m = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(line);
    if (!m) continue;
    let value = m[2] as string;
    const quote = value[0];
    if ((quote === '"' || quote === "'") && value.endsWith(quote) && value.length >= 2) {
      value = value.slice(1, -1);
      if (quote === '"') value = value.replace(/\\(["\\$`])/g, "$1");
    }
    out[m[1] as string] = value;
  }
  return out;
}

const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);

export interface Reloaded {
  applied: string[];
  needRestart: string[];
}

export class Reloader {
  #fileKeys: Set<string>;

  constructor(
    private readonly role: Role,
    private readonly config: Config,
    private readonly log: Logger,
    private readonly env: Record<string, string | undefined>,
    private readonly read: (path: string) => Promise<string> = (path) => Bun.file(path).text(),
    initialFile: Record<string, string> = {},
  ) {
    this.#fileKeys = new Set(Object.keys(initialFile));
  }

  static async start(
    role: Role,
    config: Config,
    log: Logger,
    env: Record<string, string | undefined> = Bun.env,
  ): Promise<Reloader> {
    const path = env["BUNZZLE_ENV_FILE"];
    const initial = path
      ? parseEnvFile(
          await Bun.file(path)
            .text()
            .catch(() => ""),
        )
      : {};
    return new Reloader(role, config, log, env, undefined, initial);
  }

  async reload(): Promise<Reloaded | null> {
    const path = this.env["BUNZZLE_ENV_FILE"];
    if (!path) {
      this.log.warn("reload needs BUNZZLE_ENV_FILE: the configuration was not reloaded");
      return null;
    }
    let file: Record<string, string>;
    try {
      file = parseEnvFile(await this.read(path));
    } catch (err) {
      this.log.error("configuration not reloaded: the file cannot be read", {
        file: path,
        error: (err as Error).message,
      });
      return null;
    }
    const base: Record<string, string | undefined> = { ...this.env };
    for (const key of this.#fileKeys) delete base[key];
    let next: Config;
    try {
      next = loadConfig({ ...base, ...file });
    } catch (err) {
      this.log.error("configuration not reloaded: it is not valid", {
        error: err instanceof ConfigError ? err.message : (err as Error).message,
      });
      return null;
    }
    this.#fileKeys = new Set(Object.keys(file));
    const live = new Set(LIVE[this.role]);
    const applied: string[] = [];
    const needRestart: string[] = [];
    for (const key of Object.keys(next) as (keyof Config)[]) {
      if (same(this.config[key], next[key])) continue;
      if (live.has(key)) {
        (this.config as unknown as Record<string, unknown>)[key] = next[key];
        applied.push(key);
      } else {
        needRestart.push(key);
      }
    }
    if (applied.includes("logLevel")) this.log.setLevel(this.config.logLevel);
    this.log.info("configuration reloaded", {
      changed: applied,
      ...(needRestart.length ? { need_restart: needRestart } : {}),
    });
    if (needRestart.length) {
      this.log.warn("some changed settings take effect only after a restart of this role", {
        settings: needRestart,
      });
    }
    return { applied, needRestart };
  }
}
