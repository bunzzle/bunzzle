import { z } from "zod";

const schema = z.object({
  BUNZZLE_HOST: z.string().min(1).default("127.0.0.1"),
  BUNZZLE_PORT: z.coerce.number().int().min(0).max(65535).default(3000),
  BUNZZLE_DATA_DIR: z.string().min(1).default("./data"),
  BUNZZLE_LOG_LEVEL: z.enum(["debug", "info", "warn", "error"]).default("info"),
});

export interface Config {
  host: string;
  port: number;
  dataDir: string;
  dbPath: string;
  logLevel: "debug" | "info" | "warn" | "error";
}

export class ConfigError extends Error {}

export function loadConfig(env: Record<string, string | undefined> = process.env): Config {
  const parsed = schema.safeParse(env);
  if (!parsed.success) {
    const problems = parsed.error.issues.map((i) => `  ${i.path.join(".")}: ${i.message}`);
    throw new ConfigError(`invalid configuration:\n${problems.join("\n")}`);
  }
  const c = parsed.data;
  return {
    host: c.BUNZZLE_HOST,
    port: c.BUNZZLE_PORT,
    dataDir: c.BUNZZLE_DATA_DIR,
    dbPath: `${c.BUNZZLE_DATA_DIR.replace(/\/+$/, "")}/bunzzle.db`,
    logLevel: c.BUNZZLE_LOG_LEVEL,
  };
}
