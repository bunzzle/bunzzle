export type LogLevel = "debug" | "info" | "warn" | "error";

const ORDER: Record<LogLevel, number> = { debug: 10, info: 20, warn: 30, error: 40 };

export interface Logger {
  debug(msg: string, fields?: Record<string, unknown>): void;
  info(msg: string, fields?: Record<string, unknown>): void;
  warn(msg: string, fields?: Record<string, unknown>): void;
  error(msg: string, fields?: Record<string, unknown>): void;
  child(fields: Record<string, unknown>): Logger;
  setLevel(level: LogLevel): void;
}

export function createLogger(
  level: LogLevel = "info",
  base: Record<string, unknown> = {},
  write: (line: string, level: LogLevel) => void = defaultWrite,
  shared: { min: number } = { min: ORDER[level] },
): Logger {
  const emit = (lvl: LogLevel, msg: string, fields?: Record<string, unknown>) => {
    if (ORDER[lvl] < shared.min) return;
    write(
      JSON.stringify({ time: new Date().toISOString(), level: lvl, msg, ...base, ...fields }),
      lvl,
    );
  };

  return {
    debug: (msg, fields) => emit("debug", msg, fields),
    info: (msg, fields) => emit("info", msg, fields),
    warn: (msg, fields) => emit("warn", msg, fields),
    error: (msg, fields) => emit("error", msg, fields),
    child: (fields) => createLogger(level, { ...base, ...fields }, write, shared),
    setLevel: (next) => {
      shared.min = ORDER[next];
    },
  };
}

function defaultWrite(line: string, level: LogLevel) {
  if (level === "error") console.error(line);
  else console.log(line);
}
