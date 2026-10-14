// SQL files are imported as text so `bun build --compile` embeds them in the binary.
// Add new migrations to the end of this list; never edit or reorder an applied one.
import init from "./0001_init.sql" with { type: "text" };

export interface Migration {
  version: number;
  name: string;
  sql: string;
}

export const migrations: readonly Migration[] = [{ version: 1, name: "init", sql: init }];
