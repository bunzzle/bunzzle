import init from "./0001_init.sql" with { type: "text" };
import queue from "./0002_queue.sql" with { type: "text" };

export interface Migration {
  version: number;
  name: string;
  sql: string;
}

export const migrations: readonly Migration[] = [
  { version: 1, name: "init", sql: init },
  { version: 2, name: "queue", sql: queue },
];
