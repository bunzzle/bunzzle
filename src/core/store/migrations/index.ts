import init from "./0001_init.sql" with { type: "text" };
import queue from "./0002_queue.sql" with { type: "text" };
import deliveries from "./0003_deliveries.sql" with { type: "text" };
import bodies from "./0004_bodies.sql" with { type: "text" };
import api from "./0005_api.sql" with { type: "text" };

export interface Migration {
  version: number;
  name: string;
  sql: string;
}

export const migrations: readonly Migration[] = [
  { version: 1, name: "init", sql: init },
  { version: 2, name: "queue", sql: queue },
  { version: 3, name: "deliveries", sql: deliveries },
  { version: 4, name: "bodies", sql: bodies },
  { version: 5, name: "api", sql: api },
];
