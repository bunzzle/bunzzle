import init from "./0001_init.sql" with { type: "text" };
import queue from "./0002_queue.sql" with { type: "text" };
import deliveries from "./0003_deliveries.sql" with { type: "text" };
import bodies from "./0004_bodies.sql" with { type: "text" };
import api from "./0005_api.sql" with { type: "text" };
import shaping from "./0006_shaping.sql" with { type: "text" };
import feedback from "./0007_feedback.sql" with { type: "text" };
import reputation from "./0008_reputation.sql" with { type: "text" };
import dmarc from "./0009_dmarc.sql" with { type: "text" };

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
  { version: 6, name: "shaping", sql: shaping },
  { version: 7, name: "feedback", sql: feedback },
  { version: 8, name: "reputation", sql: reputation },
  { version: 9, name: "dmarc", sql: dmarc },
];
