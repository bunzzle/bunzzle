import init from "./0001_init.sql" with { type: "text" };
import queue from "./0002_queue.sql" with { type: "text" };
import deliveries from "./0003_deliveries.sql" with { type: "text" };
import bodies from "./0004_bodies.sql" with { type: "text" };
import api from "./0005_api.sql" with { type: "text" };
import shaping from "./0006_shaping.sql" with { type: "text" };
import feedback from "./0007_feedback.sql" with { type: "text" };
import reputation from "./0008_reputation.sql" with { type: "text" };
import dmarc from "./0009_dmarc.sql" with { type: "text" };
import queueControl from "./0010_queue_control.sql" with { type: "text" };
import eventTime from "./0011_event_time.sql" with { type: "text" };
import conversations from "./0012_conversations.sql" with { type: "text" };
import testKeys from "./0013_test_keys.sql" with { type: "text" };
import postmaster from "./0014_postmaster.sql" with { type: "text" };
import search from "./0015_search.sql" with { type: "text" };
import ipPools from "./0016_ip_pools.sql" with { type: "text" };
import routes from "./0017_routes.sql" with { type: "text" };
import templates from "./0018_templates.sql" with { type: "text" };
import tracking from "./0019_tracking.sql" with { type: "text" };
import hooks from "./0020_hooks.sql" with { type: "text" };

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
  { version: 10, name: "queue control", sql: queueControl },
  { version: 11, name: "event time", sql: eventTime },
  { version: 12, name: "conversations", sql: conversations },
  { version: 13, name: "test keys", sql: testKeys },
  { version: 14, name: "postmaster", sql: postmaster },
  { version: 15, name: "search and stats", sql: search },
  { version: 16, name: "ip pools", sql: ipPools },
  { version: 17, name: "inbound routes", sql: routes },
  { version: 18, name: "templates", sql: templates },
  { version: 19, name: "tracking", sql: tracking },
  { version: 20, name: "hooks", sql: hooks },
];
