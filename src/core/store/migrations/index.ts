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
import projects from "./0021_projects.sql" with { type: "text" };
import projectKeys from "./0022_project_keys.sql" with { type: "text" };
import adminKeys from "./0023_admin_keys.sql" with { type: "text" };
import jobsProject from "./0024_jobs_project.sql" with { type: "text" };
import projectUsage from "./0025_project_usage.sql" with { type: "text" };
import poolOwners from "./0026_pool_owners.sql" with { type: "text" };
import suppressionsAddress from "./0027_suppressions_address.sql" with { type: "text" };
import domainMode from "./0028_domain_mode.sql" with { type: "text" };
import domainSlotKeys from "./0029_domain_slot_keys.sql" with { type: "text" };
import webhookAttempts from "./0030_webhook_attempts.sql" with { type: "text" };
import poolRules from "./0031_pool_rules.sql" with { type: "text" };

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
  { version: 21, name: "projects", sql: projects },
  { version: 22, name: "project keys", sql: projectKeys },
  { version: 23, name: "admin keys", sql: adminKeys },
  { version: 24, name: "jobs by project", sql: jobsProject },
  { version: 25, name: "project usage", sql: projectUsage },
  { version: 26, name: "pool owners", sql: poolOwners },
  { version: 27, name: "suppressions by address", sql: suppressionsAddress },
  { version: 28, name: "domain mode", sql: domainMode },
  { version: 29, name: "domain slot keys", sql: domainSlotKeys },
  { version: 30, name: "webhook attempts and resends", sql: webhookAttempts },
  { version: 31, name: "pool rules", sql: poolRules },
];
