import { DOMAIN_MODES } from "../domains/domains.ts";
import { ROUTE_FORMATS } from "../inbound/routes.ts";
import { b } from "../validate/schema.ts";
import { EVENT_TYPES } from "../webhooks/store.ts";

const time = b.string().format("date-time");
const day = b.string().format("date");
const id = b.string();

export const createDomainSchema = b.object({
  name: b.string().min(1).max(253),
  mode: b.enum(DOMAIN_MODES).optional(),
});

export const updateDomainSchema = b.object({
  ip_pool: b
    .string()
    .regex(/^[a-z0-9-]{1,32}$/)
    .nullable()
    .optional(),
  tracking: b
    .object({
      host: b.string().min(1).max(253),
      opens: b.boolean().optional(),
      clicks: b.boolean().optional(),
    })
    .nullable()
    .optional(),
});

export const createWebhookSchema = b.object({
  endpoint: b.string().max(2048),
  events: b.array(b.enum(EVENT_TYPES)).optional(),
});

export const createRouteSchema = b.object({
  address: b.string().max(320),
  endpoint: b.string().max(2048),
  format: b.enum(ROUTE_FORMATS).optional(),
});

const templateBody = {
  subject: b.string().max(998),
  html: b
    .string()
    .max(2 * 1024 * 1024)
    .nullable(),
  text: b
    .string()
    .max(2 * 1024 * 1024)
    .nullable(),
};

export const createTemplateSchema = b.object({
  name: b.string().max(64),
  subject: templateBody.subject,
  html: templateBody.html.optional(),
  text: templateBody.text.optional(),
});

export const updateTemplateSchema = b.object({
  subject: templateBody.subject.optional(),
  html: templateBody.html.optional(),
  text: templateBody.text.optional(),
});

export const previewSchema = b.object({
  version: b.number().int().min(1).optional(),
  variables: b.record(b.string(), b.unknown()).optional(),
});

export const createSuppressionSchema = b.object({
  email: b.string().max(320),
  scope: b.enum(["all", "bulk"]).optional(),
});

export const suspendSchema = b.object({
  target: b.string().max(300),
  reason: b.string().min(1).max(500),
  until: b.string().max(64).optional(),
});

export const removeSchema = b.object({
  reason: b.string().min(1).max(500),
  domain: b.string().max(253).optional(),
  sender_domain: b.string().max(253).optional(),
  older_than_seconds: b.number().int().nonnegative().optional(),
  dry_run: b.boolean().default(false),
});

const list = <T extends b.Schema>(item: T) =>
  b.object({ object: b.literal("list"), data: b.array(item) });

export const errorBody = b.object({
  statusCode: b.number().int(),
  name: b.string(),
  message: b.string(),
});

export const sentEmail = b.object({ id });
export const sentBatch = b.object({ data: b.array(b.object({ id })) });
export const emailRef = b.object({ object: b.literal("email"), id });
export const deleted = b.object({ id, deleted: b.boolean() });

const tag = b.object({ name: b.string(), value: b.string() });
const status = b.enum([
  "scheduled",
  "queued",
  "sending",
  "delivery_delayed",
  "delivered",
  "bounced",
  "failed",
  "expired",
  "suppressed",
  "canceled",
]);

export const emailSummary = b.object({
  object: b.literal("email"),
  id,
  from: b.string().nullable(),
  to: b.array(b.string()),
  tags: b.array(tag),
  lane: b.enum(["transactional", "bulk"]),
  created_at: time,
  last_event: status,
  recipients: b.array(b.object({ email: b.string(), status })),
});

export const emailList = b.object({
  object: b.literal("list"),
  data: b.array(emailSummary),
  next_cursor: b.string().nullable(),
});

const session = b.object({
  host: b.string(),
  ip: b.string().nullable(),
  reused_connection: b.boolean(),
  tls: b.object({
    status: b.string(),
    version: b.string().nullable(),
    cipher: b.string().nullable(),
    rule: b.string().nullable(),
    error: b.string().nullable(),
  }),
  stopped_at: b.string().nullable(),
  error: b.string().nullable(),
  conversation: b.array(
    b.object({ at_ms: b.number(), from: b.enum(["client", "server", "note"]), text: b.string() }),
  ),
});

export const email = b.object({
  object: b.literal("email"),
  id,
  from: b.string().nullable(),
  to: b.array(b.string()),
  cc: b.array(b.string()),
  bcc: b.array(b.string()),
  reply_to: b.array(b.string()),
  subject: b.literal(null),
  html: b.literal(null),
  text: b.literal(null),
  tags: b.array(tag),
  lane: b.enum(["transactional", "bulk"]),
  created_at: time,
  scheduled_at: time.nullable(),
  last_event: status,
  recipients: b.array(
    b.object({
      email: b.string(),
      status,
      attempts: b.number().int(),
      last_reply: b.string().nullable(),
      class: b.string().nullable(),
      about: b.string().nullable(),
      suppression_candidate: b.boolean(),
      updated_at: time,
    }),
  ),
  attempts: b.array(
    b.object({
      at: time,
      domain: b.string(),
      mx: b.array(b.string()),
      provider: b.string().nullable(),
      via: b.enum(["direct", "relay"]),
      tls_policy: b.string().nullable(),
      reconciled: b.boolean(),
      sessions: b.array(session),
      results: b.array(
        b.object({
          email: b.string(),
          status: b.string(),
          reply: b.string().nullable().optional(),
          class: b.string().nullable().optional(),
          action: b.string().nullable().optional(),
        }),
      ),
    }),
  ),
  events: b.array(
    b
      .record(b.string(), b.unknown())
      .describe("`type` and `at`, and fields that depend on the type"),
  ),
});

export const stats = b.object({
  object: b.literal("stats"),
  since: day,
  until: day,
  totals: b.record(b.string(), b.number().int()),
  data: b.array(b.record(b.string(), b.union([b.string(), b.number()]))),
});

const record = b.object({
  record: b.string(),
  name: b.string(),
  type: b.enum(["TXT", "MX", "CNAME"]),
  value: b.string(),
  required: b.boolean(),
  status: b.enum(["not_started", "verified", "missing", "mismatch"]),
  found: b.string().nullable(),
});

const trackingView = b
  .object({
    host: b.string(),
    opens: b.boolean(),
    clicks: b.boolean(),
    record: b.object({
      name: b.string(),
      type: b.literal("CNAME"),
      value: b.string().nullable(),
      status: b.enum(["pending", "verified", "missing", "mismatch"]),
      found: b.string().nullable(),
    }),
    checked_at: time.nullable(),
  })
  .nullable();

export const domain = b.object({
  object: b.literal("domain"),
  name: b.string(),
  mode: b.enum(DOMAIN_MODES),
  status: b.enum(["pending", "verified"]),
  created_at: time,
  checked_at: time.nullable(),
  records: b.array(record),
});

export const domainDetail = b.object({
  object: b.literal("domain"),
  name: b.string(),
  mode: b.enum(DOMAIN_MODES),
  status: b.enum(["pending", "verified"]),
  created_at: time,
  checked_at: time.nullable(),
  records: b.array(record),
  ip_pool: b.string().nullable(),
  tracking: trackingView,
  gmail: b
    .object({
      day: b.string(),
      spam_rate: b.number().nullable(),
      reputation: b.string().nullable(),
      spf_pass_rate: b.number().nullable(),
      dkim_pass_rate: b.number().nullable(),
      dmarc_pass_rate: b.number().nullable(),
      tls_rate: b.number().nullable(),
    })
    .nullable(),
});

export const domainList = list(domain);

export const domainUpdate = b.object({
  name: b.string(),
  ip_pool: b.string().nullable().optional(),
  tracking: trackingView.optional(),
});

export const dmarcReports = b.object({
  object: b.literal("list"),
  domain: b.string(),
  data: b.array(
    b.object({
      day: day,
      messages: b.number().int(),
      dmarc_pass: b.number().int(),
      reporters: b.array(b.string()),
      sources: b.array(
        b.object({
          source_ip: b.string(),
          messages: b.number().int(),
          dmarc_pass: b.number().int(),
          dkim_pass: b.number().int(),
          spf_pass: b.number().int(),
        }),
      ),
    }),
  ),
});

export const webhook = b.object({
  object: b.literal("webhook"),
  id,
  endpoint: b.string(),
  events: b.array(b.enum(EVENT_TYPES)),
  created_at: time,
  signing_secret: b.string().optional().describe("Only in the response that creates the webhook"),
});

export const webhookList = list(webhook);

export const route = b.object({
  object: b.literal("route"),
  id,
  address: b.string(),
  endpoint: b.string(),
  format: b.enum(ROUTE_FORMATS),
  created_at: time,
  signing_secret: b.string().optional().describe("Only in the response that creates the route"),
});

export const routeList = list(route);
export const routeRetry = b.object({ id, requeued: b.number().int() });

export const templateSummary = b.object({
  object: b.literal("template"),
  id,
  name: b.string(),
  version: b.number().int(),
  created_at: time,
  updated_at: time,
});

export const template = b.object({
  object: b.literal("template"),
  id,
  name: b.string(),
  version: b.number().int(),
  created_at: time,
  updated_at: time,
  subject: b.string(),
  html: b.string().nullable(),
  text: b.string().nullable(),
  versions: b.array(b.number().int()),
});

export const templateList = list(templateSummary);

export const preview = b.object({
  object: b.literal("preview"),
  id,
  name: b.string(),
  version: b.number().int(),
  subject: b.string(),
  html: b.string().nullable(),
  text: b.string().nullable(),
});

export const suppression = b.object({
  object: b.literal("suppression"),
  email: b.string(),
  scope: b.enum(["all", "bulk"]),
  reason: b.string(),
  detail: b.string().nullable(),
  email_id: b.string().nullable(),
  created_at: time,
  expires_at: time.nullable(),
});

export const suppressionList = list(suppression);
export const suppressionAdded = b.object({
  email: b.string(),
  scope: b.enum(["all", "bulk"]),
  reason: b.string(),
});
export const suppressionRemoved = b.object({ email: b.string(), removed: b.number().int() });

export const health = b.object({
  ok: b.boolean(),
  version: b.string(),
  uptime_s: b.number().int(),
  core: b.enum(["ok", "unavailable"]),
});

export const doctor = b.object({
  checks: b.array(
    b.object({
      area: b.string(),
      item: b.string(),
      status: b.enum(["ok", "warn", "fail"]),
      detail: b.string(),
    }),
  ),
  summary: b.object({ ok: b.number().int(), warn: b.number().int(), fail: b.number().int() }),
});

export const rotation = b.object({ result: b.string() });
export const operatorList = list(b.record(b.string(), b.unknown()));
export const operatorView = b.record(b.string(), b.unknown());

const limitField = b.number().int().min(1).max(100_000_000).nullable();

export const createProjectSchema = b.object({ name: b.string().min(1).max(63) });

export const updateProjectSchema = b.object({
  name: b.string().min(1).max(63).optional(),
  per_hour: limitField.optional(),
  per_day: limitField.optional(),
  ip_pool: b
    .string()
    .regex(/^[a-z0-9-]{1,32}$/)
    .nullable()
    .optional(),
  suspended: b.boolean().optional(),
});

export const createProjectKeySchema = b.object({
  name: b.string().min(1).max(100),
  scope: b.enum(["send", "read", "full"]).optional(),
  domains: b.array(b.string().max(253)).max(100).optional(),
  rate_limit: b.number().int().min(1).max(10_000).optional(),
  test: b.boolean().optional(),
  ip_pool: b
    .string()
    .regex(/^[a-z0-9-]{1,32}$/)
    .optional(),
});

export const project = b.object({
  object: b.literal("project"),
  id,
  name: b.string(),
  per_hour: b.number().int().nullable(),
  per_day: b.number().int().nullable(),
  ip_pool: b.string().nullable(),
  suspended: b.boolean(),
  created_at: time,
  suspended_at: time.nullable(),
});

export const projectList = list(project);

export const projectDeleted = b.object({
  object: b.literal("project"),
  id,
  deleted: b.boolean(),
});

export const projectKey = b.object({
  object: b.literal("api_key"),
  id,
  name: b.string(),
  scope: b.enum(["send", "read", "full"]),
  domains: b.array(b.string()).nullable(),
  rate_limit: b.number().int(),
  test: b.boolean(),
  ip_pool: b.string().nullable(),
  created_at: time,
  token: b.string().describe("Shown only once"),
});
