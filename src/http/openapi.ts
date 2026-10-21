import { b, type JsonSchema } from "../validate/schema.ts";
import { VERSION } from "../version.ts";
import * as s from "./schemas.ts";
import { rescheduleSchema, sendSchema } from "./send.ts";

type Scope = "send" | "read" | "full" | "admin";
type Named = [string, b.Schema];

export interface Operation {
  method: "GET" | "POST" | "PATCH" | "DELETE";
  path: string;
  id: string;
  tag: string;
  summary: string;
  scope: Scope[] | null;
  query?: Record<string, b.Schema>;
  body?: Named;
  response?: Named;
  headers?: Record<string, string>;
}

const text = b.string();
const int = b.number().int();

export const OPERATIONS: Operation[] = [
  {
    method: "POST",
    path: "/emails",
    id: "sendEmail",
    tag: "Emails",
    summary: "Send an email",
    scope: ["send"],
    body: ["SendEmail", sendSchema],
    response: ["SentEmail", s.sentEmail],
    headers: {
      "Idempotency-Key": "Sending again with the same key within 24 hours returns the first email.",
    },
  },
  {
    method: "GET",
    path: "/emails",
    id: "listEmails",
    tag: "Emails",
    summary: "Search emails, newest first",
    scope: ["read"],
    query: {
      to: text,
      status: b.enum(["queued", "delivery_delayed", "sending", "delivered", "bounced", "failed"]),
      tag: text.describe("name:value"),
      domain: text,
      since: b.string().format("date-time"),
      until: b.string().format("date-time"),
      limit: int.min(1).max(100).default(20),
      cursor: text,
    },
    response: ["EmailList", s.emailList],
  },
  {
    method: "POST",
    path: "/emails/batch",
    id: "sendBatch",
    tag: "Emails",
    summary: "Send up to 100 emails; if one is invalid, none is queued",
    scope: ["send"],
    body: ["SendBatch", b.array(sendSchema).min(1).max(100)],
    response: ["SentBatch", s.sentBatch],
    headers: {
      "Idempotency-Key":
        "Sending again with the same key within 24 hours returns the first emails.",
    },
  },
  {
    method: "GET",
    path: "/emails/:id",
    id: "getEmail",
    tag: "Emails",
    summary: "Status per recipient and every delivery attempt",
    scope: ["read"],
    response: ["Email", s.email],
  },
  {
    method: "PATCH",
    path: "/emails/:id",
    id: "rescheduleEmail",
    tag: "Emails",
    summary: "Move a scheduled email",
    scope: ["send"],
    body: ["RescheduleEmail", rescheduleSchema],
    response: ["EmailRef", s.emailRef],
  },
  {
    method: "POST",
    path: "/emails/:id/cancel",
    id: "cancelEmail",
    tag: "Emails",
    summary: "Cancel a scheduled email",
    scope: ["send"],
    response: ["EmailRef", s.emailRef],
  },
  {
    method: "GET",
    path: "/stats",
    id: "getStats",
    tag: "Emails",
    summary: "Counts per day",
    scope: ["read"],
    query: {
      since: b.string().format("date"),
      until: b.string().format("date"),
      domain: text,
      tag: text.describe("name:value"),
    },
    response: ["Stats", s.stats],
  },
  {
    method: "GET",
    path: "/domains",
    id: "listDomains",
    tag: "Domains",
    summary: "List domains",
    scope: ["read"],
    response: ["DomainList", s.domainList],
  },
  {
    method: "POST",
    path: "/domains",
    id: "createDomain",
    tag: "Domains",
    summary: "Add a domain and create its DKIM keys",
    scope: ["full"],
    body: ["CreateDomain", s.createDomainSchema],
    response: ["Domain", s.domain],
  },
  {
    method: "GET",
    path: "/domains/:name",
    id: "getDomain",
    tag: "Domains",
    summary: "A domain with its records, IP pool, tracking and Gmail data",
    scope: ["read"],
    response: ["DomainDetail", s.domainDetail],
  },
  {
    method: "PATCH",
    path: "/domains/:name",
    id: "updateDomain",
    tag: "Domains",
    summary: "Set the IP pool or the tracking host",
    scope: ["full"],
    body: ["UpdateDomain", s.updateDomainSchema],
    response: ["DomainUpdate", s.domainUpdate],
  },
  {
    method: "POST",
    path: "/domains/:name/verify",
    id: "verifyDomain",
    tag: "Domains",
    summary: "Check the DNS records now",
    scope: ["full"],
    response: ["Domain", s.domain],
  },
  {
    method: "GET",
    path: "/domains/:name/dmarc",
    id: "getDmarcReports",
    tag: "Domains",
    summary: "DMARC aggregate reports per day",
    scope: ["read"],
    query: { days: int.min(1).max(90).default(7) },
    response: ["DmarcReports", s.dmarcReports],
  },
  {
    method: "POST",
    path: "/domains/:name/rotate",
    id: "rotateDomainKeys",
    tag: "Domains",
    summary: "Start or continue DKIM key rotation",
    scope: ["full"],
    response: ["Rotation", s.rotation],
  },
  {
    method: "GET",
    path: "/projects",
    id: "listProjects",
    tag: "Projects",
    summary: "List projects",
    scope: ["admin"],
    response: ["ProjectList", s.projectList],
  },
  {
    method: "POST",
    path: "/projects",
    id: "createProject",
    tag: "Projects",
    summary: "Add a project",
    scope: ["admin"],
    body: ["CreateProject", s.createProjectSchema],
    response: ["Project", s.project],
  },
  {
    method: "GET",
    path: "/projects/:id",
    id: "getProject",
    tag: "Projects",
    summary: "Get a project by id or name",
    scope: ["admin"],
    response: ["Project", s.project],
  },
  {
    method: "PATCH",
    path: "/projects/:id",
    id: "updateProject",
    tag: "Projects",
    summary: "Rename a project, set its limits and IP pool, suspend or resume it",
    scope: ["admin"],
    body: ["UpdateProject", s.updateProjectSchema],
    response: ["Project", s.project],
  },
  {
    method: "DELETE",
    path: "/projects/:id",
    id: "deleteProject",
    tag: "Projects",
    summary: "Remove a project; its API keys stop working at once",
    scope: ["admin"],
    response: ["ProjectDeleted", s.projectDeleted],
  },
  {
    method: "POST",
    path: "/projects/:id/keys",
    id: "createProjectKey",
    tag: "Projects",
    summary: "Add an API key to a project; the response has the key",
    scope: ["admin"],
    body: ["CreateProjectKey", s.createProjectKeySchema],
    response: ["ProjectKey", s.projectKey],
  },
  {
    method: "GET",
    path: "/webhooks",
    id: "listWebhooks",
    tag: "Webhooks",
    summary: "List webhooks",
    scope: ["read"],
    response: ["WebhookList", s.webhookList],
  },
  {
    method: "POST",
    path: "/webhooks",
    id: "createWebhook",
    tag: "Webhooks",
    summary: "Add a webhook; the response has its signing secret",
    scope: ["full"],
    body: ["CreateWebhook", s.createWebhookSchema],
    response: ["Webhook", s.webhook],
  },
  {
    method: "DELETE",
    path: "/webhooks/:id",
    id: "deleteWebhook",
    tag: "Webhooks",
    summary: "Remove a webhook",
    scope: ["full"],
    response: ["Deleted", s.deleted],
  },
  {
    method: "GET",
    path: "/routes",
    id: "listRoutes",
    tag: "Inbound routes",
    summary: "List inbound routes",
    scope: ["read"],
    response: ["RouteList", s.routeList],
  },
  {
    method: "POST",
    path: "/routes",
    id: "createRoute",
    tag: "Inbound routes",
    summary: "Post mail for an address to a URL; the response has its signing secret",
    scope: ["full"],
    body: ["CreateRoute", s.createRouteSchema],
    response: ["Route", s.route],
  },
  {
    method: "DELETE",
    path: "/routes/:id",
    id: "deleteRoute",
    tag: "Inbound routes",
    summary: "Remove a route",
    scope: ["full"],
    response: ["Deleted", s.deleted],
  },
  {
    method: "POST",
    path: "/routes/:id/retry",
    id: "retryRoute",
    tag: "Inbound routes",
    summary: "Post failed mail for a route again",
    scope: ["full"],
    response: ["RouteRetry", s.routeRetry],
  },
  {
    method: "GET",
    path: "/templates",
    id: "listTemplates",
    tag: "Templates",
    summary: "List templates",
    scope: ["read"],
    response: ["TemplateList", s.templateList],
  },
  {
    method: "POST",
    path: "/templates",
    id: "createTemplate",
    tag: "Templates",
    summary: "Create a template",
    scope: ["full"],
    body: ["CreateTemplate", s.createTemplateSchema],
    response: ["Template", s.template],
  },
  {
    method: "GET",
    path: "/templates/:id",
    id: "getTemplate",
    tag: "Templates",
    summary: "A template by id or name",
    scope: ["read", "send"],
    query: { version: int.min(1) },
    response: ["Template", s.template],
  },
  {
    method: "PATCH",
    path: "/templates/:id",
    id: "updateTemplate",
    tag: "Templates",
    summary: "Save a new version; fields left out are kept",
    scope: ["full"],
    body: ["UpdateTemplate", s.updateTemplateSchema],
    response: ["Template", s.template],
  },
  {
    method: "DELETE",
    path: "/templates/:id",
    id: "deleteTemplate",
    tag: "Templates",
    summary: "Remove a template",
    scope: ["full"],
    response: ["Deleted", s.deleted],
  },
  {
    method: "POST",
    path: "/templates/:id/preview",
    id: "previewTemplate",
    tag: "Templates",
    summary: "Fill a template without sending",
    scope: ["read", "send"],
    body: ["PreviewTemplate", s.previewSchema],
    response: ["Preview", s.preview],
  },
  {
    method: "GET",
    path: "/suppressions",
    id: "listSuppressions",
    tag: "Suppressions",
    summary: "List suppressed addresses",
    scope: ["read"],
    response: ["SuppressionList", s.suppressionList],
  },
  {
    method: "POST",
    path: "/suppressions",
    id: "createSuppression",
    tag: "Suppressions",
    summary: "Suppress an address",
    scope: ["full"],
    body: ["CreateSuppression", s.createSuppressionSchema],
    response: ["SuppressionAdded", s.suppressionAdded],
  },
  {
    method: "DELETE",
    path: "/suppressions/:email",
    id: "deleteSuppression",
    tag: "Suppressions",
    summary: "Remove an address from the suppression list",
    scope: ["full"],
    query: { scope: b.enum(["all", "bulk"]) },
    response: ["SuppressionRemoved", s.suppressionRemoved],
  },
  {
    method: "GET",
    path: "/doctor",
    id: "runDoctor",
    tag: "Operations",
    summary: "Check the configuration, DNS and domains",
    scope: ["full"],
    response: ["Doctor", s.doctor],
  },
  {
    method: "GET",
    path: "/ips",
    id: "listIps",
    tag: "Operations",
    summary: "Source IPs with their pool and reverse DNS",
    scope: ["read"],
    response: ["OperatorList", s.operatorList],
  },
  {
    method: "GET",
    path: "/holds",
    id: "listHolds",
    tag: "Operations",
    summary: "Bulk mail on hold and sender rates",
    scope: ["read"],
    query: { all: b.boolean() },
    response: ["OperatorView", s.operatorView],
  },
  {
    method: "DELETE",
    path: "/holds/:id",
    id: "releaseHold",
    tag: "Operations",
    summary: "Release a hold",
    scope: ["full"],
    response: ["OperatorView", s.operatorView],
  },
  {
    method: "GET",
    path: "/queue",
    id: "getQueue",
    tag: "Operations",
    summary: "Queued mail per destination and suspensions",
    scope: ["read"],
    response: ["OperatorView", s.operatorView],
  },
  {
    method: "POST",
    path: "/queue/suspensions",
    id: "suspendDelivery",
    tag: "Operations",
    summary: "Pause delivery to a domain or provider",
    scope: ["full"],
    body: ["Suspend", s.suspendSchema],
    response: ["OperatorView", s.operatorView],
  },
  {
    method: "DELETE",
    path: "/queue/suspensions/:target",
    id: "resumeDelivery",
    tag: "Operations",
    summary: "Resume delivery",
    scope: ["full"],
    response: ["OperatorView", s.operatorView],
  },
  {
    method: "POST",
    path: "/queue/fail",
    id: "failQueued",
    tag: "Operations",
    summary: "Fail queued mail that matches the filters (bounces are sent)",
    scope: ["full"],
    body: ["RemoveQueued", s.removeSchema],
    response: ["OperatorView", s.operatorView],
  },
  {
    method: "POST",
    path: "/queue/cancel",
    id: "cancelQueued",
    tag: "Operations",
    summary: "Cancel queued mail that matches the filters",
    scope: ["full"],
    body: ["RemoveQueued", s.removeSchema],
    response: ["OperatorView", s.operatorView],
  },
  {
    method: "GET",
    path: "/paths",
    id: "listPaths",
    tag: "Operations",
    summary: "Sending speed per destination, limits and recent changes",
    scope: ["read"],
    response: ["OperatorList", s.operatorList],
  },
  {
    method: "GET",
    path: "/metrics",
    id: "getMetrics",
    tag: "Operations",
    summary: "Metrics in the OpenMetrics text format",
    scope: ["read"],
  },
  {
    method: "GET",
    path: "/health",
    id: "getHealth",
    tag: "Operations",
    summary: "Whether the server is up",
    scope: null,
    response: ["Health", s.health],
  },
  {
    method: "GET",
    path: "/u/:token",
    id: "unsubscribePage",
    tag: "Public links",
    summary: "Unsubscribe page of a bulk email",
    scope: null,
  },
  {
    method: "POST",
    path: "/u/:token",
    id: "unsubscribe",
    tag: "Public links",
    summary: "One-click unsubscribe",
    scope: null,
  },
  {
    method: "GET",
    path: "/o/:token",
    id: "trackOpen",
    tag: "Public links",
    summary: "Open tracking image",
    scope: null,
  },
  {
    method: "GET",
    path: "/c/:token/:url",
    id: "trackClick",
    tag: "Public links",
    summary: "Click tracking redirect",
    scope: null,
  },
];

const ref = (name: string) => ({ $ref: `#/components/schemas/${name}` });
const json = (schema: unknown) => ({ "application/json": { schema } });

function responseFor(op: Operation): Record<string, unknown> {
  if (op.path === "/metrics") {
    return {
      description: "Metrics",
      content: { "application/openmetrics-text": { schema: { type: "string" } } },
    };
  }
  if (op.id === "unsubscribePage" || op.id === "unsubscribe") {
    return { description: "HTML page", content: { "text/html": { schema: { type: "string" } } } };
  }
  if (op.id === "trackOpen") {
    return {
      description: "1×1 GIF",
      content: { "image/gif": { schema: { type: "string", format: "binary" } } },
    };
  }
  return { description: "OK", ...(op.response ? { content: json(ref(op.response[0])) } : {}) };
}

export function openApi(): Record<string, unknown> {
  const schemas: Record<string, JsonSchema> = {};
  const paths: Record<string, Record<string, unknown>> = {};
  const errors = {
    description: "Error",
    content: json(ref("Error")),
  };
  schemas["Error"] = s.errorBody.json;
  for (const op of OPERATIONS) {
    for (const named of [op.body, op.response]) {
      if (named) schemas[named[0]] = named[1].json;
    }
    const path = op.path.replace(/:(\w+)/g, "{$1}");
    const params = [
      ...[...op.path.matchAll(/:(\w+)/g)].map((m) => ({
        name: m[1],
        in: "path",
        required: true,
        schema: { type: "string" },
      })),
      ...Object.entries(op.query ?? {}).map(([name, schema]) => ({
        name,
        in: "query",
        required: false,
        schema: schema.json,
      })),
      ...Object.entries(op.headers ?? {}).map(([name, description]) => ({
        name,
        in: "header",
        required: false,
        description,
        schema: { type: "string", minLength: 1, maxLength: 256 },
      })),
    ];
    const responses: Record<string, unknown> = {
      ...(op.id === "trackClick"
        ? { "302": { description: "Redirect to the link in the email" } }
        : { "200": responseFor(op) }),
      ...(op.scope
        ? { "4XX": errors }
        : op.tag === "Public links"
          ? { "404": { description: "Not a valid link" } }
          : {}),
    };
    paths[path] ??= {};
    (paths[path] as Record<string, unknown>)[op.method.toLowerCase()] = {
      operationId: op.id,
      tags: [op.tag],
      summary: op.summary,
      ...(op.scope
        ? {
            description: op.scope.includes("admin")
              ? "Needs an admin key."
              : `API key scope: ${op.scope.join(" or ")} (full keys can do everything).`,
          }
        : {}),
      ...(op.scope ? {} : { security: [] }),
      ...(params.length ? { parameters: params } : {}),
      ...(op.body ? { requestBody: { required: true, content: json(ref(op.body[0])) } } : {}),
      responses,
    };
  }
  return {
    openapi: "3.1.0",
    info: {
      title: "Bunzzle",
      version: VERSION,
      license: { name: "AGPL-3.0-only", identifier: "AGPL-3.0-only" },
    },
    servers: [{ url: "http://127.0.0.1:3000" }],
    security: [{ apiKey: [] }],
    tags: [...new Set(OPERATIONS.map((o) => o.tag))].map((name) => ({ name })),
    paths,
    components: {
      securitySchemes: { apiKey: { type: "http", scheme: "bearer" } },
      schemas,
    },
  };
}
