import { hashToken, TOKEN } from "../accounts/api-keys.ts";
import type { Logger } from "../core/log.ts";
import type { RpcClient } from "../ipc/rpc.ts";
import { b } from "../validate/schema.ts";
import { VERSION } from "../version.ts";
import { ApiError, errorResponse, fromRpc } from "./errors.ts";
import { type PreparedEmail, prepareEmail, rescheduleSchema, sendSchema } from "./send.ts";

const MAX_BODY = 50 * 1024 * 1024;

interface Caller {
  hash: string;
  id: string;
  domains: string[] | null;
}

export const authResult = b.object({
  id: b.string(),
  scope: b.enum(["send", "read", "full"]),
  domains: b.array(b.string()).nullable(),
  rateLimit: b.number(),
});

export class Buckets {
  readonly #state = new Map<string, { tokens: number; at: number }>();

  take(id: string, perSecond: number, now: number): { ok: boolean; remaining: number } {
    const b = this.#state.get(id) ?? { tokens: perSecond, at: now };
    b.tokens = Math.min(perSecond, b.tokens + ((now - b.at) / 1000) * perSecond);
    b.at = now;
    const ok = b.tokens >= 1;
    if (ok) b.tokens -= 1;
    this.#state.set(id, b);
    return { ok, remaining: Math.floor(b.tokens) };
  }
}

async function json(req: Request): Promise<unknown> {
  const text = await req.text();
  try {
    return JSON.parse(text);
  } catch {
    throw new ApiError(422, "validation_error", "The request body must be valid JSON.");
  }
}

function parseJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    throw new ApiError(422, "validation_error", "The request body must be valid JSON.");
  }
}

function idempotencyKeyOf(req: Request): string | null {
  const key = req.headers.get("idempotency-key");
  if (key !== null && (key.length < 1 || key.length > 256)) {
    throw new ApiError(
      400,
      "invalid_idempotency_key",
      "The Idempotency-Key must be 1 to 256 characters.",
    );
  }
  return key;
}

function toSend(caller: { domains: string[] | null }, body: unknown, now: Date): PreparedEmail {
  const parsed = sendSchema.safeParse(body);
  if (!parsed.success) throw invalid(parsed.error);
  const email = prepareEmail(parsed.data, now);
  if (caller.domains && !caller.domains.includes(email.fromDomain)) {
    throw new ApiError(
      403,
      "restricted_api_key",
      `This API key cannot send from ${email.fromDomain}.`,
    );
  }
  return email;
}

function enqueueFields(email: PreparedEmail) {
  return {
    from: email.from,
    recipients: email.recipients,
    data: email.data,
    smtpUtf8: email.smtpUtf8,
    requireTls: email.requireTls,
    priority: email.lane === "bulk" ? 5 : 0,
    meta: { ...email.meta, lane: email.lane },
    ...(email.scheduledAt !== undefined ? { scheduledAt: email.scheduledAt } : {}),
    ...(email.expiresAt !== undefined ? { expiresAt: email.expiresAt } : {}),
  };
}

const suspendSchema = b.object({
  target: b.string().max(300),
  reason: b.string().min(1).max(500),
  until: b.string().max(64).optional(),
});

const removeSchema = b.object({
  reason: b.string().min(1).max(500),
  domain: b.string().max(253).optional(),
  sender_domain: b.string().max(253).optional(),
  older_than_seconds: b.number().int().nonnegative().optional(),
  dry_run: b.boolean().default(false),
});

function invalid(error: b.ValidationError): ApiError {
  const issue = error.issues[0];
  const field = issue?.path.join(".") || "body";
  return new ApiError(
    422,
    "validation_error",
    `Invalid \`${field}\` field: ${issue?.message ?? ""}`,
  );
}

function page(body: string, status = 200): Response {
  return new Response(
    `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Unsubscribe</title><body style="font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem">${body}</body>`,
    {
      status,
      headers: {
        "content-type": "text/html; charset=utf-8",
        "cache-control": "no-store",
        "content-security-policy":
          "default-src 'none'; form-action 'self'; style-src 'unsafe-inline'",
        "x-frame-options": "DENY",
      },
    },
  );
}

export interface AppOptions {
  core: RpcClient;
  log: Logger;
  hostname: string;
  port: number;
}

export function startApp({ core, log, hostname, port }: AppOptions) {
  const startedAt = Date.now();
  const buckets = new Buckets();

  const authenticate = async (req: Request): Promise<Caller> => {
    const header = req.headers.get("authorization");
    if (!header) {
      throw new ApiError(
        401,
        "missing_api_key",
        "Missing API key in the authorization header. Include the following header in the request: Authorization: Bearer YOUR_API_KEY",
      );
    }
    const token = /^Bearer\s+(\S+)$/i.exec(header)?.[1];
    if (!token || !TOKEN.test(token))
      throw new ApiError(403, "invalid_api_key", "API key is invalid");
    const hash = hashToken(token);
    let key: b.infer<typeof authResult>;
    try {
      key = await core.call(
        "authenticate",
        { tokenHash: hash },
        { result: authResult, timeoutMs: 5_000 },
      );
    } catch (err) {
      throw fromRpc(err);
    }
    const bucket = buckets.take(key.id, key.rateLimit, Date.now());
    if (!bucket.ok) {
      throw new ApiError(
        429,
        "rate_limit_exceeded",
        `Too many requests. You can only make ${key.rateLimit} requests per second.`,
        {
          "Retry-After": "1",
          "ratelimit-limit": String(key.rateLimit),
          "ratelimit-remaining": "0",
        },
      );
    }
    return { hash, id: key.id, domains: key.domains };
  };

  const handle =
    (fn: (req: Request & { params: Record<string, string> }) => Promise<Response>) =>
    async (req: Request & { params: Record<string, string> }): Promise<Response> => {
      try {
        return await fn(req);
      } catch (err) {
        const api = fromRpc(err);
        if (api.status >= 500)
          log.error("request failed", {
            path: new URL(req.url).pathname,
            error: (err as Error)?.message,
          });
        return errorResponse(api);
      }
    };

  const rpc = async <T>(method: string, params: unknown, result?: b.Schema<T>): Promise<T> => {
    try {
      return await core.call(method, params, { timeoutMs: 60_000, ...(result ? { result } : {}) });
    } catch (err) {
      throw fromRpc(err);
    }
  };

  const removeQueued = async (req: Request, action: "fail" | "cancel") => {
    const caller = await authenticate(req);
    const parsed = removeSchema.safeParse(await json(req));
    if (!parsed.success) throw invalid(parsed.error);
    const p = parsed.data;
    return Response.json(
      await rpc("removeQueued", {
        tokenHash: caller.hash,
        action,
        reason: p.reason,
        dryRun: p.dry_run,
        ...(p.domain !== undefined ? { domain: p.domain } : {}),
        ...(p.sender_domain !== undefined ? { senderDomain: p.sender_domain } : {}),
        ...(p.older_than_seconds !== undefined ? { olderThanMs: p.older_than_seconds * 1000 } : {}),
      }),
    );
  };

  return Bun.serve({
    hostname,
    port,
    maxRequestBodySize: MAX_BODY,
    routes: {
      "/health": {
        GET: async () => {
          let ok = false;
          try {
            ok = (
              await core.call(
                "health",
                {},
                { timeoutMs: 2_000, result: b.object({ ok: b.boolean() }) },
              )
            ).ok;
          } catch {
            ok = false;
          }
          return Response.json(
            {
              ok,
              version: VERSION,
              uptime_s: Math.floor((Date.now() - startedAt) / 1000),
              core: ok ? "ok" : "unavailable",
            },
            { status: ok ? 200 : 503 },
          );
        },
      },
      "/emails": {
        GET: handle(async (req) => {
          const caller = await authenticate(req);
          const q = new URL(req.url).searchParams;
          const STATUS: Record<string, string> = {
            queued: "queued",
            delivery_delayed: "deferred",
            sending: "unknown",
            delivered: "delivered",
            bounced: "bounced",
            failed: "failed",
          };
          const time = (name: string) => {
            const v = q.get(name);
            if (v === null) return undefined;
            const t = Date.parse(v);
            if (Number.isNaN(t))
              throw new ApiError(422, "validation_error", `${name} must be a date`);
            return t;
          };
          const status = q.get("status");
          if (status !== null && !STATUS[status]) {
            throw new ApiError(
              422,
              "validation_error",
              `status must be one of: ${Object.keys(STATUS).join(", ")}`,
            );
          }
          const limit = Number(q.get("limit") ?? 20);
          if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
            throw new ApiError(422, "validation_error", "limit must be 1 to 100");
          }
          const since = time("since");
          const until = time("until");
          return Response.json({
            object: "list",
            ...(await rpc(
              "listEmails",
              {
                tokenHash: caller.hash,
                limit,
                ...(q.get("cursor") ? { before: q.get("cursor") } : {}),
                ...(q.get("to") ? { to: q.get("to") } : {}),
                ...(status ? { status: STATUS[status] } : {}),
                ...(q.get("tag") ? { tag: q.get("tag") } : {}),
                ...(q.get("domain") ? { domain: q.get("domain") } : {}),
                ...(since !== undefined ? { since } : {}),
                ...(until !== undefined ? { until } : {}),
              },
              b.object({ data: b.array(b.unknown()), next_cursor: b.string().nullable() }),
            )),
          });
        }),
        POST: handle(async (req) => {
          const caller = await authenticate(req);
          const text = await req.text();
          const email = toSend(caller, parseJson(text), new Date());
          const idempotencyKey = idempotencyKeyOf(req);
          const r = await rpc(
            "enqueue",
            {
              tokenHash: caller.hash,
              ...enqueueFields(email),
              ...(idempotencyKey !== null ? { idempotencyKey, bodyHash: hashToken(text) } : {}),
            },
            b.object({ id: b.string(), existed: b.boolean() }),
          );
          return Response.json({ id: r.id });
        }),
      },
      "/emails/batch": {
        POST: handle(async (req) => {
          const caller = await authenticate(req);
          const text = await req.text();
          const list = b.array(b.unknown()).min(1).max(100).safeParse(parseJson(text));
          if (!list.success) {
            throw new ApiError(
              422,
              "validation_error",
              "The body must be an array of 1 to 100 emails.",
            );
          }
          const idempotencyKey = idempotencyKeyOf(req);
          const now = new Date();
          const emails = list.data.map((item, i) => {
            try {
              return {
                ...enqueueFields(toSend(caller, item, now)),
                ...(idempotencyKey !== null
                  ? { idempotencyKey: `${idempotencyKey}#${i}`, bodyHash: hashToken(text) }
                  : {}),
              };
            } catch (err) {
              if (err instanceof ApiError) {
                throw new ApiError(
                  err.status,
                  err.kind,
                  `emails[${i}]: ${err.message}`,
                  err.headers,
                );
              }
              throw err;
            }
          });
          const r = await rpc(
            "enqueueBatch",
            { tokenHash: caller.hash, emails },
            b.object({ data: b.array(b.object({ id: b.string() })) }),
          );
          return Response.json({ data: r.data.map((x) => ({ id: x.id })) });
        }),
      },
      "/emails/:id": {
        GET: handle(async (req) => {
          const caller = await authenticate(req);
          return Response.json(
            await rpc("getEmail", { tokenHash: caller.hash, id: req.params["id"] }),
          );
        }),
        PATCH: handle(async (req) => {
          const caller = await authenticate(req);
          let body: unknown;
          try {
            body = await req.json();
          } catch {
            throw new ApiError(422, "validation_error", "The request body must be valid JSON.");
          }
          const parsed = rescheduleSchema.safeParse(body);
          if (!parsed.success) throw invalid(parsed.error);
          const scheduledAt = Date.parse(parsed.data.scheduled_at);
          if (Number.isNaN(scheduledAt)) {
            throw new ApiError(422, "validation_error", "`scheduled_at` must be an ISO 8601 date");
          }
          const id = req.params["id"];
          await rpc("rescheduleEmail", { tokenHash: caller.hash, id, scheduledAt });
          return Response.json({ object: "email", id });
        }),
      },
      "/emails/:id/cancel": {
        POST: handle(async (req) => {
          const caller = await authenticate(req);
          const id = req.params["id"];
          await rpc("cancelEmail", { tokenHash: caller.hash, id });
          return Response.json({ object: "email", id });
        }),
      },
      "/domains": {
        GET: handle(async (req) => {
          const caller = await authenticate(req);
          const data = await rpc("listDomains", { tokenHash: caller.hash }, b.array(b.unknown()));
          return Response.json({ object: "list", data });
        }),
        POST: handle(async (req) => {
          const caller = await authenticate(req);
          const parsed = b.object({ name: b.string().min(1).max(253) }).safeParse(await json(req));
          if (!parsed.success) throw invalid(parsed.error);
          return Response.json(
            await rpc("addDomain", { tokenHash: caller.hash, name: parsed.data.name }),
          );
        }),
      },
      "/domains/:name": {
        GET: handle(async (req) => {
          const caller = await authenticate(req);
          return Response.json(
            await rpc("getDomain", { tokenHash: caller.hash, name: req.params["name"] }),
          );
        }),
      },
      "/domains/:name/dmarc": {
        GET: handle(async (req) => {
          const caller = await authenticate(req);
          const raw = new URL(req.url).searchParams.get("days") ?? "7";
          const days = Number(raw);
          if (!Number.isInteger(days) || days < 1 || days > 90) {
            throw new ApiError(
              422,
              "validation_error",
              "`days` must be a whole number from 1 to 90",
            );
          }
          return Response.json(
            await rpc("dmarcReports", { tokenHash: caller.hash, domain: req.params["name"], days }),
          );
        }),
      },
      "/webhooks": {
        GET: handle(async (req) => {
          const caller = await authenticate(req);
          const data = await rpc("listWebhooks", { tokenHash: caller.hash }, b.array(b.unknown()));
          return Response.json({ object: "list", data });
        }),
        POST: handle(async (req) => {
          const caller = await authenticate(req);
          const parsed = b
            .object({ endpoint: b.string().max(2048), events: b.array(b.string()).optional() })
            .safeParse(await json(req));
          if (!parsed.success) throw invalid(parsed.error);
          return Response.json(
            await rpc("createWebhook", {
              tokenHash: caller.hash,
              url: parsed.data.endpoint,
              ...(parsed.data.events ? { events: parsed.data.events } : {}),
            }),
          );
        }),
      },
      "/webhooks/:id": {
        DELETE: handle(async (req) => {
          const caller = await authenticate(req);
          return Response.json(
            await rpc("deleteWebhook", { tokenHash: caller.hash, id: req.params["id"] }),
          );
        }),
      },
      "/stats": {
        GET: handle(async (req) => {
          const caller = await authenticate(req);
          const q = new URL(req.url).searchParams;
          const day = (t: number) => new Date(t).toISOString().slice(0, 10);
          const date = (name: string) => {
            const v = q.get(name);
            if (v !== null && (!/^\d{4}-\d{2}-\d{2}$/.test(v) || Number.isNaN(Date.parse(v)))) {
              throw new ApiError(422, "validation_error", `${name} must be a date like 2026-10-20`);
            }
            return v;
          };
          const until = date("until") ?? day(Date.now());
          const since = date("since") ?? day(Date.parse(until) - 6 * 86_400_000);
          return Response.json(
            await rpc("stats", {
              tokenHash: caller.hash,
              since,
              until,
              ...(q.get("domain") ? { domain: q.get("domain") } : {}),
              ...(q.get("tag") ? { tag: q.get("tag") } : {}),
            }),
          );
        }),
      },
      "/suppressions": {
        GET: handle(async (req) => {
          const caller = await authenticate(req);
          const data = await rpc(
            "listSuppressions",
            { tokenHash: caller.hash },
            b.array(b.unknown()),
          );
          return Response.json({ object: "list", data });
        }),
        POST: handle(async (req) => {
          const caller = await authenticate(req);
          const parsed = b
            .object({ email: b.string().max(320), scope: b.enum(["all", "bulk"]).optional() })
            .safeParse(await json(req));
          if (!parsed.success) throw invalid(parsed.error);
          return Response.json(
            await rpc("addSuppression", { tokenHash: caller.hash, ...parsed.data }),
          );
        }),
      },
      "/suppressions/:email": {
        DELETE: handle(async (req) => {
          const caller = await authenticate(req);
          const scope = new URL(req.url).searchParams.get("scope");
          return Response.json(
            await rpc("removeSuppression", {
              tokenHash: caller.hash,
              email: decodeURIComponent(req.params["email"] ?? ""),
              ...(scope === "all" || scope === "bulk" ? { scope } : {}),
            }),
          );
        }),
      },
      "/u/:token": {
        GET: (req) => {
          const token = req.params.token;
          if (!/^[a-z2-7]{20,80}$/.test(token))
            return page("This unsubscribe link is not valid.", 404);
          return page(
            `<form method="post"><p>Stop receiving these emails?</p><button type="submit">Unsubscribe</button></form>`,
          );
        },
        POST: async (req) => {
          const token = req.params.token;
          if (!/^[a-z2-7]{20,80}$/.test(token))
            return page("This unsubscribe link is not valid.", 404);
          try {
            await core.call("unsubscribe", { token }, { timeoutMs: 10_000 });
          } catch (err) {
            const e = fromRpc(err);
            return page(
              e.status === 404
                ? "This unsubscribe link is not valid."
                : "Please try again in a minute.",
              e.status,
            );
          }
          return page("You are unsubscribed. You will not receive these emails any more.");
        },
      },
      "/doctor": {
        GET: handle(async (req) => {
          const caller = await authenticate(req);
          return Response.json(await rpc("doctor", { tokenHash: caller.hash }));
        }),
      },
      "/domains/:name/rotate": {
        POST: handle(async (req) => {
          const caller = await authenticate(req);
          return Response.json(
            await rpc("rotateDomain", { tokenHash: caller.hash, name: req.params["name"] }),
          );
        }),
      },
      "/ips": {
        GET: handle(async (req) => {
          const caller = await authenticate(req);
          const data = await rpc("ips", { tokenHash: caller.hash }, b.array(b.unknown()));
          return Response.json({ object: "list", data });
        }),
      },
      "/holds": {
        GET: handle(async (req) => {
          const caller = await authenticate(req);
          const all = new URL(req.url).searchParams.get("all") === "true";
          return Response.json(await rpc("holds", { tokenHash: caller.hash, all }));
        }),
      },
      "/holds/:id": {
        DELETE: handle(async (req) => {
          const caller = await authenticate(req);
          return Response.json(
            await rpc("releaseHold", { tokenHash: caller.hash, id: req.params["id"] }),
          );
        }),
      },
      "/queue": {
        GET: handle(async (req) => {
          const caller = await authenticate(req);
          return Response.json(await rpc("queue", { tokenHash: caller.hash }));
        }),
      },
      "/queue/suspensions": {
        POST: handle(async (req) => {
          const caller = await authenticate(req);
          const parsed = suspendSchema.safeParse(await json(req));
          if (!parsed.success) throw invalid(parsed.error);
          const until = parsed.data.until === undefined ? null : Date.parse(parsed.data.until);
          if (until !== null && Number.isNaN(until)) {
            throw new ApiError(422, "validation_error", "`until` must be an ISO 8601 date");
          }
          const { target, reason } = parsed.data;
          return Response.json(
            await rpc("suspend", { tokenHash: caller.hash, target, reason, until }),
          );
        }),
      },
      "/queue/suspensions/:target": {
        DELETE: handle(async (req) => {
          const caller = await authenticate(req);
          return Response.json(
            await rpc("resume", { tokenHash: caller.hash, target: req.params["target"] }),
          );
        }),
      },
      "/queue/fail": {
        POST: handle(async (req) => removeQueued(req, "fail")),
      },
      "/queue/cancel": {
        POST: handle(async (req) => removeQueued(req, "cancel")),
      },
      "/metrics": {
        GET: handle(async (req) => {
          const caller = await authenticate(req);
          const r = await rpc(
            "metrics",
            { tokenHash: caller.hash },
            b.object({ text: b.string() }),
          );
          return new Response(r.text, {
            headers: {
              "content-type": "application/openmetrics-text; version=1.0.0; charset=utf-8",
            },
          });
        }),
      },
      "/paths": {
        GET: handle(async (req) => {
          const caller = await authenticate(req);
          const data = await rpc("paths", { tokenHash: caller.hash }, b.array(b.unknown()));
          return Response.json({ object: "list", data });
        }),
      },
      "/domains/:name/verify": {
        POST: handle(async (req) => {
          const caller = await authenticate(req);
          return Response.json(
            await rpc("verifyDomain", { tokenHash: caller.hash, name: req.params["name"] }),
          );
        }),
      },
    },
    fetch() {
      return errorResponse(new ApiError(404, "not_found", "Not found"));
    },
    error(err) {
      log.error("unhandled request error", { error: err.message });
      return errorResponse(new ApiError(500, "application_error", "Internal server error"));
    },
  });
}
