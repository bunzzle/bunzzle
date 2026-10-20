import type { Database } from "bun:sqlite";
import { allows, keyForHash } from "../accounts/api-keys.ts";
import type { Logger } from "../core/log.ts";
import type { Writer } from "../core/store/writer.ts";
import { parseCheckReply, parseScanReply } from "../hooks/reply.ts";
import { addHook, type Hook, listHooks, removeHook } from "../hooks/store.ts";
import { type Methods, method, type RpcClient, RpcError } from "../ipc/rpc.ts";
import { b } from "../validate/schema.ts";
import { tokenHash } from "./wire.ts";

export interface HookDeps {
  db: Database;
  writer: Writer;
  log: Logger;
  delivery: RpcClient;
  now?: () => number;
}

const posted = b.union([
  b.object({ ok: b.literal(true), status: b.number(), body: b.string() }),
  b.object({ ok: b.literal(false), error: b.string() }),
]);

const view = (h: Hook) => ({
  object: "hook",
  id: h.id,
  kind: h.kind,
  url: h.url,
  timeout_ms: h.timeoutMs,
  on_error: h.onError,
  max_score: h.maxScore,
  created_at: new Date(h.createdAt).toISOString(),
});

export function hookMethods(deps: HookDeps) {
  const { db, writer, log, delivery } = deps;
  const now = deps.now ?? Date.now;

  const post = async (
    h: Hook,
    contentType: "application/json" | "message/rfc822",
    body: string,
    headers: Record<string, string> = {},
  ) => {
    try {
      return await delivery.call(
        "postHook",
        { url: h.url, contentType, headers, body, timeoutMs: h.timeoutMs },
        { result: posted, timeoutMs: h.timeoutMs + 5_000 },
      );
    } catch (err) {
      return { ok: false as const, error: (err as Error).message };
    }
  };

  const failed = (h: Hook, problem: string): void => {
    log.warn("hook failed", { hook: h.id, url: h.url, error: problem, onError: h.onError });
    if (h.onError === "refuse") {
      throw new RpcError("hook-failed", `A check before sending is not answering (${problem}).`);
    }
  };

  const scan = async (data: string, from: string, recipients: string[]) => {
    for (const h of listHooks(db, "scan")) {
      const r = await post(h, "message/rfc822", data, {
        From: from,
        ...(recipients[0] ? { Rcpt: recipients[0] } : {}),
      });
      const score = r.ok ? parseScanReply(r.status, r.body) : r.error;
      if (typeof score === "string") {
        failed(h, score);
        continue;
      }
      if (h.maxScore !== null && score >= h.maxScore) {
        throw new RpcError(
          "refused",
          `The content check refused this email (score ${score}, limit ${h.maxScore}).`,
        );
      }
    }
  };

  const methods: Methods = {
    addHook: method(
      b.object({
        kind: b.enum(["check", "scan"]),
        url: b.string().max(2048),
        timeoutMs: b.number().int().min(100).max(60_000),
        onError: b.enum(["accept", "refuse"]),
        maxScore: b.number().nullable(),
      }),
      async (p) => {
        let url: URL;
        try {
          url = new URL(p.url);
        } catch {
          throw new RpcError("invalid", "the hook URL is not valid");
        }
        if (url.protocol !== "https:" && url.protocol !== "http:") {
          throw new RpcError("invalid", "the hook URL must be http or https");
        }
        if (p.kind === "scan" && p.maxScore === null) {
          throw new RpcError("invalid", "a scan hook needs a score limit");
        }
        if (p.kind === "check" && p.maxScore !== null) {
          throw new RpcError("invalid", "only a scan hook has a score limit");
        }
        const h = await writer.run((d) => addHook(d, p, now()));
        log.info("hook added", { hook: h.id, kind: h.kind, url: h.url });
        return view(h);
      },
    ),

    listHooks: method(b.object({}), () => listHooks(db).map(view)),

    removeHook: method(b.object({ id: b.string().max(64) }), async ({ id }) => {
      if (!(await writer.run((d) => removeHook(d, id)))) {
        throw new RpcError("not-found", "no hook with that id");
      }
      return { id, deleted: true };
    }),

    checkEmail: method(
      b.object({ tokenHash, email: b.record(b.string(), b.unknown()) }),
      async (p) => {
        let apiKey: string | null = null;
        if (p.tokenHash !== undefined) {
          const key = keyForHash(db, p.tokenHash);
          if (!key) throw new RpcError("unauthenticated", "API key is invalid");
          if (!allows(key.scope, "send")) {
            throw new RpcError("forbidden", "this API key cannot send email");
          }
          apiKey = key.id;
        }
        let email = p.email;
        for (const h of listHooks(db, "check")) {
          const r = await post(
            h,
            "application/json",
            JSON.stringify({ email, api_key_id: apiKey }),
          );
          const reply = r.ok ? parseCheckReply(r.status, r.body) : r.error;
          if (typeof reply === "string") {
            failed(h, reply);
            continue;
          }
          if (reply.action === "refuse") {
            throw new RpcError(
              "refused",
              reply.reason ? `Refused before sending: ${reply.reason}` : "Refused before sending.",
            );
          }
          if (reply.action === "change") email = { ...email, ...reply.email };
        }
        return { email };
      },
    ),
  };

  return {
    methods,
    scan,
    hasCheckHooks: () => listHooks(db, "check").length > 0,
  };
}
