import type { Database } from "bun:sqlite";
import type { Logger } from "../core/log.ts";
import type { Writer } from "../core/store/writer.ts";
import { parseCheckReply, parseScanReply } from "../hooks/reply.ts";
import { addHook, type Hook, listHooks, removeHook } from "../hooks/store.ts";
import { type Methods, method, type RpcClient, RpcError } from "../ipc/rpc.ts";
import { parseMilterAddress } from "../milter/client.ts";
import { b } from "../validate/schema.ts";
import { resolveActor } from "./actor.ts";
import { project, tokenHash } from "./wire.ts";

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

  const score = async (
    kind: "scan" | "inbound",
    data: string,
    headers: Record<string, string>,
  ): Promise<number | null> => {
    let highest: number | null = null;
    for (const h of listHooks(db, kind)) {
      const r = await post(h, "message/rfc822", data, headers);
      const s = r.ok ? parseScanReply(r.status, r.body) : r.error;
      if (typeof s === "string") {
        failed(h, s);
        continue;
      }
      if (h.maxScore !== null && s >= h.maxScore) {
        throw new RpcError(
          "refused",
          `The content check refused this email (score ${s}, limit ${h.maxScore}).`,
        );
      }
      highest = highest === null ? s : Math.max(highest, s);
    }
    return highest;
  };

  const milterResult = b.union([
    b.object({ action: b.literal("accept"), data: b.string() }),
    b.object({ action: b.enum(["reject", "tempfail"]), text: b.string().nullable() }),
    b.object({ action: b.literal("failed"), error: b.string() }),
  ]);

  const filter = async (
    data: string,
    m: { id: string; from: string; recipients: string[]; user: string },
  ): Promise<string> => {
    await score("scan", data, {
      From: m.from,
      ...(m.recipients[0] ? { Rcpt: m.recipients[0] } : {}),
    });
    let out = data;
    for (const h of listHooks(db, "milter")) {
      let r: b.infer<typeof milterResult>;
      try {
        r = await delivery.call(
          "milter",
          { address: h.url, timeoutMs: h.timeoutMs, ...m, data: out },
          { result: milterResult, timeoutMs: h.timeoutMs + 5_000 },
        );
      } catch (err) {
        r = { action: "failed", error: (err as Error).message };
      }
      if (r.action === "accept") out = r.data;
      else if (r.action === "failed") failed(h, r.error);
      else if (r.action === "reject") {
        throw new RpcError(
          "refused",
          r.text
            ? `A content filter refused this email: ${r.text}`
            : "A content filter refused this email.",
        );
      } else {
        throw new RpcError(
          "hook-failed",
          r.text
            ? `A content filter asks to try again later: ${r.text}`
            : "A content filter asks to try again later.",
        );
      }
    }
    return out;
  };

  const printable = (v: string) => v.replace(/[^\x20-\x7e]/g, "").slice(0, 1000);

  const methods: Methods = {
    addHook: method(
      b.object({
        kind: b.enum(["check", "scan", "inbound", "milter"]),
        url: b.string().max(2048),
        timeoutMs: b.number().int().min(100).max(60_000),
        onError: b.enum(["accept", "refuse"]),
        maxScore: b.number().nullable(),
      }),
      async (p) => {
        if (p.kind === "milter") {
          if (!parseMilterAddress(p.url)) {
            throw new RpcError(
              "invalid",
              "a milter address looks like inet:127.0.0.1:11332 or unix:/run/milter.sock",
            );
          }
          if (p.maxScore !== null)
            throw new RpcError("invalid", "a milter hook has no score limit");
        } else {
          let url: URL;
          try {
            url = new URL(p.url);
          } catch {
            throw new RpcError("invalid", "the hook URL is not valid");
          }
          if (url.protocol !== "https:" && url.protocol !== "http:") {
            throw new RpcError("invalid", "the hook URL must be http or https");
          }
        }
        if (p.kind === "scan" && p.maxScore === null) {
          throw new RpcError("invalid", "a scan hook needs a score limit");
        }
        if (p.kind === "check" && p.maxScore !== null) {
          throw new RpcError("invalid", "a check hook has no score limit");
        }
        const h = await writer.run((d) => addHook(d, p, now()));
        log.info("hook added", { hook: h.id, kind: h.kind, url: h.url });
        return view(h);
      },
    ),

    listHooks: method(b.object({}), () => listHooks(db).map(view)),

    inboundScan: method(
      b.object({
        raw: b.string().max(60 * 1024 * 1024),
        from: b.string().max(1000),
        recipients: b.array(b.string().max(320)).min(1).max(100),
        ip: b.string().max(64),
        helo: b.string().max(1000),
      }),
      async (p) => {
        try {
          const s = await score("inbound", p.raw, {
            From: printable(p.from),
            Rcpt: printable(p.recipients[0] ?? ""),
            Ip: printable(p.ip),
            Helo: printable(p.helo),
          });
          return { result: "ok" as const, score: s };
        } catch (err) {
          if (!(err instanceof RpcError)) throw err;
          log.info("inbound scan refused a message", { ip: p.ip, reason: err.message });
          return { result: err.code === "refused" ? ("refused" as const) : ("failed" as const) };
        }
      },
    ),

    removeHook: method(b.object({ id: b.string().max(64) }), async ({ id }) => {
      if (!(await writer.run((d) => removeHook(d, id)))) {
        throw new RpcError("not-found", "no hook with that id");
      }
      return { id, deleted: true };
    }),

    checkEmail: method(
      b.object({ tokenHash, project, email: b.record(b.string(), b.unknown()) }),
      async (p) => {
        const apiKey = resolveActor(db, p, "send").key?.id ?? null;
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
    filter,
    hasCheckHooks: () => listHooks(db, "check").length > 0,
  };
}
