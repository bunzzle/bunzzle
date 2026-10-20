import { b } from "../validate/schema.ts";

export const CHANGEABLE = ["subject", "html", "text", "headers", "tags"] as const;

const checkReply = b.discriminatedUnion("action", [
  b.object({ action: b.literal("accept") }),
  b.object({ action: b.literal("refuse"), reason: b.string().max(1000).optional() }),
  b.object({ action: b.literal("change"), email: b.record(b.string(), b.unknown()) }),
]);

export type CheckReply = b.infer<typeof checkReply>;

export function parseCheckReply(status: number, body: string): CheckReply | string {
  if (status === 204) return { action: "accept" };
  if (status < 200 || status > 299) return `answered ${status}`;
  let json: unknown;
  try {
    json = JSON.parse(body);
  } catch {
    return "the reply is not JSON";
  }
  const r = checkReply.safeParse(json);
  if (!r.success) return "the reply needs `action`: accept, refuse or change";
  if (r.data.action === "change") {
    const extra = Object.keys(r.data.email).filter(
      (k) => !(CHANGEABLE as readonly string[]).includes(k),
    );
    if (extra.length > 0) return `a hook cannot change ${extra.join(", ")}`;
  }
  return r.data;
}

export function parseScanReply(status: number, body: string): number | string {
  if (status < 200 || status > 299) return `answered ${status}`;
  let json: unknown;
  try {
    json = JSON.parse(body);
  } catch {
    return "the reply is not JSON";
  }
  const score = (json as { score?: unknown } | null)?.score;
  return typeof score === "number" && Number.isFinite(score)
    ? score
    : "the reply has no numeric `score`";
}
