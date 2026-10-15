import type { Family } from "../dns/ip.ts";
import type { Resolver } from "../dns/resolver.ts";
import { guardedRequest } from "./request.ts";

export interface PostOptions {
  resolver: Resolver;
  allowPrivate?: boolean;
  ownAddresses?: string[];
  families?: Family[];
  timeoutMs?: number;
  ca?: string;
}

export type PostResult = { ok: true; status: number } | { ok: false; error: string };

export async function guardedPost(
  url: string,
  headers: Record<string, string>,
  body: string,
  o: PostOptions,
): Promise<PostResult> {
  const r = await guardedRequest(
    { method: "POST", url, headers: { "Content-Type": "application/json", ...headers }, body },
    o,
  );
  return r.ok ? { ok: true, status: r.status } : { ok: false, error: r.error };
}
