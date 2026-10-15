import { familyOf, reverseName, sameAddress } from "./ip.ts";
import type { Resolver } from "./resolver.ts";

export interface ReverseCheck {
  ip: string;
  ptr: string | null;
  forwardConfirmed: boolean;
  problem: string | null;
}

export async function checkReverse(resolver: Resolver, ip: string): Promise<ReverseCheck> {
  const name = reverseName(ip);
  if (!name) return { ip, ptr: null, forwardConfirmed: false, problem: "not an IP address" };
  let ptr: string | null = null;
  try {
    const answer = await resolver.query(name, "PTR");
    for (const r of answer.records) if (r.type === "PTR") ptr ??= r.target;
  } catch (err) {
    return {
      ip,
      ptr: null,
      forwardConfirmed: false,
      problem: `PTR lookup failed: ${(err as Error).message}`,
    };
  }
  if (!ptr) return { ip, ptr: null, forwardConfirmed: false, problem: `no PTR record for ${ip}` };
  const family = familyOf(ip);
  try {
    const forward = await resolver.query(ptr, family === 6 ? "AAAA" : "A");
    const ok = forward.records.some(
      (r) => (r.type === "A" || r.type === "AAAA") && sameAddress(r.address, ip),
    );
    return {
      ip,
      ptr,
      forwardConfirmed: ok,
      problem: ok ? null : `${ptr} does not resolve back to ${ip}`,
    };
  } catch (err) {
    return {
      ip,
      ptr,
      forwardConfirmed: false,
      problem: `forward lookup failed: ${(err as Error).message}`,
    };
  }
}
