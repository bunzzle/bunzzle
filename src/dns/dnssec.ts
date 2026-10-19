import type { Resolver, Server } from "./resolver.ts";

export const DNSSEC_PROBE = "iana.org";

function loopback(host: string): boolean {
  return host === "::1" || host === "localhost" || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host);
}

export async function localValidatingResolver(
  servers: Server[],
  resolver: Resolver,
): Promise<boolean> {
  if (servers.length === 0 || !servers.every((s) => loopback(s.host))) return false;
  try {
    const answer = await resolver.query(DNSSEC_PROBE, "A");
    return answer.rcode === 0 && answer.authenticated;
  } catch {
    return false;
  }
}
