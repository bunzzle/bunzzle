import type { SourceIp } from "../config.ts";
import { RpcError } from "../ipc/rpc.ts";
import { asciiDomain } from "../mime/address.ts";
import { DOMAIN } from "./wire.ts";

export function knownPool(ips: SourceIp[] | undefined, pool: string): void {
  const pools = [...new Set((ips ?? []).map((x) => x.pool))];
  if (!pools.includes(pool)) {
    throw new RpcError(
      "invalid",
      `no source IP is in the pool ${pool}; pools in BUNZZLE_SOURCE_IPS: ${pools.join(", ") || "none"}`,
    );
  }
}

export function domainName(raw: string): string {
  let name: string;
  try {
    name = asciiDomain(raw);
  } catch (err) {
    throw new RpcError("invalid", (err as Error).message);
  }
  if (!DOMAIN.test(name)) throw new RpcError("invalid", `invalid domain: ${raw}`);
  return name;
}
