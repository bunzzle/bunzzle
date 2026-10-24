import type { Socket } from "bun";
import type { Logger } from "../core/log.ts";
import { familyOf } from "../dns/ip.ts";
import { pipeTo, refuse } from "../ipc/pipe.ts";
import type { StreamHandler } from "../ipc/rpc.ts";
import { b } from "../validate/schema.ts";

const request = b.object({
  host: b.string().max(64),
  port: b.number().int().min(1).max(65535),
  source: b.string().max(64),
});

export interface RelayOptions {
  port: number;
  log: Logger;
}

export function relayStream(o: RelayOptions) {
  return (params: unknown, down: Socket<undefined>): StreamHandler => {
    const p = request.safeParse(params);
    if (!p.success) return refuse(down, "invalid", "bad stream request");
    const { host, port, source } = p.data;
    if (port !== o.port) return refuse(down, "invalid", `only port ${o.port} is allowed`);
    const family = familyOf(host);
    if (!family || familyOf(source) !== family) {
      return refuse(down, "invalid", "host and source must be IP addresses of the same family");
    }
    return pipeTo(down, { host, port, source }, o.log, "egress");
  };
}
