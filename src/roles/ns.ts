import { type Config, ConfigError } from "../config.ts";
import type { Logger } from "../core/log.ts";
import { method, RpcError, serveRpc } from "../ipc/rpc.ts";
import { DEFAULT_LIMITS } from "../ns/limits.ts";
import { NsServer } from "../ns/server.ts";
import { ZoneError, zoneWire } from "../ns/zone.ts";
import { b } from "../validate/schema.ts";
import { onStop, privateDir, ready } from "./runtime.ts";
import { sockets } from "./wire.ts";

export async function runNs(config: Config, log: Logger) {
  const ns = config.ns;
  if (!ns) throw new ConfigError("the ns role needs BUNZZLE_NS_ZONE");
  const server = new NsServer({
    apex: ns.zone,
    names: ns.names,
    limits: { ...DEFAULT_LIMITS, v4Prefix: ns.v4Prefix, v6Prefix: ns.v6Prefix },
  });

  await privateDir(config.dataDir);
  const saved = `${config.dataDir}/ns-zone.json`;
  const file = Bun.file(saved);
  if (await file.exists()) {
    try {
      const wire = zoneWire.parse(await file.json());
      server.load(wire);
      log.info("loaded the saved zone", { serial: wire.serial });
    } catch (err) {
      log.error("cannot load the saved zone", { error: (err as Error).message });
    }
  }

  const rpc = await serveRpc(sockets(config.runDir).ns, {
    zone: method(zoneWire, async (wire) => {
      try {
        server.load(wire);
      } catch (err) {
        if (err instanceof ZoneError) throw new RpcError("invalid", err.message);
        throw err;
      }
      const tmp = `${saved}.tmp`;
      await Bun.write(tmp, JSON.stringify(wire));
      await Bun.$`mv ${tmp} ${saved}`.quiet();
      return { serial: wire.serial };
    }),
    stats: method(b.object({}), () => server.snapshot()),
  });

  const ports: number[] = [];
  for (const ip of ns.listen) ports.push(await server.listen(ip, ns.port));

  onStop(log, () => {
    server.stop();
    rpc.stop();
  });
  log.info("ns ready", { zone: ns.zone, listen: ns.listen, serial: server.serial });
  ready({ listen: ns.listen, ports, serial: server.serial });
}
