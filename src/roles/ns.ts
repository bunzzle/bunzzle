import { type Config, ConfigError } from "../config.ts";
import type { Logger } from "../core/log.ts";
import { method, RpcError, serveRpc } from "../ipc/rpc.ts";
import { DEFAULT_LIMITS } from "../ns/limits.ts";
import { limitSummary, NsServer } from "../ns/server.ts";
import { ZoneError, zoneWire } from "../ns/zone.ts";
import { b } from "../validate/schema.ts";
import { every, onStop, privateDir, ready } from "./runtime.ts";
import { sockets } from "./wire.ts";

export async function runNs(config: Config, log: Logger) {
  const ns = config.ns;
  if (!ns) throw new ConfigError("the ns role needs BUNZZLE_NS_ZONE");
  const server = new NsServer({
    apex: ns.zone,
    names: ns.names,
    limits: { ...DEFAULT_LIMITS, v4Prefix: ns.v4Prefix, v6Prefix: ns.v6Prefix, slip: ns.slip },
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
  for (const ip of ns.listen) {
    try {
      ports.push(await server.listen(ip, ns.port));
    } catch (err) {
      const code = (err as { code?: string }).code ?? null;
      log.error("ns cannot listen", {
        address: ip,
        port: ns.port,
        code,
        error: (err as Error).message,
        hint:
          code === "EADDRINUSE"
            ? "another program already uses this port for UDP or TCP"
            : code === "EACCES"
              ? "ports below 1024 need the CAP_NET_BIND_SERVICE capability"
              : code === "EADDRNOTAVAIL"
                ? "this address is not on any interface of this host"
                : null,
      });
      server.stop();
      throw err;
    }
  }

  let last = server.snapshot();
  const stopSummary = every(60_000, () => {
    const now = server.snapshot();
    const hit = limitSummary(last, now);
    last = now;
    if (hit) log.warn("ns limits hit in the last minute", hit);
  });

  onStop(log, () => {
    stopSummary();
    server.stop();
    rpc.stop();
  });
  log.info("ns ready", { zone: ns.zone, listen: ns.listen, serial: server.serial });
  ready({ listen: ns.listen, ports, serial: server.serial });
}
