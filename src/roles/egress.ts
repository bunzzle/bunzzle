import { type Config, ConfigError } from "../config.ts";
import type { Logger } from "../core/log.ts";
import { relayStream } from "../egress/relay.ts";
import { type RpcServer, serveRpc } from "../ipc/rpc.ts";
import { nodeLinkMethods } from "../nodes/node.ts";
import { loadLinkTls, loadPeers } from "./node-link.ts";
import { onStop, ready } from "./runtime.ts";

export const DELIVERY_CALLS = new Set<string>(["stream"]);

export async function runEgress(config: Config, log: Logger): Promise<RpcServer> {
  const listen = config.egressListen;
  if (!listen) {
    throw new ConfigError(
      "invalid configuration:\n  BUNZZLE_EGRESS_LISTEN: set the <ip>:<port> core reaches this egress on",
    );
  }
  const tls = await loadLinkTls(config.nodeDir);
  const peers = await loadPeers(config.nodeDir);
  const server: RpcServer = await serveRpc(
    { ...listen, tls },
    nodeLinkMethods(config.nodeDir, tls, () => server, peers),
    {
      onRefused: (reason, remote) => log.warn("node link refused", { reason, remote }),
      stream: relayStream({ port: config.smtpPort, log }),
      allow: (pin, call) =>
        peers.core.includes(pin) || (peers.delivery.includes(pin) && DELIVERY_CALLS.has(call)),
    },
  );
  onStop(log, () => server.stop());
  log.info("egress ready", { link: `${listen.hostname}:${listen.port}` });
  ready();
  return server;
}
