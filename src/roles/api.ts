import type { Config } from "../config.ts";
import type { Logger } from "../core/log.ts";
import { startApp } from "../http/app.ts";
import { RpcClient } from "../ipc/rpc.ts";
import { startSubmission } from "../submission/server.ts";
import { onStop, ready } from "./runtime.ts";
import { sockets } from "./wire.ts";

async function loadCert(certFile: string, keyFile: string): Promise<{ cert: string; key: string }> {
  const cert = await Bun.file(certFile).text();
  const key = await Bun.file(keyFile).text();
  if (!cert.includes("-----BEGIN CERTIFICATE-----")) {
    throw new Error(`${certFile} is not a PEM certificate`);
  }
  if (!/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(key)) {
    throw new Error(`${keyFile} is not a PEM private key`);
  }
  return { cert, key };
}

export async function runApi(config: Config, log: Logger) {
  const core = new RpcClient(sockets(config.runDir).core);
  const server = startApp({ core, log, hostname: config.host, port: config.port });
  const listeners: { port: number; stop(): void }[] = [];
  const sub = config.submission;
  if (sub) {
    const tls = await loadCert(sub.certFile, sub.keyFile);
    const name = sub.hostname ?? "localhost";
    for (const [port, implicitTls] of [
      [sub.port, false],
      [sub.tlsPort, true],
    ] as const) {
      if (port === null) continue;
      listeners.push(
        startSubmission({ core, log, hostname: sub.host, port, name, tls, implicitTls }),
      );
    }
  }
  onStop(log, async () => {
    for (const l of listeners) l.stop();
    await server.stop();
    core.close();
  });
  ready({
    url: server.url.href,
    ...(listeners.length ? { submissionPorts: listeners.map((l) => l.port) } : {}),
  });
}
