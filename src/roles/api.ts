import type { Config } from "../config.ts";
import type { Logger } from "../core/log.ts";
import { startApp } from "../http/app.ts";
import { startTrackServer, trackCerts } from "../http/track.ts";
import { RpcClient } from "../ipc/rpc.ts";
import { startSubmission } from "../submission/server.ts";
import { every, onStop, ready, reportUsage, watchFile } from "./runtime.ts";
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
  const waiting = sub && config.acme && !(await Bun.file(sub.certFile).exists());
  if (waiting) log.warn("SMTP submission waits for its TLS certificate");
  if (sub && !waiting) {
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
  const track = config.track;
  let tracker: ReturnType<typeof startTrackServer> | null = null;
  let loaded = "";
  const loadTracker = async () => {
    if (!track) return;
    const certs = await trackCerts(track.dir);
    const seen = JSON.stringify(certs);
    if (seen === loaded) return;
    loaded = seen;
    await tracker?.stop();
    tracker = null;
    if (certs.length === 0) {
      log.warn("click and open tracking waits for a certificate", { dir: track.dir });
      return;
    }
    const started = startTrackServer({ core, log, hostname: track.host, port: track.port, certs });
    tracker = started;
    log.info("tracking listener ready", {
      port: started.port,
      hosts: certs.map((c) => c.serverName),
    });
  };
  await loadTracker();
  const stopTrackWatch = track ? every(10 * 60_000, loadTracker) : () => {};
  const stopUsage = reportUsage(core, "api");
  const restart = onStop(log, async () => {
    stopTrackWatch();
    stopUsage();
    await tracker?.stop();
    for (const l of listeners) l.stop();
    await server.stop();
    core.close();
  });
  if (sub && config.acme) {
    await watchFile(sub.certFile, 10 * 60_000, () => {
      log.info("new TLS certificate: restarting to load it");
      void restart("new certificate");
    });
  }
  ready({
    url: server.url.href,
    ...(listeners.length ? { submissionPorts: listeners.map((l) => l.port) } : {}),
    ...(tracker ? { trackPort: (tracker as ReturnType<typeof startTrackServer>).port } : {}),
  });
}
