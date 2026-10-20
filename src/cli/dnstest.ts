import type { Config } from "../config.ts";
import { cachingResolver } from "../dns/cache.ts";
import { createResolver, parseServer, type Resolver, systemServers } from "../dns/resolver.ts";
import { type DnsProvider, openDnsProvider } from "../net/providers.ts";
import { guardedRequest } from "../net/request.ts";
import { UsageError } from "./args.ts";

const WAIT_MS = 120_000;
const POLL_MS = 2_000;

export interface DnsTestDeps {
  opened: { name: string; provider: DnsProvider } | null;
  resolver: Resolver;
  serverResolver: (ip: string) => Resolver;
  token: string;
  print: (line: string) => void;
  now: () => number;
  sleep: (ms: number) => Promise<void>;
}

async function defaultDeps(config: Config): Promise<DnsTestDeps> {
  const servers = config.dnsServers.length
    ? config.dnsServers.map(parseServer)
    : await systemServers();
  const resolver = createResolver({ servers });
  const cached = cachingResolver(resolver);
  const api = (r: Parameters<typeof guardedRequest>[0]) =>
    guardedRequest(r, {
      resolver: cached,
      allowPrivate: config.allowPrivateDestinations,
      timeoutMs: 15_000,
    });
  return {
    opened: await openDnsProvider(config, servers, api),
    resolver,
    serverResolver: (ip) =>
      createResolver({ servers: [{ host: ip, port: 53 }], timeoutMs: 3_000, attempts: 1 }),
    token: crypto.getRandomValues(new Uint8Array(144)).toHex(),
    print: (line) => console.log(line),
    now: Date.now,
    sleep: Bun.sleep,
  };
}

async function nameServers(
  resolver: Resolver,
  domain: string,
): Promise<{ host: string; ips: string[] }[]> {
  const labels = domain.split(".");
  for (let i = 0; i <= labels.length - 2; i++) {
    const answer = await resolver.query(labels.slice(i).join("."), "NS");
    const hosts = answer.records.flatMap((r) => (r.type === "NS" ? [r.target] : []));
    if (hosts.length === 0) continue;
    return Promise.all(
      hosts.sort().map(async (host) => {
        const a = await resolver.query(host, "A").catch(() => null);
        return {
          host,
          ips: (a?.records ?? []).flatMap((r) => (r.type === "A" ? [r.address] : [])),
        };
      }),
    );
  }
  return [];
}

async function serves(d: DnsTestDeps, ips: string[], name: string, content: string) {
  for (const ip of ips) {
    const answer = await d
      .serverResolver(ip)
      .query(name, "TXT")
      .catch(() => null);
    const found = (answer?.records ?? []).some(
      (r) => r.type === "TXT" && r.strings.join("") === content,
    );
    if (found) return true;
  }
  return false;
}

export async function dnsTestCommand(
  argv: string[],
  config: Config,
  deps?: DnsTestDeps,
): Promise<number> {
  const [arg] = argv;
  if (argv.length !== 1 || !arg || arg.startsWith("-")) {
    throw new UsageError("usage: bunzzle dns-test DOMAIN");
  }
  const domain = arg.toLowerCase().replace(/\.$/, "");
  const d = deps ?? (await defaultDeps(config));
  if (!d.opened) {
    d.print(
      "no DNS provider is set: configure Cloudflare, DNS updates, Route 53 or deSEC (docs/configuration.md)",
    );
    return 1;
  }
  const { name: providerName, provider } = d.opened;
  const rec = {
    type: "TXT" as const,
    name: `_bunzzle-test.${domain}`,
    content: `bunzzle-test=${d.token}`,
  };
  let failed = false;
  const step = (ok: boolean, text: string) => {
    d.print(`  ${ok ? "[ok]  " : "[FAIL]"} ${text}`);
    if (!ok) failed = true;
  };

  d.print(`provider: ${providerName}`);
  const created = await provider.upsert(rec);
  if (!created.ok) {
    step(false, `publish TXT ${rec.name}: ${created.error}`);
    return 1;
  }
  step(true, `published TXT ${rec.name} (${rec.content.length} characters)`);
  try {
    const again = await provider.upsert(rec);
    if (!again.ok) step(false, `read it back from ${providerName}: ${again.error}`);
    else if (again.action !== "exists") {
      step(false, `read it back from ${providerName}: the value did not match (${again.action})`);
    } else step(true, `read it back from ${providerName}`);

    const servers = await nameServers(d.resolver, domain).catch(() => []);
    if (servers.length === 0) {
      step(false, `no name servers found for ${domain}`);
    } else {
      const start = d.now();
      const waiting = new Set(servers.map((s) => s.host));
      for (;;) {
        for (const s of servers) {
          if (waiting.has(s.host) && (await serves(d, s.ips, rec.name, rec.content))) {
            waiting.delete(s.host);
          }
        }
        if (waiting.size === 0 || d.now() - start >= WAIT_MS) break;
        await d.sleep(POLL_MS);
      }
      const seconds = Math.round((d.now() - start) / 1_000);
      if (waiting.size === 0) {
        step(true, `served by ${servers.map((s) => s.host).join(", ")} after ${seconds} s`);
      } else {
        step(false, `not served by ${[...waiting].join(", ")} after ${seconds} s`);
      }
    }
  } finally {
    const removed = await provider.remove(rec);
    if (!removed.ok) step(false, `remove TXT ${rec.name}: ${removed.error}`);
    else if (removed.action !== "removed") {
      step(false, `remove TXT ${rec.name}: it was already gone`);
    } else step(true, `removed TXT ${rec.name}`);
  }
  d.print(failed ? "\nthe provider does not work yet" : `\n${providerName} works`);
  return failed ? 1 : 0;
}
