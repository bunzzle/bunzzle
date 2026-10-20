import type { Config } from "../config.ts";
import { createResolver, parseServer, type Server } from "../dns/resolver.ts";
import { type CfRecord, type CfResult, Cloudflare } from "./cloudflare.ts";
import { Desec } from "./desec.ts";
import type { RequestInput, RequestResult } from "./request.ts";
import { DnsUpdater } from "./rfc2136.ts";
import { Route53 } from "./route53.ts";

export interface DnsProvider {
  upsert(rec: CfRecord): Promise<CfResult>;
  remove(rec: CfRecord): Promise<CfResult>;
}

const secret = async (file: string) => (await Bun.file(file).text()).trim();

export async function openDnsProvider(
  config: Config,
  servers: Server[],
  api: (r: RequestInput) => Promise<RequestResult>,
): Promise<{ name: string; provider: DnsProvider } | null> {
  const token =
    config.cloudflareToken ??
    (config.cloudflareTokenFile ? await secret(config.cloudflareTokenFile) : null);
  if (token) {
    return { name: "cloudflare", provider: new Cloudflare(token, config.cloudflareUrl, api) };
  }
  const u = config.dnsUpdate;
  if (u) {
    return {
      name: "dns-update",
      provider: new DnsUpdater(
        parseServer(u.server),
        {
          name: u.keyName,
          algorithm: u.algorithm,
          secret: Uint8Array.fromBase64(await secret(u.keyFile)),
        },
        createResolver({ servers }),
      ),
    };
  }
  const r53 = config.route53;
  if (r53) {
    return {
      name: "route53",
      provider: new Route53(
        { accessKeyId: r53.accessKeyId, secretAccessKey: await secret(r53.secretKeyFile) },
        r53.url,
        api,
      ),
    };
  }
  if (config.desec) {
    return {
      name: "desec",
      provider: new Desec(await secret(config.desec.tokenFile), config.desec.url, api),
    };
  }
  return null;
}
