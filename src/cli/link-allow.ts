import { type Config, parseLinkAddress } from "../config.ts";
import { call } from "./admin.ts";

const UNIT = "bunzzle-link.service";

export function linkHosts(addresses: string[]): string[] {
  const hosts = addresses.flatMap((a) => {
    const at = parseLinkAddress(a);
    return at ? [at.hostname] : [];
  });
  return [...new Set(hosts)].sort();
}

export function parseAllowed(value: string): string[] {
  return [
    ...new Set(
      value
        .split(/\s+/)
        .filter(Boolean)
        .map((x) => x.replace(/\/(32|128)$/, "")),
    ),
  ].sort();
}

export function linkUnitManaged(): Promise<boolean> {
  return Bun.file(`/etc/systemd/system/${UNIT}`).exists();
}

async function nodeHosts(config: Config): Promise<string[]> {
  const nodes = await call<{ address: string }[]>(config, "listNodes", {});
  return linkHosts(nodes.map((n) => n.address));
}

export async function allowLinks(config: Config): Promise<string[] | null> {
  if (!(await linkUnitManaged())) return null;
  const hosts = await nodeHosts(config);
  const set = hosts.length > 0 ? [`IPAddressAllow=${hosts.join(" ")}`] : [];
  await Bun.$`systemctl set-property ${UNIT} IPAddressAllow= ${set}`.quiet();
  return hosts;
}

export async function linkAllowCheck(
  config: Config,
): Promise<{ status: "ok" | "warn"; detail: string } | null> {
  if (!(await linkUnitManaged())) return null;
  const want = await nodeHosts(config);
  const out = await Bun.$`systemctl show -p IPAddressAllow --value ${UNIT}`.quiet().text();
  const have = parseAllowed(out);
  if (have.join(" ") === want.join(" ")) {
    return {
      status: "ok",
      detail: want.length > 0 ? `may reach ${want.join(", ")}` : "may reach no address",
    };
  }
  return {
    status: "warn",
    detail: `may reach ${have.join(", ") || "no address"}, the nodes are at ${want.join(", ") || "no address"}: run sudo bunzzle nodes allow`,
  };
}

export async function allowLinksAfterChange(config: Config) {
  try {
    printAllowed(await allowLinks(config));
  } catch (err) {
    console.error(
      `Could not set the addresses bunzzle-link may reach (${(err as Error).message.trim()}): run sudo bunzzle nodes allow`,
    );
  }
}

export function printAllowed(hosts: string[] | null) {
  if (hosts === null) return;
  console.log(`bunzzle-link may reach: ${hosts.join(", ") || "no address"}.`);
}
