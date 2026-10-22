export interface Delegation {
  parent: string | null;
  asked: string | null;
  ns: string[];
  glue: Record<string, string[]>;
  addresses: Record<string, string[]>;
  error: string | null;
}

export function delegationProblems(
  d: Delegation,
  zone: string,
  names: string[],
  listen: string[],
): string[] {
  if (d.error) return [d.error];
  const want = names.map((n) => n.toLowerCase().replace(/\.$/, "")).sort();
  const problems: string[] = [];
  if (d.ns.length === 0) problems.push(`${d.parent} does not delegate ${zone}`);
  for (const n of want) if (!d.ns.includes(n)) problems.push(`${n} is missing from the NS set`);
  for (const n of d.ns)
    if (!want.includes(n)) problems.push(`${n} is in the NS set but not in BUNZZLE_NS_NAMES`);
  const under = (n: string) => n === zone || n.endsWith(`.${zone}`);
  for (const n of want.filter((x) => d.ns.includes(x))) {
    if (under(n) && !d.glue[n]?.length) problems.push(`${n} has no glue at ${d.parent}`);
    const ips = d.addresses[n] ?? [];
    if (ips.length === 0) problems.push(`${n} has no address`);
    for (const ip of ips) {
      if (!listen.includes(ip))
        problems.push(`${n} points to ${ip}, which is not in BUNZZLE_NS_LISTEN`);
    }
  }
  return problems;
}
