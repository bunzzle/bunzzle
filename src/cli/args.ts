export class UsageError extends Error {}

export interface ArgSpec {
  strings?: string[];
  lists?: string[];
  flags?: string[];
}

export interface Args {
  strings: Map<string, string>;
  lists: Map<string, string[]>;
  flags: Set<string>;
}

export function parseArgs(argv: string[], spec: ArgSpec): Args {
  const strings = new Set(spec.strings ?? []);
  const lists = new Set(spec.lists ?? []);
  const flags = new Set(spec.flags ?? []);
  const out: Args = { strings: new Map(), lists: new Map(), flags: new Set() };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] as string;
    if (!arg.startsWith("--")) throw new UsageError(`unexpected argument: ${arg}`);
    const eq = arg.indexOf("=");
    const name = eq > 0 ? arg.slice(2, eq) : arg.slice(2);
    if (flags.has(name)) {
      if (eq > 0) throw new UsageError(`--${name} takes no value`);
      out.flags.add(name);
      continue;
    }
    if (!strings.has(name) && !lists.has(name)) throw new UsageError(`unknown option: --${name}`);
    let value: string;
    if (eq > 0) value = arg.slice(eq + 1);
    else {
      const next = argv[i + 1];
      if (next === undefined) throw new UsageError(`--${name} needs a value`);
      value = next;
      i++;
    }
    if (lists.has(name)) out.lists.set(name, [...(out.lists.get(name) ?? []), value]);
    else if (out.strings.has(name)) throw new UsageError(`--${name} given twice`);
    else out.strings.set(name, value);
  }
  return out;
}
