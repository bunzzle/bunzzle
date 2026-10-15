import type { Config } from "../config.ts";
import { loadMasterKey } from "../crypto/load.ts";
import {
  dnsRecords,
  generateKeyFile,
  type KeyFile,
  parseKeyFile,
  sealKeyFile,
} from "../dkim/keys.ts";
import { parseArgs, UsageError } from "./args.ts";

function printRecords(file: KeyFile) {
  console.log(`DNS records for ${file.domain} (TXT):\n`);
  for (const r of dnsRecords(file)) console.log(`${r.name}\n  ${r.value}\n`);
}

async function keygen(argv: string[], config: Config) {
  const args = parseArgs(argv, {
    strings: ["domain", "selector", "out"],
    flags: ["force", "unencrypted"],
  });
  const domain = args.strings.get("domain");
  const out = args.strings.get("out");
  if (!domain || !out) throw new UsageError("dkim keygen needs --domain and --out");
  const now = new Date();
  const selector =
    args.strings.get("selector") ??
    `bz${now.getUTCFullYear()}${String(now.getUTCMonth() + 1).padStart(2, "0")}`;
  if (!/^[a-z0-9-]+$/i.test(selector)) throw new UsageError("invalid --selector");
  if ((await Bun.file(out).exists()) && !args.flags.has("force")) {
    throw new UsageError(`${out} already exists (use --force to replace it)`);
  }
  const master = await loadMasterKey(config);
  if (!master && !args.flags.has("unencrypted")) {
    throw new UsageError(
      "DKIM keys are stored encrypted: set BUNZZLE_MASTER_KEY or BUNZZLE_MASTER_KEY_FILE (create one with `bunzzle master-key`), or pass --unencrypted for local testing",
    );
  }
  const plain = await generateKeyFile(domain, selector);
  const file = master ? await sealKeyFile(plain, master) : plain;
  await Bun.write(out, `${JSON.stringify(file, null, 2)}\n`);
  await Bun.$`chmod 600 ${out}`.quiet();
  console.log(
    master
      ? `Wrote ${out}, encrypted with master key ${master.id}.\n`
      : `Wrote ${out} UNENCRYPTED (keep it secret).\n`,
  );
  printRecords(file);
}

async function records(argv: string[]) {
  const args = parseArgs(argv, { strings: ["keys"] });
  const path = args.strings.get("keys");
  if (!path) throw new UsageError("dkim records needs --keys");
  printRecords(parseKeyFile(await Bun.file(path).json()));
}

export async function dkimCommand(argv: string[], config: Config) {
  const [sub, ...rest] = argv;
  if (sub === "keygen") return keygen(rest, config);
  if (sub === "records") return records(rest);
  throw new UsageError("usage: bunzzle dkim keygen|records");
}
