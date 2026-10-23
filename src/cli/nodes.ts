import { fromPem, pem } from "../asn1/der.ts";
import type { Config } from "../config.ts";
import { pinOf } from "../ipc/rpc.ts";
import { b } from "../validate/schema.ts";
import { parseCertificate } from "../x509/cert.ts";
import { certificateRequest, importP256, validName } from "../x509/issue.ts";
import { call } from "./admin.ts";
import { parseArgs, UsageError } from "./args.ts";

const USAGE =
  "usage: bunzzle nodes [list | request NAME | add NAME ADDRESS CSR_FILE | install BUNDLE_FILE | remove NAME | rotate-ca [start | promote | finish]]";

interface Rotation {
  cas: { name: string; state: string; expires_at: string }[];
  pending: { step: string; nodes: string[] } | null;
  dropped?: { name: string; store_key: string | null }[];
}

function printRotation(r: Rotation) {
  for (const ca of r.cas) {
    console.log(`${ca.name.padEnd(24)} ${ca.state.padEnd(10)} until ${ca.expires_at.slice(0, 10)}`);
  }
  if (!r.pending) console.log("No CA rotation in progress.");
  else if (r.pending.nodes.length === 0)
    console.log(`Next step: ${r.pending.step}. All nodes are ready.`);
  else console.log(`Next step: ${r.pending.step}. Waiting for: ${r.pending.nodes.join(", ")}`);
  for (const d of r.dropped ?? []) {
    console.log(`Dropped ${d.name}.`);
    if (d.store_key) {
      console.log(
        `Its key ${d.store_key} is still in the external key store. Bunzzle no longer uses it: delete it in the key store.`,
      );
    }
  }
}

const bundle = b.object({
  name: b.string(),
  cert: b.string(),
  ca: b.string(),
  corePins: b.array(b.string()).min(1),
});

function split(argv: string[]): [string[], string[]] {
  const i = argv.findIndex((a) => a.startsWith("--"));
  return i < 0 ? [argv, []] : [argv.slice(0, i), argv.slice(i)];
}

async function writePrivate(path: string, text: string) {
  await Bun.write(path, text);
  await Bun.$`chmod 600 ${path}`.quiet();
}

async function request(argv: string[], config: Config) {
  const [positional, options] = split(argv);
  const args = parseArgs(options, { strings: ["dir"], flags: ["force"] });
  const [name, ...extra] = positional;
  if (!name || extra.length > 0) throw new UsageError(USAGE);
  if (!validName(name)) throw new UsageError("node names use a-z, 0-9 and -, up to 63 characters");
  const dir = args.strings.get("dir") ?? config.nodeDir;
  if ((await Bun.file(`${dir}/key.pem`).exists()) && !args.flags.has("force")) {
    throw new UsageError(`${dir}/key.pem already exists (use --force to replace it)`);
  }
  await Bun.$`mkdir -p ${dir} && chmod 700 ${dir}`.quiet();
  const key = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", key.privateKey));
  await writePrivate(`${dir}/key.pem`, pem("PRIVATE KEY", pkcs8));
  pkcs8.fill(0);
  const csr = `${dir}/request.csr`;
  await Bun.write(csr, pem("CERTIFICATE REQUEST", await certificateRequest(name, key)));
  console.log(`Wrote ${dir}/key.pem and ${csr}.`);
  console.log(`On core: bunzzle nodes add ${name} <ip>:<port> request.csr`);
}

async function add(argv: string[], config: Config) {
  const [positional, options] = split(argv);
  const args = parseArgs(options, { strings: ["out"] });
  const [name, address, csrFile, ...extra] = positional;
  if (!name || !address || !csrFile || extra.length > 0) throw new UsageError(USAGE);
  const der = fromPem(await Bun.file(csrFile).text())[0];
  if (!der) throw new UsageError(`${csrFile} holds no certificate request`);
  const result = await call<b.infer<typeof bundle>>(config, "addNode", {
    name,
    address,
    csr: der.toBase64(),
  });
  const out = args.strings.get("out") ?? `${name}.bundle.json`;
  await writePrivate(out, `${JSON.stringify(result, null, 2)}\n`);
  console.log(`Added ${name} at ${address}. Wrote ${out}.`);
  console.log(`On the node: bunzzle nodes install ${out}`);
}

async function install(argv: string[], config: Config) {
  const [positional, options] = split(argv);
  const args = parseArgs(options, { strings: ["dir"] });
  const [file, ...extra] = positional;
  if (!file || extra.length > 0) throw new UsageError(USAGE);
  const parsed = bundle.safeParse(await Bun.file(file).json());
  if (!parsed.success) throw new UsageError(`${file} is not a node bundle`);
  const dir = args.strings.get("dir") ?? config.nodeDir;
  const keyFile = Bun.file(`${dir}/key.pem`);
  if (!(await keyFile.exists())) {
    throw new UsageError(`${dir}/key.pem is missing: run bunzzle nodes request first`);
  }
  const key = await importP256(fromPem(await keyFile.text())[0] as Uint8Array);
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", key.publicKey));
  const cert = parseCertificate(fromPem(parsed.data.cert)[0] as Uint8Array);
  if (pinOf(cert.spki) !== pinOf(spki)) {
    throw new UsageError(`${file} was not issued for the key in ${dir}/key.pem`);
  }
  await Bun.write(`${dir}/cert.pem`, parsed.data.cert);
  await Bun.write(`${dir}/ca.pem`, parsed.data.ca);
  await Bun.write(`${dir}/peer.pin`, `${parsed.data.corePins.join("\n")}\n`);
  console.log(`Installed ${parsed.data.name} in ${dir}. Restart the delivery role.`);
}

export async function nodesCommand(argv: string[], config: Config) {
  const [sub, ...rest] = argv;
  switch (sub) {
    case undefined:
    case "list": {
      const nodes = await call<{ name: string; address: string; certificate_expires_at: string }[]>(
        config,
        "listNodes",
        {},
      );
      if (nodes.length === 0) console.log("No delivery nodes.");
      for (const n of nodes) {
        console.log(
          `${n.name.padEnd(24)} ${n.address.padEnd(24)} until ${n.certificate_expires_at}`,
        );
      }
      return;
    }
    case "request":
      return request(rest, config);
    case "add":
      return add(rest, config);
    case "install":
      return install(rest, config);
    case "rotate-ca": {
      const [step, ...extra] = rest;
      if (
        extra.length > 0 ||
        (step !== undefined && !["start", "promote", "finish"].includes(step))
      ) {
        throw new UsageError(USAGE);
      }
      printRotation(
        step === undefined
          ? await call<Rotation>(config, "nodeCaRotation", {})
          : await call<Rotation>(config, "rotateNodeCa", { step }),
      );
      return;
    }
    case "remove": {
      const [name, ...extra] = rest;
      if (!name || extra.length > 0) throw new UsageError(USAGE);
      await call(config, "removeNode", { name });
      console.log(`Removed ${name}.`);
      return;
    }
    default:
      throw new UsageError(USAGE);
  }
}
