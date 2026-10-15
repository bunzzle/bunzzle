import type { Config } from "../config.ts";
import { loadKeyFile } from "../dkim/keys.ts";
import { signMessage } from "../dkim/sign.ts";
import { cachingResolver } from "../dns/cache.ts";
import { createResolver, parseServer, systemServers } from "../dns/resolver.ts";
import { type Address, domainOf, parseAddress } from "../mime/address.ts";
import { buildMessage, newMessageId } from "../mime/builder.ts";
import { type Classification, classify } from "../replies/classify.ts";
import { type DeliveryReport, deliver } from "../smtp/deliver.ts";
import { parseArgs, UsageError } from "./args.ts";

const SPEC = {
  strings: [
    "from",
    "subject",
    "text",
    "text-file",
    "html",
    "html-file",
    "dkim-keys",
    "ehlo",
    "source-ip",
  ],
  lists: ["to", "cc", "bcc", "reply-to", "attach"],
  flags: ["require-tls", "dry-run", "unsigned", "json"],
};

async function readText(path: string | undefined): Promise<string | undefined> {
  if (path === undefined) return undefined;
  const f = Bun.file(path);
  if (!(await f.exists())) throw new UsageError(`file not found: ${path}`);
  return f.text();
}

const MEANING: Record<string, string> = {
  retry: "will retry",
  "fail-recipient": "recipient failed",
  "fail-message": "message failed",
  "pause-path": "path paused",
  "slow-path": "path slowed",
};

function verdictsOf(r: DeliveryReport): Classification[] {
  const atDot = r.recipients.filter((x) => x.phase === "dot").length;
  return r.recipients.map((x) =>
    classify({
      phase: x.phase,
      code: x.code,
      enhanced: x.enhanced,
      text: x.reply,
      provider: r.provider?.id ?? null,
      shared: x.phase === "dot" && atDot > 1,
    }),
  );
}

function describeVerdict(v: Classification): string {
  if (v.action === "done") return "";
  const parts = [v.class, `about the ${v.scope}`, MEANING[v.action] ?? v.action];
  if (v.suppress) parts.push("would suppress");
  if (v.alert) parts.push("operator alert");
  return `  [${parts.join(", ")}]`;
}

function describeReport(r: DeliveryReport): string {
  const lines: string[] = [];
  const d = r.destination;
  if (d.kind !== "targets") {
    lines.push(`${r.domain}: ${d.reason}`);
  } else {
    const via = r.provider ? ` (${r.provider.name})` : "";
    const mx = d.implicit
      ? `${d.mxHosts[0]} (no MX, using the domain itself)`
      : d.mxHosts.join(", ");
    lines.push(`${r.domain}${via}`);
    lines.push(`  MX: ${mx}${d.authenticated ? "  [DNSSEC]" : ""}`);
    for (const s of r.sessions) {
      const tls =
        s.tls.status === "none"
          ? "no TLS"
          : `${s.tls.version} ${s.tls.cipher ?? ""}, certificate ${s.tls.status}${s.tls.error ? ` (${s.tls.error})` : ""}`;
      const secs = ((s.finishedAt - s.startedAt) / 1000).toFixed(1);
      lines.push(`  → ${s.host} [${s.address}]  ${tls}, rule: ${s.tls.rule}  ${secs}s`);
      if (s.error) lines.push(`    stopped at ${s.phase}: ${s.error}`);
    }
  }
  const verdicts = verdictsOf(r);
  r.recipients.forEach((rc, i) => {
    const v = verdicts[i] as Classification;
    lines.push(`  ${rc.status.padEnd(9)} ${rc.address}  ${rc.reply}${describeVerdict(v)}`);
  });
  return lines.join("\n");
}

export async function sendCommand(argv: string[], config: Config): Promise<number> {
  const args = parseArgs(argv, SPEC);
  const fromRaw = args.strings.get("from");
  const subject = args.strings.get("subject");
  if (!fromRaw) throw new UsageError("--from is required");
  if (subject === undefined) throw new UsageError("--subject is required");
  const parse = (name: string): Address[] => (args.lists.get(name) ?? []).map(parseAddress);
  const from = parseAddress(fromRaw);
  const to = parse("to");
  const cc = parse("cc");
  const bcc = parse("bcc");
  const replyTo = parse("reply-to");
  if (to.length + cc.length + bcc.length === 0)
    throw new UsageError("at least one --to, --cc or --bcc is required");

  const text = args.strings.get("text") ?? (await readText(args.strings.get("text-file")));
  const html = args.strings.get("html") ?? (await readText(args.strings.get("html-file")));
  if (text === undefined && html === undefined) {
    throw new UsageError("a body is required: --text, --text-file, --html or --html-file");
  }
  const attachments = [];
  for (const path of args.lists.get("attach") ?? []) {
    const f = Bun.file(path);
    if (!(await f.exists())) throw new UsageError(`file not found: ${path}`);
    attachments.push({
      filename: path.split("/").pop() as string,
      content: new Uint8Array(await f.arrayBuffer()),
      contentType: f.type.split(";")[0] as string,
    });
  }

  const fromDomain = domainOf(from.address);
  const built = buildMessage({
    from,
    to,
    ...(cc.length ? { cc } : {}),
    ...(replyTo.length ? { replyTo } : {}),
    subject,
    ...(text !== undefined ? { text } : {}),
    ...(html !== undefined ? { html } : {}),
    ...(attachments.length ? { attachments } : {}),
    messageId: newMessageId(fromDomain),
    date: new Date(),
  });

  const keyFile = args.strings.get("dkim-keys") ?? config.dkimKeyFile;
  let raw = built.raw;
  if (keyFile) {
    const keys = await loadKeyFile(keyFile);
    const keyDomain = keys[0]?.domain;
    if (keyDomain !== fromDomain) {
      throw new UsageError(
        `the DKIM keys are for ${keyDomain}, but the sender is ${fromDomain}; Bunzzle only signs for the sender's own domain`,
      );
    }
    raw = await signMessage(raw, keys);
  } else if (!args.flags.has("unsigned")) {
    throw new UsageError(
      "no DKIM keys: pass --dkim-keys (create them with `bunzzle dkim keygen`), or --unsigned to send without DKIM",
    );
  }

  if (args.flags.has("dry-run")) {
    process.stdout.write(raw);
    return 0;
  }

  const ehloName = args.strings.get("ehlo") ?? config.ehloName;
  if (!ehloName) {
    throw new UsageError(
      "--ehlo (or BUNZZLE_EHLO_NAME) is required: the reverse DNS name of the IP you send from",
    );
  }
  const sourceIp = args.strings.get("source-ip") ?? config.sourceIp;
  const servers = config.dnsServers.length
    ? config.dnsServers.map(parseServer)
    : await systemServers();
  const resolver = cachingResolver(createResolver({ servers }));

  const byDomain = new Map<string, string[]>();
  for (const a of [...to, ...cc, ...bcc]) {
    const d = domainOf(a.address);
    const list = byDomain.get(d) ?? [];
    if (!list.includes(a.address)) list.push(a.address);
    byDomain.set(d, list);
  }

  const reports = await Promise.all(
    [...byDomain].map(([domain, recipients]) =>
      deliver(
        {
          domain,
          from: from.address,
          recipients,
          data: raw,
          smtpUtf8: built.smtpUtf8,
          requireTls: args.flags.has("require-tls"),
        },
        {
          resolver,
          ehloName,
          port: config.smtpPort,
          families: config.ipv6 ? [4, 6] : [4],
          allowPrivate: config.allowPrivateDestinations,
          ...(sourceIp ? { localAddress: sourceIp, ownAddresses: [sourceIp] } : {}),
        },
      ),
    ),
  );

  if (args.flags.has("json")) {
    const withVerdicts = reports.map((r) => {
      const verdicts = verdictsOf(r);
      return {
        ...r,
        recipients: r.recipients.map((x, i) => ({ ...x, verdict: verdicts[i] })),
      };
    });
    console.log(JSON.stringify({ messageId: built.messageId, reports: withVerdicts }, null, 2));
  } else {
    console.log(
      `Message-ID: ${built.messageId}${keyFile ? "  (DKIM: RSA + Ed25519)" : "  (unsigned)"}\n`,
    );
    console.log(reports.map(describeReport).join("\n\n"));
  }
  const delivered = reports.every((r) => r.recipients.every((x) => x.status === "delivered"));
  return delivered ? 0 : 1;
}
