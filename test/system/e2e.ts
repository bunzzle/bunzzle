import { keyFromTxt, verifyDkim } from "../../src/dkim/verify.ts";
import { startFakeDns, type Zone } from "../support/fake-dns.ts";
import { startFakeMx } from "../support/fake-mx.ts";

const API = Bun.env["BUNZZLE_E2E_API"] ?? "http://127.0.0.1:3000";
const CLI = (Bun.env["BUNZZLE_E2E_CLI"] ?? "bunzzle").split(" ");
const DNS_PORT = Number(Bun.env["BUNZZLE_E2E_DNS_PORT"] ?? 5354);
const MX_PORT = Number(Bun.env["BUNZZLE_E2E_MX_PORT"] ?? 2526);
const DOMAIN = `e2e-${Date.now().toString(36)}.test`;

const zone: Zone = {
  "inbox.test": { MX: [[10, "mx.inbox.test"]] },
  "mx.inbox.test": { A: ["127.0.0.1"] },
};

function step(text: string) {
  console.log(`- ${text}`);
}

function fail(text: string): never {
  console.error(`FAIL: ${text}`);
  process.exit(1);
}

async function cli(...args: string[]): Promise<string> {
  const p = Bun.spawn([...CLI, ...args], { stdout: "pipe", stderr: "pipe" });
  const [out, err, code] = await Promise.all([
    new Response(p.stdout).text(),
    new Response(p.stderr).text(),
    p.exited,
  ]);
  if (code !== 0) fail(`bunzzle ${args.join(" ")} exited ${code}: ${err || out}`);
  return out;
}

async function api<T>(token: string, path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(`${API}${path}`, {
    ...init,
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
  });
  const body = (await res.json()) as T;
  if (!res.ok) fail(`${init.method ?? "GET"} ${path} → ${res.status} ${JSON.stringify(body)}`);
  return body;
}

const dns = await startFakeDns(zone, DNS_PORT);
const mx = startFakeMx({}, MX_PORT);
try {
  const health = await fetch(`${API}/health`).then((r) => r.json() as Promise<{ ok: boolean }>);
  if (!health.ok) fail("health is not ok");
  step("health ok");

  const token =
    (await cli("keys", "create", "--name", DOMAIN, "--scope", "full")).trim().split("\n").pop() ??
    "";
  if (!token.startsWith("bz_")) fail(`no API key in the CLI output: ${token}`);
  step("API key created with the CLI");

  const domain = await api<{ records: { record: string; name: string; value: string }[] }>(
    token,
    "/domains",
    { method: "POST", body: JSON.stringify({ name: DOMAIN }) },
  );
  const dkim = domain.records.filter((r) => r.record === "DKIM");
  if (dkim.length === 0) fail("no DKIM records");
  for (const r of dkim) zone[r.name] = { TXT: [r.value] };
  const verified = await api<{ status: string }>(token, `/domains/${DOMAIN}/verify`, {
    method: "POST",
  });
  if (verified.status !== "verified") fail(`domain is ${verified.status}`);
  step(`domain ${DOMAIN} verified (${dkim.length} DKIM keys, made by the signer)`);

  const { id } = await api<{ id: string }>(token, "/emails", {
    method: "POST",
    body: JSON.stringify({
      from: `Bunzzle <hello@${DOMAIN}>`,
      to: ["someone@inbox.test"],
      subject: "end to end",
      text: "delivered through every role",
    }),
  });
  step(`email ${id} accepted by the API`);

  let status = "";
  for (let i = 0; i < 100 && status !== "delivered"; i++) {
    await Bun.sleep(200);
    status = (await api<{ last_event: string }>(token, `/emails/${id}`)).last_event;
  }
  if (status !== "delivered") fail(`email is ${status} after 20 s`);
  const raw = mx.sessions.flatMap((s) => s.messages).at(-1);
  if (!raw) fail("the fake MX received nothing");
  const keys = Object.fromEntries(
    dkim.flatMap((r) => {
      const key = keyFromTxt(r.value);
      return key ? [[r.name.split("._domainkey.")[0] as string, key]] : [];
    }),
  );
  const verdicts = await verifyDkim(raw, keys);
  if (!verdicts.length || !verdicts.every((v) => v.ok)) {
    fail(`DKIM did not verify: ${JSON.stringify(verdicts)}`);
  }
  step(`delivered to the MX, ${verdicts.length} DKIM signatures verify`);
  console.log("PASS");
} finally {
  dns.stop();
  mx.stop();
}
