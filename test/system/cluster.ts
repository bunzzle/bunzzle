import { keyFromTxt, verifyDkim } from "../../src/dkim/verify.ts";
import { startFakeDns, type Zone } from "../support/fake-dns.ts";
import { startFakeMx } from "../support/fake-mx.ts";

const API = Bun.env["BUNZZLE_CLUSTER_API"] ?? "http://10.89.0.10:3000";
const TOKEN = Bun.env["BUNZZLE_CLUSTER_TOKEN"] ?? "";
const MX_IP = Bun.env["BUNZZLE_CLUSTER_MX"] ?? "10.89.3.40";
const ROUTES = (Bun.env["BUNZZLE_CLUSTER_ROUTES"] ?? "node=10.89.3.20,edge=10.89.3.30")
  .split(",")
  .map((r) => r.split("=") as [string, string]);
const STAMP = Date.now().toString(36);

const zone: Zone = {
  "inbox.test": { MX: [[10, "mx.inbox.test"]] },
  "mx.inbox.test": { A: [MX_IP] },
};

function step(text: string) {
  console.log(`- ${text}`);
}

function fail(text: string): never {
  console.error(`FAIL: ${text}`);
  process.exit(1);
}

async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(`${API}${path}`, {
    ...init,
    headers: { authorization: `Bearer ${TOKEN}`, "content-type": "application/json" },
  });
  const body = (await res.json()) as T;
  if (!res.ok) fail(`${init.method ?? "GET"} ${path} → ${res.status} ${JSON.stringify(body)}`);
  return body;
}

if (!TOKEN.startsWith("bz_")) fail("BUNZZLE_CLUSTER_TOKEN is not an API key");
const dns = await startFakeDns(zone, 53, "0.0.0.0");
const mx = startFakeMx({}, 25, "0.0.0.0");
try {
  type Node = { name: string; up: boolean; ips: string[] };
  let nodes: Node[] = [];
  for (let i = 0; i < 60; i++) {
    nodes = (await api<{ data: Node[] }>("/nodes")).data;
    if (ROUTES.every(([, ip]) => nodes.some((n) => n.up && n.ips.includes(ip)))) break;
    await Bun.sleep(1000);
  }
  for (const [, ip] of ROUTES) {
    if (!nodes.some((n) => n.up && n.ips.includes(ip))) {
      fail(`no node is up with ${ip}: ${JSON.stringify(nodes)}`);
    }
  }
  step(`core sees ${nodes.map((n) => n.name).join(" and ")} up over their links`);

  for (const [pool, ip] of ROUTES) {
    const name = `${pool}-${STAMP}.test`;
    const domain = await api<{ records: { record: string; name: string; value: string }[] }>(
      "/domains",
      { method: "POST", body: JSON.stringify({ name }) },
    );
    const dkim = domain.records.filter((r) => r.record === "DKIM");
    for (const r of dkim) zone[r.name] = { TXT: [r.value] };
    const verified = await api<{ status: string }>(`/domains/${name}/verify`, { method: "POST" });
    if (verified.status !== "verified") fail(`domain ${name} is ${verified.status}`);
    await api(`/domains/${name}`, { method: "PATCH", body: JSON.stringify({ ip_pool: pool }) });

    const subject = `through ${pool}`;
    const { id } = await api<{ id: string }>("/emails", {
      method: "POST",
      body: JSON.stringify({
        from: `Bunzzle <hello@${name}>`,
        to: ["someone@inbox.test"],
        subject,
        text: `sent from the ${pool} pool`,
      }),
    });
    let status = "";
    for (let i = 0; i < 150 && status !== "delivered"; i++) {
      await Bun.sleep(200);
      status = (await api<{ last_event: string }>(`/emails/${id}`)).last_event;
    }
    if (status !== "delivered") fail(`email ${id} in pool ${pool} is ${status} after 30 s`);

    const session = mx.sessions.find((s) =>
      s.messages.some((m) => m.includes(`Subject: ${subject}`)),
    );
    if (!session) fail(`the MX received nothing for pool ${pool}`);
    const remote = session.remote.replace(/^::ffff:/, "");
    if (remote !== ip) fail(`pool ${pool} connected from ${remote}, not ${ip}`);
    const raw = session.messages.find((m) => m.includes(`Subject: ${subject}`)) ?? "";
    const keys = Object.fromEntries(
      dkim.flatMap((r) => {
        const key = keyFromTxt(r.value);
        return key ? [[r.name.split("._domainkey.")[0] as string, key]] : [];
      }),
    );
    const verdicts = await verifyDkim(raw, keys);
    if (!verdicts.length || !verdicts.every((v) => v.ok)) {
      fail(`DKIM did not verify for pool ${pool}: ${JSON.stringify(verdicts)}`);
    }
    step(`pool ${pool}: delivered from ${ip}${session.tls ? " over TLS" : ""}, DKIM verifies`);
  }
  console.log("PASS");
} finally {
  dns.stop();
  mx.stop();
}
