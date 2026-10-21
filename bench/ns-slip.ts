import { encodeQuery, RRType } from "../src/dns/wire.ts";
import { DEFAULT_LIMITS } from "../src/ns/limits.ts";
import { NsServer } from "../src/ns/server.ts";

const APEX = "dz.mail.example.net";
const NAME = `bza-r.k3j9q2mx7c4d8f1h.${APEX}`;
const SECONDS = Number(Bun.argv[2] ?? 60);
const RATES = (Bun.argv[3] ?? "200,2000,20000").split(",").map(Number);
const VICTIM = "198.51.100.7";
const NEIGHBOUR = "198.51.100.53";
const ELSEWHERE = "203.0.113.53";
const RESOLVER_QPS = 5;

interface Row {
  slip: number;
  rate: number;
  inBytes: number;
  reflected: number;
  neighbourUdp: number;
  neighbourTcp: number;
  neighbourLost: number;
  elsewhereOk: number;
  asked: number;
}

function random(seed: number): () => number {
  let a = seed;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let x = Math.imul(a ^ (a >>> 15), 1 | a);
    x = (x + Math.imul(x ^ (x >>> 7), 61 | x)) ^ x;
    return ((x ^ (x >>> 14)) >>> 0) / 4294967296;
  };
}

function run(slip: number, rate: number): Row {
  let t = 0;
  const rnd = random(rate);
  const gap = (perSec: number) => (-Math.log(1 - rnd()) * 1000) / perSec;
  const server = new NsServer({
    apex: APEX,
    names: ["ns1.mail.example.net"],
    limits: { ...DEFAULT_LIMITS, slip },
    now: () => t,
  });
  server.load({
    serial: 1,
    records: [{ name: NAME, type: "TXT", ttl: 300, value: `v=DKIM1; k=rsa; p=${"A".repeat(392)}` }],
  });
  const query = encodeQuery(1, NAME, RRType.TXT);
  const row: Row = {
    slip,
    rate,
    inBytes: 0,
    reflected: 0,
    neighbourUdp: 0,
    neighbourTcp: 0,
    neighbourLost: 0,
    elsewhereOk: 0,
    asked: 0,
  };
  let nextFlood = gap(rate);
  let nextResolver = gap(RESOLVER_QPS);
  const end = SECONDS * 1000;
  while (nextFlood < end || nextResolver < end) {
    if (nextFlood <= nextResolver) {
      t = nextFlood;
      nextFlood += gap(rate);
      row.inBytes += query.length;
      const out = server.answerUdp(query, VICTIM);
      if (out) row.reflected += out.length;
      continue;
    }
    t = nextResolver;
    nextResolver += gap(RESOLVER_QPS);
    const out = server.answerUdp(query, NEIGHBOUR);
    row.asked++;
    if (!out) row.neighbourLost++;
    else if (((out[2] as number) & 0x02) === 0) row.neighbourUdp++;
    else if (server.answerTcp(query)) row.neighbourTcp++;
    if (server.answerUdp(query, ELSEWHERE)) row.elsewhereOk++;
  }
  return row;
}

const rows: Row[] = [];
for (const rate of RATES) for (const slip of [0, 2]) rows.push(run(slip, rate));

console.log(
  `${SECONDS} s flood of TXT queries spoofed from ${VICTIM}; real resolvers at ${RESOLVER_QPS} q/s in the same /24 and in another /24`,
);
console.table(
  rows.map((r) => ({
    "flood q/s": r.rate,
    slip: r.slip === 0 ? "drop only" : r.slip,
    "bytes in": r.inBytes,
    "bytes to victim": r.reflected,
    "out/in": (r.reflected / r.inBytes).toFixed(3),
    "neighbour UDP ok": `${r.neighbourUdp}/${r.asked}`,
    "neighbour via TCP": `${r.neighbourTcp}/${r.asked}`,
    "neighbour lost": `${r.neighbourLost}/${r.asked}`,
    "other /24 ok": `${r.elsewhereOk}/${r.asked}`,
  })),
);
