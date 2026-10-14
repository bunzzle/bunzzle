import { eventsFor } from "../../src/core/events.ts";
import { countByState } from "../../src/core/jobs.ts";
import { openDatabase } from "../../src/core/store/db.ts";

export interface CrashOptions {
  messages: number;
  kills: number;
  minRunMs: number;
  maxRunMs: number;
  busyRate?: number;
  onProgress?: (line: string) => void;
}

export interface CrashReport {
  messages: number;
  kills: number;
  done: number;
  dead: number;
  lost: number;
  ackedMissingAfterKill: number;
  deliveries: number;
  duplicates: number;
  duplicatesRecorded: number;
  unrecordedDuplicates: number;
  unknownDeliveries: number;
  seconds: number;
}

const WORKER = `${import.meta.dir}/worker.ts`;

export async function runCrash(o: CrashOptions): Promise<CrashReport> {
  const started = performance.now();
  const dir = `${Bun.env["TMPDIR"] ?? "/tmp"}/bunzzle-crash-${crypto.randomUUID()}`;
  await Bun.$`mkdir -p ${dir}`.quiet();
  const dbPath = `${dir}/bunzzle.db`;

  const received = new Map<string, number>();
  const acked = new Set<string>();
  const busyRate = o.busyRate ?? 0.05;
  const sink = Bun.serve({
    port: 0,
    routes: {
      "/send": {
        POST: async (req) => {
          const id = await req.text();
          if (Math.random() < busyRate) return new Response("busy", { status: 503 });
          received.set(id, (received.get(id) ?? 0) + 1);
          return new Response("ok");
        },
      },
      "/ack": {
        POST: async (req) => {
          for (const id of (await req.json()) as string[]) acked.add(id);
          return new Response("ok");
        },
      },
    },
  });

  const spawn = () =>
    Bun.spawn(["bun", WORKER], {
      env: {
        ...Bun.env,
        CRASH_DB: dbPath,
        CRASH_SINK: sink.url.href.replace(/\/$/, ""),
        CRASH_N: String(o.messages),
      },
      stdin: "ignore",
      stdout: "inherit",
      stderr: "pipe",
    });

  const storedIds = () => {
    const db = openDatabase({ path: dbPath });
    const ids = new Set(
      db
        .query<{ id: string }, []>("SELECT id FROM messages")
        .all()
        .map((r) => r.id),
    );
    db.close();
    return ids;
  };

  let kills = 0;
  let ackedMissingAfterKill = 0;
  try {
    for (; kills < o.kills; kills++) {
      const proc = spawn();
      const runFor = o.minRunMs + Math.random() * (o.maxRunMs - o.minRunMs);
      const finished = await Promise.race([
        proc.exited.then(() => true),
        Bun.sleep(runFor).then(() => false),
      ]);
      if (finished) {
        if (proc.exitCode !== 0) {
          throw new Error(`worker exited with ${proc.exitCode}: ${await proc.stderr.text()}`);
        }
        break;
      }
      proc.kill("SIGKILL");
      await proc.exited;
      const ids = storedIds();
      for (const id of acked) if (!ids.has(id)) ackedMissingAfterKill++;
      o.onProgress?.(
        `kill ${kills + 1}/${o.kills} after ${Math.round(runFor)} ms: ${ids.size} stored, ${acked.size} acked, ${received.size} delivered`,
      );
    }

    const last = spawn();
    const timeout = Bun.sleep(120_000).then(() => "timeout" as const);
    if ((await Promise.race([last.exited, timeout])) === "timeout") {
      last.kill("SIGKILL");
      throw new Error("final run did not finish in 120 s");
    }
    if (last.exitCode !== 0) {
      throw new Error(`final worker exited with ${last.exitCode}: ${await last.stderr.text()}`);
    }

    const db = openDatabase({ path: dbPath });
    const states = countByState(db);
    const doneIds = new Set(
      db
        .query<{ message_id: string }, []>("SELECT message_id FROM jobs WHERE state = 'done'")
        .all()
        .map((r) => r.message_id),
    );
    let lost = 0;
    for (let i = 0; i < o.messages; i++) {
      if (!doneIds.has(`m${String(i).padStart(7, "0")}`)) lost++;
    }

    let deliveries = 0;
    let duplicates = 0;
    let duplicatesRecorded = 0;
    let unrecordedDuplicates = 0;
    let unknownDeliveries = 0;
    const risk = new Map(
      db
        .query<{ message_id: string; n: number }, []>(
          "SELECT message_id, count(*) AS n FROM events WHERE kind = 'duplicate_risk' GROUP BY message_id",
        )
        .all()
        .map((r) => [r.message_id, r.n]),
    );
    for (const n of risk.values()) duplicatesRecorded += n;
    for (const [id, n] of received) {
      deliveries += n;
      if (!doneIds.has(id)) unknownDeliveries++;
      const extra = n - 1;
      duplicates += extra;
      unrecordedDuplicates += Math.max(0, extra - (risk.get(id) ?? 0));
    }
    if (unrecordedDuplicates > 0) {
      const sample = [...received].find(([id, n]) => n - 1 > (risk.get(id) ?? 0));
      if (sample)
        o.onProgress?.(
          `unrecorded duplicate: ${sample[0]} ${JSON.stringify(eventsFor(db, sample[0]))}`,
        );
    }
    db.close();

    return {
      messages: o.messages,
      kills,
      done: states.done,
      dead: states.dead,
      lost,
      ackedMissingAfterKill,
      deliveries,
      duplicates,
      duplicatesRecorded,
      unrecordedDuplicates,
      unknownDeliveries,
      seconds: Math.round((performance.now() - started) / 100) / 10,
    };
  } finally {
    sink.stop(true);
    await Bun.$`rm -rf ${dir}`.quiet();
  }
}
