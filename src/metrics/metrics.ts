import type { Database } from "bun:sqlite";
import type { ProjectId } from "../accounts/projects.ts";
import { countByState } from "../core/jobs.ts";
import type { StorageState } from "../core/storage.ts";
import { PROJECT_HOLDS } from "../guards/guards.ts";
import type { NsTargetView } from "../roles/core-ns.ts";
import type { PathView } from "../shaping/shaper.ts";
import { VERSION } from "../version.ts";

type Labels = Record<string, string>;

interface Family {
  name: string;
  type: "gauge" | "counter" | "info";
  help: string;
  samples: { labels: Labels; value: number }[];
}

const TOP_DESTINATIONS = 50;

function escapeLabel(v: string): string {
  return v.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n");
}

function sample(name: string, labels: Labels, value: number): string {
  const l = Object.entries(labels)
    .map(([k, v]) => `${k}="${escapeLabel(v)}"`)
    .join(",");
  return `${name}${l ? `{${l}}` : ""} ${Number.isFinite(value) ? value : 0}`;
}

export function render(families: Family[]): string {
  const lines: string[] = [];
  for (const f of families) {
    lines.push(`# TYPE ${f.name} ${f.type}`, `# HELP ${f.name} ${f.help}`);
    const name =
      f.type === "counter" ? `${f.name}_total` : f.type === "info" ? `${f.name}_info` : f.name;
    for (const s of f.samples) lines.push(sample(name, s.labels, s.value));
  }
  lines.push("# EOF");
  return `${lines.join("\n")}\n`;
}

export function collect(
  db: Database,
  project: ProjectId | null,
  paths: PathView[],
  now: number,
  startedAt: number,
  storage?: StorageState,
  ns?: NsTargetView[] | null,
): Family[] {
  const jobs = countByState(db, project);
  const recipients = db
    .query<{ status: string; target: string; n: number }, [string | null]>(
      `SELECT r.status, j.target, count(*) AS n FROM recipients r JOIN jobs j ON j.id = r.job_id
       WHERE ?1 IS NULL OR j.project_id = ?1
       GROUP BY r.status, j.target`,
    )
    .all(project);
  const busiest = new Map<string, number>();
  for (const r of recipients) busiest.set(r.target, (busiest.get(r.target) ?? 0) + r.n);
  const top = new Set(
    [...busiest.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, TOP_DESTINATIONS)
      .map(([d]) => d),
  );
  const byStatus = new Map<string, number>();
  for (const r of recipients) {
    const key = `${r.status}\u0000${top.has(r.target) ? r.target : "other"}`;
    byStatus.set(key, (byStatus.get(key) ?? 0) + r.n);
  }
  const one = (sql: string, ...args: (number | string | null)[]) =>
    db.query<{ n: number }, (number | string | null)[]>(sql).get(...args)?.n ?? 0;
  return [
    {
      name: "bunzzle_build",
      type: "info",
      help: "Version of the running Bunzzle.",
      samples: [{ labels: { version: VERSION }, value: 1 }],
    },
    {
      name: "bunzzle_uptime_seconds",
      type: "gauge",
      help: "Seconds since the core role started.",
      samples: [{ labels: {}, value: Math.round((now - startedAt) / 1000) }],
    },
    ...(storage && storage.freeMb !== null
      ? [
          {
            name: "bunzzle_disk_free_bytes",
            type: "gauge" as const,
            help: "Free space for the data directory.",
            samples: [{ labels: {}, value: storage.freeMb * 1024 * 1024 }],
          },
          {
            name: "bunzzle_disk_low",
            type: "gauge" as const,
            help: "1 while new email is refused because free space is below BUNZZLE_MIN_FREE_MB.",
            samples: [{ labels: {}, value: storage.low ? 1 : 0 }],
          },
        ]
      : []),
    {
      name: "bunzzle_jobs",
      type: "gauge",
      help: "Delivery jobs (one per email and recipient domain) by state.",
      samples: Object.entries(jobs).map(([state, n]) => ({ labels: { state }, value: n })),
    },
    {
      name: "bunzzle_recipients",
      type: "gauge",
      help: "Stored recipients by status and recipient domain (the 50 busiest domains, the rest as other).",
      samples: [...byStatus.entries()].map(([k, n]) => {
        const [status = "", domain = ""] = k.split("\u0000");
        return { labels: { status, domain }, value: n };
      }),
    },
    {
      name: "bunzzle_path_paused",
      type: "gauge",
      help: "1 when sending on this path (source IP to destination) is paused.",
      samples: paths.map((p) => ({
        labels: { source: p.source, destination: p.target },
        value: p.mode === "paused" ? 1 : 0,
      })),
    },
    {
      name: "bunzzle_path_rate_per_second",
      type: "gauge",
      help: "Current allowed sending rate on this path.",
      samples: paths.map((p) => ({
        labels: { source: p.source, destination: p.target },
        value: p.rate,
      })),
    },
    {
      name: "bunzzle_path_waiting",
      type: "gauge",
      help: "Emails waiting to be sent on this path, by lane.",
      samples: paths.flatMap((p) => [
        {
          labels: { source: p.source, destination: p.target, lane: "transactional" },
          value: p.waiting.transactional,
        },
        {
          labels: { source: p.source, destination: p.target, lane: "bulk" },
          value: p.waiting.bulk,
        },
      ]),
    },
    {
      name: "bunzzle_path_in_flight",
      type: "gauge",
      help: "Emails being sent on this path right now.",
      samples: paths.map((p) => ({
        labels: { source: p.source, destination: p.target },
        value: p.inflight,
      })),
    },
    {
      name: "bunzzle_path_delivered",
      type: "counter",
      help: "Emails delivered on this path since the core role started.",
      samples: paths.map((p) => ({
        labels: { source: p.source, destination: p.target },
        value: p.sent,
      })),
    },
    {
      name: "bunzzle_webhook_backlog",
      type: "gauge",
      help: "Webhook deliveries waiting or being sent.",
      samples: [
        {
          labels: {},
          value: one(
            `SELECT count(*) AS n FROM webhook_deliveries d JOIN webhooks w ON w.id = d.webhook_id
             WHERE d.state IN ('pending', 'sending') AND (?1 IS NULL OR w.project_id = ?1)`,
            project,
          ),
        },
      ],
    },
    {
      name: "bunzzle_suppressions",
      type: "gauge",
      help: "Active suppressed addresses.",
      samples: [
        {
          labels: {},
          value: one(
            `SELECT count(*) AS n FROM suppressions
             WHERE (expires_at IS NULL OR expires_at > ?2) AND (?1 IS NULL OR project_id = ?1)`,
            project,
            now,
          ),
        },
      ],
    },
    {
      name: "bunzzle_holds",
      type: "gauge",
      help: "Active holds on bulk mail by the reputation or anomaly guard.",
      samples: [
        {
          labels: {},
          value: one(
            `SELECT count(*) AS n FROM holds WHERE released_at IS NULL AND ${PROJECT_HOLDS}`,
            project,
          ),
        },
      ],
    },
    ...(ns
      ? [
          {
            name: "bunzzle_ns_up",
            type: "gauge" as const,
            help: "1 when the ns listener answered the last probe over this protocol.",
            samples: ns.flatMap((v) => [
              { labels: { ns: v.ns, proto: "udp" }, value: v.udp ? 1 : 0 },
              { labels: { ns: v.ns, proto: "tcp" }, value: v.tcp ? 1 : 0 },
            ]),
          },
          {
            name: "bunzzle_ns_healthy",
            type: "gauge" as const,
            help: "0 from the ns.unhealthy event until the ns.healthy event for this listener.",
            samples: ns.map((v) => ({ labels: { ns: v.ns }, value: v.healthy ? 1 : 0 })),
          },
          {
            name: "bunzzle_ns_failures",
            type: "gauge" as const,
            help: "Failed probes of this listener in a row.",
            samples: ns.map((v) => ({ labels: { ns: v.ns }, value: v.failures })),
          },
          {
            name: "bunzzle_ns_serial_lag_seconds",
            type: "gauge" as const,
            help: "Seconds the ns listener has been behind the zone serial core pushed.",
            samples: ns.map((v) => ({ labels: { ns: v.ns }, value: v.lagSeconds })),
          },
        ]
      : []),
  ];
}
