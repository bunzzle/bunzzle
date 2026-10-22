import type { Subprocess } from "bun";

const MAIN = `${import.meta.dir}/../../src/cli/main.ts`;

export interface Served {
  proc: Subprocess<"ignore", "pipe", "pipe">;
  dir: string;
  url: string;
  inboundPort: number | null;
  submissionPorts: number[];
  trackPort: number | null;
  pids: Map<string, number>;
  logs: Record<string, unknown>[];
  stop(): Promise<number>;
}

export async function startServe(env: Record<string, string>): Promise<Served> {
  const dir = `${Bun.env["TMPDIR"] ?? "/tmp"}/bunzzle-serve-${crypto.randomUUID()}`;
  await Bun.$`mkdir -p ${dir}`.quiet();
  const proc = Bun.spawn(["bun", MAIN, "serve"], {
    cwd: dir,
    env: {
      PATH: Bun.env["PATH"] ?? "",
      HOME: Bun.env["HOME"] ?? "",
      TMPDIR: Bun.env["TMPDIR"] ?? "/tmp",
      BUNZZLE_PORT: "0",
      ...env,
    },
    stdin: "ignore",
    stdout: "pipe",
    stderr: "pipe",
  });
  const pids = new Map<string, number>();
  const logs: Record<string, unknown>[] = [];
  const listening = Promise.withResolvers<string>();
  let inboundPort: number | null = null;
  let submissionPorts: number[] = [];
  let trackPort: number | null = null;
  let stderrText = "";
  const read = async (stream: ReadableStream<Uint8Array>, isErr: boolean) => {
    let buf = "";
    const dec = new TextDecoder();
    for await (const chunk of stream) {
      const text = dec.decode(chunk);
      if (isErr) stderrText += text;
      buf += text;
      let i = buf.indexOf("\n");
      while (i >= 0) {
        const line = buf.slice(0, i);
        buf = buf.slice(i + 1);
        i = buf.indexOf("\n");
        let entry: Record<string, unknown>;
        try {
          entry = JSON.parse(line);
        } catch {
          continue;
        }
        logs.push(entry);
        if (
          (entry["msg"] === "role started" || entry["msg"] === "role restarted") &&
          typeof entry["pid"] === "number"
        ) {
          pids.set(String(entry["role"]), entry["pid"]);
        }
        if (entry["msg"] === "listening") {
          inboundPort = typeof entry["inboundPort"] === "number" ? entry["inboundPort"] : null;
          submissionPorts = Array.isArray(entry["submissionPorts"])
            ? (entry["submissionPorts"] as number[])
            : [];
          trackPort = typeof entry["trackPort"] === "number" ? entry["trackPort"] : null;
          listening.resolve(String(entry["url"]));
        }
      }
    }
  };
  void read(proc.stderr, true);
  void read(proc.stdout, false).then(() =>
    listening.reject(
      new Error(
        `serve exited: ${stderrText}${logs
          .filter((l) => l["level"] === "error")
          .map((l) => `\n${JSON.stringify(l)}`)
          .join("")}`,
      ),
    ),
  );
  const url = (await listening.promise).replace(/\/$/, "");
  return {
    proc,
    dir,
    url,
    get inboundPort() {
      return inboundPort;
    },
    get submissionPorts() {
      return submissionPorts;
    },
    get trackPort() {
      return trackPort;
    },
    pids,
    logs,
    async stop() {
      if (proc.exitCode === null) proc.kill("SIGTERM");
      const code = await proc.exited;
      await Bun.$`rm -rf ${dir}`.quiet();
      return code;
    },
  };
}

export function alive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}
