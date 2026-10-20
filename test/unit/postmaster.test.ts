import { describe, expect, test } from "bun:test";
import { postmasterCommand } from "../../src/cli/postmaster.ts";
import { loadConfig } from "../../src/config.ts";
import { createLogger } from "../../src/core/log.ts";
import { openDatabase } from "../../src/core/store/db.ts";
import { gmailGuard, latestPostmaster, savePostmaster } from "../../src/guards/gmail.ts";
import { activeHold } from "../../src/guards/guards.ts";
import { type DayStats, POSTMASTER_SCOPE, Postmaster } from "../../src/net/postmaster.ts";
import type { RequestInput, RequestResult } from "../../src/net/request.ts";

const json = (status: number, body: unknown): RequestResult => ({
  ok: true,
  status,
  headers: new Map(),
  body: JSON.stringify(body),
});

function fakeGoogle() {
  const calls: RequestInput[] = [];
  let tokens = 0;
  const request = async (r: RequestInput): Promise<RequestResult> => {
    calls.push(r);
    const u = new URL(r.url);
    if (u.pathname === "/token") {
      const form = new URLSearchParams(r.body ?? "");
      if (form.get("refresh_token") !== "refresh-1")
        return json(400, {
          error: "invalid_grant",
          error_description: "Token has been expired or revoked.",
        });
      tokens++;
      return json(200, { access_token: `access-${tokens}`, expires_in: 3600 });
    }
    if (r.headers?.["Authorization"] !== `Bearer access-${tokens}`)
      return json(401, { error: { message: "bad token" } });
    if (u.pathname === "/v1/domains/unknown.test/trafficStats") {
      return json(404, { error: { message: "Requested entity was not found." } });
    }
    if (u.pathname === "/v1/domains/acme.test/trafficStats") {
      if (!u.searchParams.get("pageToken")) {
        return json(200, {
          trafficStats: [
            {
              name: "domains/acme.test/trafficStats/20261017",
              userReportedSpamRatio: 0.0004,
              domainReputation: "HIGH",
              spfSuccessRatio: 1,
              dkimSuccessRatio: 1,
              dmarcSuccessRatio: 0.99,
              outboundEncryptionRatio: 1,
            },
          ],
          nextPageToken: "p2",
        });
      }
      return json(200, {
        trafficStats: [
          { name: "domains/acme.test/trafficStats/20261018", domainReputation: "MEDIUM" },
        ],
      });
    }
    return json(500, {});
  };
  return { request, calls };
}

const creds = { clientId: "id", clientSecret: "secret", refreshToken: "refresh-1" };
const AT = Date.parse("2026-10-20T08:00:00Z");

describe("Postmaster Tools client", () => {
  test("refreshes the access token once, follows pages, newest day first", async () => {
    const g = fakeGoogle();
    const pm = new Postmaster(
      creds,
      g.request,
      "https://pm.test",
      "https://oauth.test/token",
      () => AT,
    );
    const r = await pm.trafficStats("acme.test");
    expect(r).toEqual({
      ok: true,
      days: [
        {
          day: "2026-10-18",
          spamRatio: null,
          reputation: "MEDIUM",
          spfRatio: null,
          dkimRatio: null,
          dmarcRatio: null,
          encryptedRatio: null,
        },
        {
          day: "2026-10-17",
          spamRatio: 0.0004,
          reputation: "HIGH",
          spfRatio: 1,
          dkimRatio: 1,
          dmarcRatio: 0.99,
          encryptedRatio: 1,
        },
      ],
    });
    await pm.trafficStats("acme.test");
    expect(g.calls.filter((c) => c.url.endsWith("/token"))).toHaveLength(1);
    const first = new URL(g.calls[1]?.url ?? "");
    expect(first.searchParams.get("startDate.day")).toBe("13");
    expect(first.searchParams.get("endDate.day")).toBe("21");
  });

  test("a domain not in the account and a revoked token are reported", async () => {
    const g = fakeGoogle();
    const pm = new Postmaster(
      creds,
      g.request,
      "https://pm.test",
      "https://oauth.test/token",
      () => AT,
    );
    const missing = await pm.trafficStats("unknown.test");
    expect(missing.ok).toBe(false);
    if (!missing.ok) expect(missing.error).toContain("not set up in Postmaster Tools");
    const revoked = new Postmaster(
      { ...creds, refreshToken: "old" },
      g.request,
      "https://pm.test",
      "https://oauth.test/token",
      () => AT,
    );
    expect(await revoked.trafficStats("acme.test")).toEqual({
      ok: false,
      error: "could not refresh the access token: Token has been expired or revoked.",
    });
  });
});

const day = (d: string, spamRatio: number | null, reputation: string | null): DayStats => ({
  day: d,
  spamRatio,
  reputation,
  spfRatio: null,
  dkimRatio: null,
  dmarcRatio: null,
  encryptedRatio: null,
});

describe("Gmail guard", () => {
  test("holds bulk mail at a 0.3% spam rate or a BAD reputation, warns before", () => {
    const db = openDatabase({ path: ":memory:" });
    const lines: Record<string, unknown>[] = [];
    const log = createLogger("debug", {}, (l) => lines.push(JSON.parse(l)));
    savePostmaster(
      db,
      "spam.test",
      [day("2026-10-17", 0.001, "HIGH"), day("2026-10-18", 0.0035, "LOW")],
      AT,
    );
    savePostmaster(db, "bad.test", [day("2026-10-18", null, "BAD")], AT);
    savePostmaster(db, "slip.test", [day("2026-10-18", 0.0012, "HIGH")], AT);
    savePostmaster(db, "fine.test", [day("2026-10-18", 0.0002, "HIGH")], AT);
    savePostmaster(db, "fine.test", [day("2026-10-18", 0.0001, "HIGH")], AT);
    expect(latestPostmaster(db, "spam.test")?.day).toBe("2026-10-18");
    expect(latestPostmaster(db, "fine.test")?.spamRatio).toBe(0.0001);
    const made = gmailGuard(
      db,
      ["spam.test", "bad.test", "slip.test", "fine.test", "none.test"],
      AT,
      log,
    );
    expect(made.map((h) => h.target)).toEqual(["domain:spam.test", "domain:bad.test"]);
    expect(activeHold(db, "domain:spam.test", "bulk")?.reason).toBe(
      "Gmail reports a spam rate of 0.35% for 2026-10-18 (its limit is 0.3%)",
    );
    expect(activeHold(db, "domain:slip.test", "bulk")).toBeNull();
    expect(lines.map((l) => l["msg"])).toContain(
      "Gmail reputation is slipping for a sending domain",
    );
    expect(gmailGuard(db, ["spam.test"], AT, log)).toEqual([]);
  });
});

describe("bunzzle postmaster auth", () => {
  const dir = `${Bun.env["TMPDIR"] ?? "/tmp"}/bunzzle-pm-${crypto.randomUUID()}`;
  const config = loadConfig({});

  async function run(answer: (redirect: URL) => string, extra: string[] = []) {
    await Bun.$`mkdir -p ${dir}`.quiet();
    await Bun.write(`${dir}/secret`, "client-secret\n");
    const exchanged: URLSearchParams[] = [];
    const google = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      async fetch(req) {
        const form = new URLSearchParams(await req.text());
        exchanged.push(form);
        return form.get("code") === "good-code" && form.get("client_secret") === "client-secret"
          ? Response.json({ access_token: "a", refresh_token: "the-refresh-token" })
          : Response.json({ error: "invalid_grant" }, { status: 400 });
      },
    });
    const lines: string[] = [];
    let browsed: Response | null = null;
    const done = postmasterCommand(
      [
        "auth",
        "--client-id",
        "cid",
        "--client-secret-file",
        `${dir}/secret`,
        "--out",
        `${dir}/token`,
        ...extra,
      ],
      config,
      {
        tokenUrl: `http://127.0.0.1:${google.port}/token`,
        waitMs: 5_000,
        print: (l) => {
          lines.push(l);
          if (l.startsWith("https://accounts.google.com/")) {
            const u = new URL(l);
            setTimeout(async () => {
              browsed = await fetch(answer(u));
            }, 10);
          }
        },
      },
    );
    const code = await done;
    google.stop(true);
    return { code, lines, exchanged, browsed: browsed as Response | null };
  }

  test("signs in with PKCE and saves the refresh token with mode 600", async () => {
    const r = await run(
      (u) =>
        `${u.searchParams.get("redirect_uri")}/?state=${u.searchParams.get("state")}&code=good-code`,
    );
    expect(r.code).toBe(0);
    const url = new URL(r.lines.find((l) => l.startsWith("https://")) ?? "");
    expect(url.searchParams.get("scope")).toBe(POSTMASTER_SCOPE);
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("access_type")).toBe("offline");
    const verifier = r.exchanged[0]?.get("code_verifier") ?? "";
    const challenge = new Uint8Array(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)),
    ).toBase64({ alphabet: "base64url", omitPadding: true });
    expect(url.searchParams.get("code_challenge")).toBe(challenge);
    expect((await Bun.file(`${dir}/token`).text()).trim()).toBe("the-refresh-token");
    expect(((await Bun.file(`${dir}/token`).stat()).mode & 0o777).toString(8)).toBe("600");
    expect(r.lines.join("\n")).not.toContain("the-refresh-token");
    expect(r.lines.join("\n")).not.toContain("client-secret");
  });

  test("an existing file needs --force; a wrong state is refused; a denied sign-in fails", async () => {
    const kept = await run(() => "http://127.0.0.1:1/");
    expect(kept.code).toBe(1);
    expect(kept.lines[0]).toContain("already exists");
    await Bun.$`rm -f ${dir}/token`.quiet();
    const denied = await run(
      (u) =>
        `${u.searchParams.get("redirect_uri")}/?state=${u.searchParams.get("state")}&error=access_denied`,
    );
    expect(denied.code).toBe(1);
    expect(denied.lines.at(-1)).toContain("not authorized: access_denied");
    const bad = await run(
      (u) =>
        `${u.searchParams.get("redirect_uri")}/?state=${u.searchParams.get("state")}&code=wrong`,
      ["--force"],
    );
    expect(bad.code).toBe(1);
    expect(bad.lines.at(-1)).toContain("the token exchange failed: invalid_grant");
    await Bun.$`rm -rf ${dir}`.quiet();
  }, 20_000);
});
