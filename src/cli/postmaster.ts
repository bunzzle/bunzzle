import type { Config } from "../config.ts";
import { POSTMASTER_SCOPE } from "../net/postmaster.ts";
import { parseArgs, UsageError } from "./args.ts";

const USAGE =
  "usage: bunzzle postmaster auth --client-id ID --client-secret-file FILE --out FILE [--force]";
const WAIT_MS = 10 * 60_000;

export interface PostmasterAuthDeps {
  authUrl: string;
  tokenUrl: string;
  print: (line: string) => void;
  waitMs: number;
}

const base64url = (bytes: Uint8Array) =>
  bytes.toBase64({ alphabet: "base64url", omitPadding: true });

export async function postmasterCommand(
  argv: string[],
  config: Config,
  deps: Partial<PostmasterAuthDeps> = {},
): Promise<number> {
  const [sub, ...rest] = argv;
  if (sub !== "auth") throw new UsageError(USAGE);
  const args = parseArgs(rest, {
    strings: ["client-id", "client-secret-file", "out"],
    flags: ["force"],
  });
  const clientId = args.strings.get("client-id");
  const secretFile = args.strings.get("client-secret-file");
  const out = args.strings.get("out");
  if (!clientId || !secretFile || !out) throw new UsageError(USAGE);
  const d: PostmasterAuthDeps = {
    authUrl: "https://accounts.google.com/o/oauth2/v2/auth",
    tokenUrl: config.postmaster?.tokenUrl ?? "https://oauth2.googleapis.com/token",
    print: (line) => console.log(line),
    waitMs: WAIT_MS,
    ...deps,
  };
  if ((await Bun.file(out).exists()) && !args.flags.has("force")) {
    d.print(`${out} already exists; pass --force to replace it`);
    return 1;
  }
  const clientSecret = (await Bun.file(secretFile).text()).trim();
  const verifier = base64url(crypto.getRandomValues(new Uint8Array(32)));
  const challenge = base64url(
    new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
  );
  const state = base64url(crypto.getRandomValues(new Uint8Array(16)));

  let settle: (r: { code: string } | { error: string }) => void = () => {};
  const answered = new Promise<{ code: string } | { error: string }>((resolve) => {
    settle = resolve;
  });
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch(req) {
      const u = new URL(req.url);
      if (u.pathname !== "/") return new Response("not found", { status: 404 });
      if (u.searchParams.get("state") !== state) {
        return new Response("this sign-in does not match the running command", { status: 400 });
      }
      const code = u.searchParams.get("code");
      settle(code ? { code } : { error: u.searchParams.get("error") ?? "no code in the answer" });
      return new Response(
        code
          ? "Bunzzle got the authorization. You can close this tab."
          : "The authorization was not given.",
      );
    },
  });
  const redirect = `http://127.0.0.1:${server.port}`;
  try {
    const url = `${d.authUrl}?${new URLSearchParams({
      client_id: clientId,
      redirect_uri: redirect,
      response_type: "code",
      scope: POSTMASTER_SCOPE,
      access_type: "offline",
      prompt: "consent",
      state,
      code_challenge: challenge,
      code_challenge_method: "S256",
    })}`;
    d.print("Open this address in a browser on this machine and sign in with the Google account");
    d.print("that has your domains in Postmaster Tools:\n");
    d.print(url);
    const timer = setTimeout(
      () => settle({ error: "timed out waiting for the sign-in" }),
      d.waitMs,
    );
    const r = await answered;
    clearTimeout(timer);
    if ("error" in r) {
      d.print(`\nnot authorized: ${r.error}`);
      return 1;
    }
    const res = await fetch(d.tokenUrl, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: r.code,
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: redirect,
        code_verifier: verifier,
      }).toString(),
    });
    const body = (await res.json().catch(() => ({}))) as {
      refresh_token?: string;
      error_description?: string;
      error?: string;
    };
    if (!res.ok || !body.refresh_token) {
      d.print(
        `\nthe token exchange failed: ${body.error_description ?? body.error ?? `status ${res.status}`}`,
      );
      return 1;
    }
    await Bun.write(out, "");
    await Bun.$`chmod 600 ${out}`.quiet();
    await Bun.write(out, `${body.refresh_token}\n`);
    d.print(`\nSaved the refresh token to ${out} (mode 600). Then set:`);
    d.print(`  BUNZZLE_POSTMASTER_CLIENT_ID=${clientId}`);
    d.print(`  BUNZZLE_POSTMASTER_CLIENT_SECRET_FILE=<file with the client secret>`);
    d.print(`  BUNZZLE_POSTMASTER_REFRESH_TOKEN_FILE=<${out}, readable only by bunzzle-dns>`);
    return 0;
  } finally {
    await server.stop();
  }
}
