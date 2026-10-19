# Security policy

Bunzzle sends email on behalf of your applications and holds DKIM keys, API keys and email bodies. Every report gets an answer.

## Reporting a vulnerability

Please **do not open a public issue**. Report privately through either:

- GitHub: [Report a vulnerability](https://github.com/bunzzle/bunzzle/security/advisories/new) (private advisory), or
- Email: hello@bunzzle.com with "SECURITY" in the subject.

Include what you found, how to reproduce it (a minimal input, request or message helps most), the version (`bunzzle --version`) and what an attacker gains. If you found it with a fuzzer, the seed and input are enough.

What happens next:

| Step | Within |
|---|---|
| We confirm we received it | 3 days |
| We tell you whether we can reproduce it and how severe we think it is | 10 days |
| Fix released | as soon as possible; 90 days at most |
| Public advisory with credit (unless you prefer not to be named) | when the fix is released |

If a vulnerability is being exploited in the wild, we release a fix first and explain afterwards.

## Supported versions

Bunzzle is before 1.0. Only the latest release gets security fixes. Upgrade by replacing the binary or the image; the database migrates itself.

## Scope

In scope: everything in this repository, the released binaries and the container image. Examples:

- reading or changing data across the role boundaries (for example, `api` or `inbound` reaching keys, the database or plaintext bodies);
- forged bounces, complaints or unsubscribes being accepted;
- the server being used as an open relay or to reach private networks (SSRF through webhooks, MTA-STS or DNS);
- crashes, hangs or unbounded memory from outside input (HTTP, SMTP replies, DNS answers, inbound mail);
- bypassing API key scopes, domain restrictions or rate limits;
- recovering a body after its retention ended.

Out of scope: deliverability problems (an email landing in spam), denial of service by sheer traffic volume, problems that need root on the server or a stolen master key, and settings documented as unsafe (`BUNZZLE_ALLOW_PRIVATE_DESTINATIONS`).

## Safe harbor

We won't take legal action against research done in good faith: test only against your own installation, don't access other people's data, and give us reasonable time to fix before publishing.

## How Bunzzle is built to limit damage

- Six roles, six users. `api`, `core`, `delivery`, `dns`, `signer` and `inbound` run as separate processes. With the shipped systemd units (or the six-container compose file) each is a separate user in its own sandbox: `signer` and `core` have no network at all, only `signer` can read DKIM keys, only `core` can open the database. See [docs/security.md](docs/security.md).
- Encrypted at rest. DKIM keys are encrypted with a master key that never enters the database. Every email body has its own key; when retention ends the key is destroyed and the body is unreadable everywhere, backups included.
- API keys are hashed, scoped (`send`, `read`, `full`), optionally limited to domains, rate limited.
- Strict limits on outside input, and fuzz tests for every parser that reads it (DNS answers, SMTP replies, bounces and complaints, inbound SMTP, IPC frames, the HTTP API). Fuzzing runs on every push and nightly in CI.
- One private-network filter for SMTP, webhooks and MTA-STS fetches; no redirects; DNS-rebinding safe.
- Few dependencies: Bun and zod at runtime.
- Signed releases. Every binary and image comes with a checksum, a signature and an SBOM. See [docs/verify.md](docs/verify.md).
