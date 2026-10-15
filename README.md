# Bunzzle

Self-hosted email delivery engine for apps. Delivers straight to your recipients' mail servers. Bun-native, one binary, one SQLite file.

> Status: v0.1.0, first release. Test it on a throwaway domain before sending real mail.

## Install

On a Linux server with systemd:

```sh
curl -fsSLO https://github.com/bunzzle/bunzzle/releases/latest/download/install.sh
sudo sh install.sh
```

Each of the five roles runs as its own user in its own systemd sandbox. Docker (one container or five) is covered in [docs/install.md](docs/install.md). Releases are signed; see [docs/verify.md](docs/verify.md). Security design: [docs/security.md](docs/security.md). Reporting a vulnerability: [SECURITY.md](SECURITY.md).

## Develop

Requires [Bun](https://bun.sh) 1.4+ and [Biome](https://biomejs.dev) (`brew install biome`).

```sh
bun install
bun run dev        # start the server with reload on save
bun run check      # typecheck + lint + tests
bun run build      # single binary at dist/bunzzle
```

Tests include fuzzing of every parser that reads outside input (`test/fuzz`, more iterations with `BUNZZLE_FUZZ_ITERATIONS`) and an end-to-end check for any installed server (`test/system/e2e.ts`).

## Run

```sh
export BUNZZLE_MASTER_KEY=$(./dist/bunzzle master-key)   # keep it safe, outside the database
./dist/bunzzle serve
curl localhost:3000/health
```

`serve` starts five separate processes, each holding only what it needs:

| Role | Does | Cannot |
|---|---|---|
| api | HTTP from the internet | touch the database, keys or the network beyond its port |
| core | queue, retries, the database | reach the network or read keys; it can encrypt bodies but not decrypt them |
| delivery | DNS and SMTP to recipients' servers | read the database or any key |
| signer | DKIM signing, body decryption | reach the network or the database |
| inbound | bounces and complaints | read the database or keys |

Every email body is encrypted with its own key, and those keys are destroyed when retention ends, so old backups stay unreadable. A role that crashes is restarted; email in flight is reconciled, never silently sent twice.

Configuration is read from environment variables. See `.env.example`.

## Send with the API

With `serve` running:

```sh
./dist/bunzzle keys create --name my-app          # prints a bz_… key once; only its hash is stored
./dist/bunzzle domains add your.domain           # creates DKIM keys, prints the TXT records to publish
./dist/bunzzle domains verify your.domain        # only verified domains can send

curl -X POST localhost:3000/emails \
  -H "Authorization: Bearer bz_…" -H "Content-Type: application/json" \
  -H "Idempotency-Key: order-42" \
  -d '{"from":"You <hello@your.domain>","to":["someone@example.com"],"subject":"Hi","html":"<p>Hi</p>"}'

curl localhost:3000/emails/<id> -H "Authorization: Bearer bz_…"
```

`POST /emails` takes the same fields as Resend (`from`, `to`, `cc`, `bcc`, `reply_to`, `subject`, `html`, `text`, `headers`, `attachments`, `tags`, `scheduled_at`) plus `expires_at` and `require_tls`. `GET /emails/:id` shows each recipient's status and every attempt: the MX host, TLS version, whether the certificate was verified, the rule that applied and the server's reply. Bodies are never returned: once accepted, only the signer can decrypt them.

Keys have a scope (`send`, `read`, `full`), can be limited to some domains (`--domain`) and have a per-second rate limit.

### Polite sending

Bunzzle keeps a speed per destination (per provider for Gmail, Microsoft, Yahoo and others), starting from conservative limits. When a receiver says "too many connections", the speed is halved and held; when it says your IP is blocked, sending there pauses, then resumes with one probe email and climbs back slowly. Connections are reused. Emails sent with `"lane": "bulk"` never delay transactional ones: a password reset goes ahead of any queued newsletter, while bulk still gets a small guaranteed share. `GET /paths` (or `bunzzle paths`) shows each destination's current speed, its limits and every change with the reason.

### Bounces, complaints and unsubscribes

Bunzzle hears back from receivers and acts on it:

- **Signed return path.** Once `bounce.your.domain` has the MX and SPF records `domains add` prints, mail is sent with `MAIL FROM:<b-…@bounce.your.domain>`. The token is signed, so every bounce maps to the exact email, and forged bounces are refused. SPF then also aligns with your domain.
- **Inbound listener** (`BUNZZLE_INBOUND_PORT`, 25 in production) accepts only bounce, unsubscribe and feedback addresses. It reads standard bounces (DSN), non-standard bounces, complaint reports (ARF, to `fbl@bounce.your.domain`) and ignores auto-replies.
- **Suppression list**, checked for every email: hard bounces stop all mail for a year, a domain that doesn't exist for 30 days; complaints and unsubscribes stop bulk mail only, for good. Password resets still reach someone who unsubscribed from a newsletter. `GET/POST/DELETE /suppressions` or `bunzzle suppressions`.
- **One-click unsubscribe** (Gmail and Yahoo bulk-sender rule) is added to every `"lane": "bulk"` email, signed into DKIM, hosted at `BUNZZLE_PUBLIC_URL/u/…`.
- **Webhooks**: `email.delivered`, `email.delivery_delayed`, `email.bounced`, `email.complained`, `email.unsubscribed`, `email.suppressed`, `email.failed`. Signed in the Standard Webhooks / Svix format, so the verification code you use for Resend works. Retried for about a day. Webhook URLs that point to private networks are refused.

### Reputation on autopilot

- **IPs, reverse DNS and warm-up.** List your sending IPs in `BUNZZLE_SOURCE_IPS` (`ip` or `ip=bulk` for a bulk pool). Each IP's reverse DNS is checked and its PTR name used as EHLO. A new IP warms up by itself: a daily budget per provider that doubles in week one and grows by half after, but only when yesterday was healthy (few deferrals, bounces, complaints, no blocks); trouble steps it back and alerts you. `bunzzle ips` shows "warming, day 6 of ~14, today's budget 1600". IPs in `BUNZZLE_ESTABLISHED_IPS` skip warm-up.
- **Guards.** Bulk mail for a domain is held before Gmail's 0.3% complaint line (or at 5% hard bounces), and bulk mail from an API key is held when it suddenly sends ten times its normal volume, as a leaked key would. Transactional mail keeps flowing. `bunzzle holds` shows why; `bunzzle holds release ID` reopens.
- **MTA-STS.** Recipient domains that publish an MTA-STS policy get exactly what they ask for: only their listed MX hosts, only over TLS with a valid certificate.
- **DKIM rotation.** Keys rotate every 90 days (`BUNZZLE_DKIM_ROTATE_DAYS`): new keys are created and published, Bunzzle switches only after their DNS records verify and a real signature checks out against live DNS, and the old keys stay published for 7 days. With `BUNZZLE_CLOUDFLARE_API_TOKEN` (DNS edit for your zone), every record Bunzzle owns is published for you.
- **`bunzzle doctor`** checks the configuration, every IP's reverse DNS, every DNS record of every domain (and what to change), signs a test message and verifies it against live DNS, and lists holds, paused destinations and failing webhooks.

## Send one email

```sh
./dist/bunzzle dkim keygen --domain your.domain --out dkim.json   # encrypted with the master key; prints the DNS records
./dist/bunzzle send --from "You <hello@your.domain>" --to someone@example.com \
  --subject "Hello" --text "Sent by Bunzzle" --dkim-keys dkim.json --ehlo mail.your.domain
```

The sending server needs outbound port 25 and a reverse DNS (PTR) record matching `--ehlo`.

When a recipient is refused, `send` says what the reply means: who it is about (the recipient, the message, your sender setup, your IP's reputation or the sending rate) and what Bunzzle does about it. Only a permanent problem with the recipient's own address ever marks it for suppression.

## License

The server is licensed under [AGPL-3.0](LICENSE). SDKs will be MIT.
