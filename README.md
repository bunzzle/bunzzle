<p align="center"><img src="assets/logo/bunzzle.svg" width="140" alt="Bunzzle"></p>

# Bunzzle

Self-hosted email delivery engine for apps. Delivers straight to your recipients' mail servers. Bun-native, one binary, one SQLite file.

> Status: v0.1.0, first release. Test it on a throwaway domain before sending real mail.

## Why

- A small HTTP API on your own server. `POST /emails` takes plain JSON, and webhooks are signed in the Standard Webhooks format.
- No relay in between. Bunzzle talks SMTP to Gmail, Outlook and every other receiver itself, so there is no sending service to pay per email. If your provider blocks port 25, you can still point it at a relay (`BUNZZLE_RELAY_HOST`), for all mail or only for some providers, and as a fallback while a provider blocks your IPs.
- New IPs warm up on their own, each destination gets a sending speed that follows its replies, bounces and complaints are suppressed, and bulk mail is held before it can delay your password resets.
- Six processes, each with only the access it needs. Every email body is encrypted with its own key, and DKIM keys never leave the signer.

It is for sending transactional and bulk email from your apps. It does not host mailboxes (no IMAP) and has no campaign editor.

## What you need

- A Linux server with outbound port 25 open and a static IP whose reverse DNS (PTR) you can set. Many providers block port 25 until you ask.
- A domain whose DNS you control, to publish the DKIM, SPF and bounce records Bunzzle prints (or let it publish them on Cloudflare, Route 53, deSEC or any DNS server that accepts RFC 2136 updates).

## Install

On a Linux server with systemd:

```sh
curl -fsSLO https://github.com/bunzzle/bunzzle/releases/latest/download/install.sh
sudo sh install.sh
```

Each of the six roles runs as its own user in its own systemd sandbox. Docker (one container or six) is covered in [docs/install.md](docs/install.md). Releases are signed; see [docs/verify.md](docs/verify.md). Security design: [docs/security.md](docs/security.md). Reporting a vulnerability: [SECURITY.md](SECURITY.md).

### First email

Create an API key (it is shown only once), add your domain and publish the DNS records it prints, verify the domain, then run `doctor`, which checks IPs, DNS and signing and tells you what to fix.

```sh
sudo bunzzle keys create --name my-app --scope full
sudo bunzzle domains add your.domain
sudo bunzzle domains verify your.domain
sudo bunzzle doctor

curl -X POST http://127.0.0.1:3000/emails \
  -H "Authorization: Bearer bz_…" -H "Content-Type: application/json" \
  -d '{"from":"You <hello@your.domain>","to":["you@example.com"],"subject":"Hi","text":"It works"}'
```

## API

```sh
curl -X POST http://127.0.0.1:3000/emails \
  -H "Authorization: Bearer bz_…" -H "Content-Type: application/json" \
  -H "Idempotency-Key: order-42" \
  -d '{"from":"You <hello@your.domain>","to":["someone@example.com"],"subject":"Hi","html":"<p>Hi</p>"}'

curl http://127.0.0.1:3000/emails/<id> -H "Authorization: Bearer bz_…"
```

`POST /emails` takes `from`, `to`, `cc`, `bcc`, `reply_to`, `subject`, `html`, `text`, `template`, `headers`, `attachments`, `tags`, `scheduled_at`, `expires_at`, `require_tls` and `tracking`. `GET /emails/:id` shows each recipient's status and every attempt: the MX host, TLS version, whether the certificate was verified, the rule that applied, the server's reply and the whole SMTP conversation with timings (without the message content or passwords, kept for `BUNZZLE_RETENTION_DAYS`). Bodies are never returned: once accepted, only the signer can decrypt them. `POST /emails/batch` takes an array of up to 100 such emails and returns their ids in order; if one of them is invalid, none is queued. Until a scheduled email starts sending, `PATCH /emails/:id` with a new `scheduled_at` moves it and `POST /emails/:id/cancel` cancels it.

`GET /emails` searches by recipient (`to`), status, tag (`tag=name:value`), sender domain and time (`since`, `until`), newest first, with `limit` and `cursor`. `GET /stats` counts sent, delivered, deferred, bounced, failed, suppressed, complained and unsubscribed per day, for all mail or one `domain` or `tag` (`since` and `until` as `YYYY-MM-DD`, the last 7 days by default). `bunzzle emails list` and `bunzzle stats` show the same from the server. Email sent with a test key is left out of the stats.

The whole API is described in [openapi.json](openapi.json) (OpenAPI 3.1); `bunzzle openapi` prints the description for the version you run. A TypeScript and JavaScript client generated from it is in [sdk/typescript](sdk/typescript).

API keys are shown once and stored only as a hash. They have a scope (`send`, `read`, `full`), can be limited to some domains (`--domain`) and have a per-second rate limit.

### Templates

```sh
curl -X POST http://127.0.0.1:3000/templates \
  -H "Authorization: Bearer bz_…" -H "Content-Type: application/json" \
  -d '{"name":"welcome","subject":"Welcome, {{name}}","html":"<p>Hi {{name}}</p>{{#if trial}}<p>Your trial ends {{trial.ends}}</p>{{/if}}","text":"Hi {{name}}"}'

curl -X POST http://127.0.0.1:3000/emails \
  -H "Authorization: Bearer bz_…" -H "Content-Type: application/json" \
  -d '{"from":"You <hello@your.domain>","to":"someone@example.com","template":{"id":"welcome","variables":{"name":"Ayşe"}}}'
```

A template has a `subject` and `html`, `text` or both. `{{name}}` inserts a variable and `{{order.id}}` a nested one. In HTML, values are escaped; `{{{name}}}` inserts one as it is. `{{#if name}}…{{else}}…{{/if}}` shows a part only when the value is set and not empty, and `{{#each items}}…{{/each}}` repeats a part for each entry of a list, with `{{this}}` or `{{this.field}}` for the entry. A missing variable refuses the email with the names of all missing variables, so nothing goes out half filled. Syntax errors are refused when the template is saved, with the line.

Send with `template` instead of `subject`, `html` and `text`; each email in `POST /emails/batch` has its own `variables`. `PATCH /templates/:id` saves a new version (fields left out are kept) and email uses the newest one unless `template.version` asks for another. `GET /templates/:id?version=N` shows a version, `POST /templates/:id/preview` with `variables` (and `version`) returns the filled subject, HTML and text without sending, and `GET /templates` and `DELETE /templates/:id` list and remove. `:id` is the template's id or name. Keys with the send scope can send with templates and preview them; changing them needs the full scope.

### Open and click tracking

```sh
curl -X PATCH http://127.0.0.1:3000/domains/your.domain \
  -H "Authorization: Bearer bz_…" -H "Content-Type: application/json" \
  -d '{"tracking":{"host":"links.your.domain","opens":true,"clicks":true}}'
```

Tracking is off until a domain has a tracking host: a subdomain with a CNAME record to the host of `BUNZZLE_PUBLIC_URL`. `GET /domains/:name` shows the record and its status. Once the record is verified, `opens` and `clicks` apply to every email from the domain, and `"tracking": {"opens": false, "clicks": true}` on an email changes that for this email only. An email that asks for tracking before the host is verified is refused. `bunzzle domains tracking DOMAIN HOST --opens --clicks` does the same from the server, and `none` removes the host.

Every `http` and `https` link in the HTML part then goes through `https://links.your.domain/c/…` and redirects to the original address. Each link is signed with the email id and the address it points to; a changed or made-up link gets a 404, so the host never redirects anywhere else. Links keep working after retention ends. Links with a `data-no-track` attribute and the text part stay as they are. For opens, a 1×1 image is added at the end of the HTML part.

Each open and click is an event on `GET /emails/:id` and an `email.opened` or `email.clicked` webhook with the user agent, at most 100 of each per email. IP addresses are not stored. HEAD requests redirect without counting, so mail scanners that check links that way are left out.

The API answers `/o/…` and `/c/…`, so a reverse proxy can serve the tracking host with its own certificate and pass it on. With `BUNZZLE_TRACK_PORT=443`, Bunzzle serves the tracking hosts over HTTPS itself, with the certificate of each host from `BUNZZLE_CERTS_DIR/track/HOST/` (`cert.pem` and `key.pem`), and gets and renews them by itself when `BUNZZLE_ACME_EMAIL` and a DNS provider are set.

### Checks before sending

```sh
bunzzle hooks add check https://checks.internal/email --on-error refuse
bunzzle hooks add scan http://127.0.0.1:8080/scan --max-score 6
```

Hooks are set by the operator with `bunzzle hooks`, not through the API, and may point to addresses on the local network. They run in the order they were added, before an email is queued, so the caller gets the answer right away.

A `check` hook gets each email sent through the API as JSON: `{"email": {...}, "api_key_id": "..."}`, with the fields of `POST /emails` after a template is filled (attachments only by name and type). It answers `{"action": "accept"}` (or 204), `{"action": "refuse", "reason": "..."}`, which refuses the email with a 422 and the reason, or `{"action": "change", "email": {...}}` with new `subject`, `html`, `text`, `headers` or `tags`. Open and click tracking is added after the checks.

A `scan` hook gets every email, from the API and from SMTP submission, as the whole message (`message/rfc822`) with the envelope sender in a `From` header and a recipient in `Rcpt`. It answers JSON with a numeric `score`; at `--max-score` or above, the email is refused with a 422.

Each hook has a timeout (`--timeout-ms`, 2,000 by default). A hook that times out, fails or answers something else is skipped with a warning in the log, or, with `--on-error refuse`, the email is refused with a 503 so the caller tries again. Use IP addresses for hooks on the same machine; the egress filter lets the delivery role reach other machines on port 443 only.

### Test mode

`bunzzle keys create --name dev --test` creates a test key. Email sent with it goes through the same checks, gets an id, events and webhooks, and is never delivered: every recipient counts as delivered. A test key can send from a domain that is added but not verified yet.

Addresses at `simulator.test` behave the same way with any key and never leave the server:

| Address | What happens |
|---|---|
| `delivered@simulator.test` | delivered |
| `bounced@simulator.test` | permanent bounce (5.1.1), the address is suppressed |
| `deferred@simulator.test` | deferred once, delivered on the retry |
| `complained@simulator.test` | delivered, then a complaint; the address is suppressed for bulk mail |
| `suppressed@simulator.test` | refused at intake as suppressed |

Simulated bounces and complaints do not count toward the reputation guards or IP warm-up.

### SMTP

Apps that can only send through SMTP can use Bunzzle as their mail server. Set `BUNZZLE_SUBMISSION_PORT=587` (and `BUNZZLE_SUBMISSION_TLS_PORT=465` if the app wants TLS from the start) with a certificate, then give the app these settings:

```
host      mail.your.domain
port      587 (STARTTLS) or 465 (TLS)
username  anything
password  an API key with the send scope (bz_…)
```

Nothing is accepted before TLS: `AUTH` and `MAIL` are refused on a plain connection. Each message goes through the same checks as `POST /emails`: the From domain must be verified and allowed for the key, `Bcc:` is removed, `Message-ID` and `Date` are added when missing, and the reply carries the email id (`250 2.0.0 Ok: queued as …`). 8-bit content must be UTF-8. Ten failed logins from one address lock it out for 15 minutes.

### Polite sending

Bunzzle keeps a speed per destination (per provider for Gmail, Microsoft, Yahoo and others), starting from conservative limits. When a receiver says "too many connections", the speed is halved and held; when it says your IP is blocked, sending there pauses, then resumes with one probe email and climbs back slowly. Connections are reused. Emails sent with `"lane": "bulk"` never delay transactional ones: a password reset goes ahead of any queued newsletter, while bulk still gets a small guaranteed share. `GET /paths` (or `bunzzle paths`) shows each destination's current speed, its limits and every change with the reason. During an incident, `bunzzle queue` (or `GET /queue`) shows what is waiting per recipient domain and per route. `bunzzle queue suspend --domain NAME` or `--provider ID` holds delivery there with a reason and an optional end time; emails stay queued and still expire on time, and `bunzzle queue resume` releases them at once. `bunzzle queue fail` and `bunzzle queue cancel` remove queued emails by recipient domain, sender domain or age, with `--dry-run` to see the count first. `GET /metrics` (API key with the read scope) gives the same state in the OpenMetrics text format for a monitoring system: jobs by state, recipients by status and domain, each path's speed, pause and backlog, webhook backlog, suppressions and holds.

### Bounces, complaints and unsubscribes

Receivers report back, and Bunzzle acts on it:

- Signed return path. Once `bounce.your.domain` has the MX and SPF records `domains add` prints, mail is sent with `MAIL FROM:<b-…@bounce.your.domain>`. The token is signed, so every bounce maps to the exact email, and forged bounces are refused. SPF then also aligns with your domain.
- An inbound listener (`BUNZZLE_INBOUND_PORT`, 25 in production) accepts bounce, unsubscribe and feedback addresses, and addresses with a route. It reads standard bounces (DSN), non-standard bounces, complaint reports (ARF, to `fbl@bounce.your.domain`) and ignores auto-replies. With a certificate (`BUNZZLE_INBOUND_TLS_CERT_FILE`, `BUNZZLE_INBOUND_TLS_KEY_FILE`) it offers STARTTLS, so bounces and complaints, which quote your recipients' addresses, arrive encrypted. An address that keeps guessing recipients, sending unknown commands or idling is refused for 15 minutes; the submission ports do the same.
- Inbound routes. `bunzzle routes add support@your.domain https://app.your.domain/inbound` (or `POST /routes`) posts every message for that address, or for `*@your.domain`, to your app as JSON: envelope, headers, text, HTML and attachments, or the raw message with `--raw`. Requests are signed in the Standard Webhooks format with the secret shown once. 429 and 5xx answers are retried, with `Retry-After` honored, for about a day; any other 4xx stops at once, and `bunzzle routes retry ID` sends those again. Point the domain's MX at this server.
- A suppression list, checked for every email: hard bounces stop all mail for a year, a domain that doesn't exist for 30 days; complaints and unsubscribes stop bulk mail only, for good. Password resets still reach someone who unsubscribed from a newsletter. `GET/POST/DELETE /suppressions` or `bunzzle suppressions`.
- One-click unsubscribe (required by Gmail and Yahoo for bulk senders) is added to every `"lane": "bulk"` email, signed into DKIM, hosted at `BUNZZLE_PUBLIC_URL/u/…`.
- Webhooks: `email.delivered`, `email.delivery_delayed`, `email.bounced`, `email.complained`, `email.unsubscribed`, `email.suppressed`, `email.failed`, `email.canceled`, `email.opened`, `email.clicked`. Signed in the Standard Webhooks format. Retried for about a day. Webhook URLs that point to private networks are refused.
- Event log. With `BUNZZLE_EVENT_LOG=true` every event also goes to local files, one JSON object per line, rotated daily and gzipped, for log shippers and `grep` (see `docs/configuration.md`).

### Reputation

- IPs and warm-up. List your sending IPs in `BUNZZLE_SOURCE_IPS` (`ip` or `ip=bulk` for a bulk pool). Each IP's reverse DNS is checked and its PTR name used as EHLO. A new IP warms up by itself: a daily budget per provider that doubles in week one and grows by half after, but only when yesterday was healthy (few deferrals, bounces, complaints, no blocks); trouble steps it back and alerts you. `bunzzle ips` shows "warming, day 6 of ~14, today's budget 1600". IPs in `BUNZZLE_ESTABLISHED_IPS` skip warm-up.
- Guards. Bulk mail for a domain is held before Gmail's 0.3% complaint line, counted from complaint reports and, once Postmaster Tools is connected, from Gmail's own numbers (or at 5% hard bounces), and bulk mail from an API key is held when it suddenly sends ten times its normal volume, as a leaked key would. Transactional mail keeps flowing. `bunzzle holds` shows why; `bunzzle holds release ID` reopens.
- TLS reports. Domains that ask for them (an `_smtp._tls` record) get a daily report (RFC 8460) on how TLS went with their mail servers: sessions, certificate problems, missing STARTTLS, per MTA-STS policy. HTTPS reports go out by themselves; emailed reports need `BUNZZLE_TLSRPT_FROM`.
- DMARC reports. With the inbound listener set up, the DMARC record `domains add` prints asks mailbox providers to send their daily aggregate reports to `dmarc@bounce.your.domain`. Bunzzle reads them (zip, gzip or plain XML) and `GET /domains/:name/dmarc` or `bunzzle domains reports NAME` shows, per day, which IPs sent mail as your domain and whether it passed DKIM and SPF. A server you don't know in that list is someone sending as you.
- DANE. Recipient domains that sign their DNS and publish TLSA records for their MX hosts get TLS checked against those records, even without a public certificate. Bunzzle checks the DNSSEC signatures itself, from the root down, so no extra resolver is needed; a DNSSEC-validating resolver on the same machine (for example on `127.0.0.1`) is used instead when there is one. Answers whose signatures do not check out are not used: their email waits and is retried. A server whose certificate matches none of them is never used. `GET /emails/:id` shows `dane` as the TLS status when it applied.
- MTA-STS. Recipient domains that publish an MTA-STS policy get exactly what they ask for: only their listed MX hosts, only over TLS with a valid certificate.
- REQUIRETLS. An email sent with `require_tls: true` (`--require-tls`, or `REQUIRETLS` on `MAIL FROM` over SMTP submission) goes only to a mail server found through DNSSEC or an enforced MTA-STS policy, over TLS with a verified certificate, and only if that server supports REQUIRETLS too, so the requirement travels with the email (RFC 8689). Otherwise it bounces right away (class `requiretls-unsupported`, the address is not suppressed); few mailbox providers support REQUIRETLS yet. `BUNZZLE_REQUIRETLS=relaxed` still requires TLS with a verified certificate but drops the other two checks. A `TLS-Required: No` header does the opposite: the email ignores the recipient's MTA-STS and DANE policies, for reaching a server with a broken certificate.
- DKIM rotation. Keys rotate every 90 days (`BUNZZLE_DKIM_ROTATE_DAYS`): new keys are created and published, Bunzzle switches only after their DNS records verify and a real signature checks out against live DNS, and the old keys stay published for 7 days. With `BUNZZLE_CLOUDFLARE_API_TOKEN` (DNS edit for your zone), every record Bunzzle owns is published for you.
- `bunzzle doctor` checks the configuration, every IP's reverse DNS and blocklist listings, every DNS record of every domain (and what to change), signs a test message and verifies it against live DNS, and lists holds, paused destinations and failing webhooks.
- `bunzzle dns-test DOMAIN` publishes a test record through the configured DNS provider, checks that every name server of the zone serves it, and removes it.

## Send one email without the server

`dkim keygen` creates a key encrypted with the master key and prints the DNS records to publish.

```sh
./dist/bunzzle dkim keygen --domain your.domain --out dkim.json
./dist/bunzzle send --from "You <hello@your.domain>" --to someone@example.com \
  --subject "Hello" --text "Sent by Bunzzle" --dkim-keys dkim.json --ehlo mail.your.domain
```

The sending server needs outbound port 25 and a reverse DNS (PTR) record matching `--ehlo`.

When a recipient is refused, `send` says what the reply means: who it is about (the recipient, the message, your sender setup, your IP's reputation or the sending rate) and what Bunzzle does about it. Only a permanent problem with the recipient's own address ever marks it for suppression.

## How it's built

Bunzzle runs as six separate processes, each holding only what it needs:

| Role | Does | Cannot |
|---|---|---|
| api | HTTP from the internet | touch the database, keys or the network beyond its port |
| core | queue, retries, the database | reach the network or read keys; it can encrypt bodies but not decrypt them |
| delivery | DNS and SMTP to recipients' servers | read the database or any key |
| signer | DKIM signing, body decryption | reach the network or the database |
| inbound | bounces and complaints | read the database or keys |
| dns | publishes DNS records through the provider's API | read email, the database or any key |

Every email body is encrypted with its own key, and those keys are destroyed when retention ends, so old backups stay unreadable. A role that crashes is restarted; email in flight is reconciled, never silently sent twice.

## Performance

On a 2-CPU, 2 GB Linux machine (the load generator and test mail servers on the same two CPUs):

| | |
|---|---|
| Emails accepted by the API, stored durably | 5,900–6,500 per second, p99 under 27 ms |
| Emails delivered end to end, STARTTLS and two DKIM signatures each | 1,480 per second |
| CPU per delivered email | 1.2 ms, two thirds of it the RSA signature |

Memory for all roles stays around 285 MB during sustained sending (measured separately, 60,000 emails). In practice receivers set the pace long before the CPU does. Method and more numbers: [bench/README.md](bench/README.md).

## Develop

Requires [Bun](https://bun.sh) 1.4+ and [Biome](https://biomejs.dev) (`brew install biome`).

```sh
bun install
bun run dev
bun run check
bun run build
```

`dev` starts the server and reloads on save, `check` runs the type check, the linter and the tests, and `build` makes a single binary at `dist/bunzzle`. After changing the API, `bun run openapi` writes `openapi.json` and the SDK again; a test fails while they are out of date.

Tests include fuzzing of every parser that reads outside input (`test/fuzz`, more iterations with `BUNZZLE_FUZZ_ITERATIONS`) and an end-to-end check for any installed server (`test/system/e2e.ts`).

### Run locally

Keep the master key somewhere safe, outside the database.

```sh
export BUNZZLE_MASTER_KEY=$(./dist/bunzzle master-key)
./dist/bunzzle serve
curl localhost:3000/health
```

Configuration is read from environment variables. Every setting is listed in [docs/configuration.md](docs/configuration.md).

## License

[AGPL-3.0](LICENSE).
