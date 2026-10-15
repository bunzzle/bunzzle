# Bunzzle

Self-hosted email delivery engine for apps. Delivers straight to your recipients' mail servers. Bun-native, one binary, one SQLite file.

> Status: early development (milestone M6). Not usable in production yet.

## Develop

Requires [Bun](https://bun.sh) 1.4+ and [Biome](https://biomejs.dev) (`brew install biome`).

```sh
bun install
bun run dev        # start the server with reload on save
bun run check      # typecheck + lint + tests
bun run build      # single binary at dist/bunzzle
```

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
| inbound | incoming mail (later) | read the database or keys |

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
