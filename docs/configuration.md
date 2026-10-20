# Configuration

Bunzzle reads its settings from environment variables. With the systemd install they live in `/etc/bunzzle/bunzzle.env`; with Docker, pass them to the container. Restart after a change.

[`.env.example`](../.env.example) has the defaults for running from a checkout.

## Server

| Variable | Default | |
|---|---|---|
| `BUNZZLE_HOST` | `127.0.0.1` | Address the API listens on. Use `0.0.0.0` inside Docker. |
| `BUNZZLE_PORT` | `3000` | API port. |
| `BUNZZLE_DATA_DIR` | `./data` | Where the SQLite database lives. |
| `BUNZZLE_RUN_DIR` | `./run` | Unix sockets the roles use to talk to each other. |
| `BUNZZLE_LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error`. |
| `BUNZZLE_PUBLIC_URL` | | Public https URL of the API, used in the one-click unsubscribe links of bulk email. |

## Sending

| Variable | Default | |
|---|---|---|
| `BUNZZLE_EHLO_NAME` | | Name the server introduces itself with. Must be the reverse DNS (PTR) name of the sending IP. |
| `BUNZZLE_SOURCE_IPS` | | Sending IPs, comma-separated. Add `=bulk` to put an IP in the bulk pool: `203.0.113.7,203.0.113.8=bulk`. |
| `BUNZZLE_SOURCE_IP` | | A single sending IP. Use `BUNZZLE_SOURCE_IPS` for more than one. |
| `BUNZZLE_ESTABLISHED_IPS` | | IPs that already have a good reputation. They skip warm-up. |
| `BUNZZLE_IPV6` | `false` | Also deliver over IPv6. Only with reverse DNS for the IPv6 address. |
| `BUNZZLE_DNS_SERVERS` | `/etc/resolv.conf` | DNS resolvers, comma-separated: `1.1.1.1,9.9.9.9`. |
| `BUNZZLE_DANE` | `auto` | `auto` uses DANE and checks DNSSEC for delivery lookups. When every DNS resolver is on this machine and validates DNSSEC (for example on `127.0.0.1`), its answers are trusted; otherwise Bunzzle validates DNSSEC itself, if the resolvers return signatures (checked at start; `bunzzle doctor` shows the result). `off` never uses DANE. |
| `BUNZZLE_REQUIRETLS` | `enforce` | For emails sent with `require_tls`. `enforce` follows RFC 8689: secure MX lookup, verified certificate, and a server that supports REQUIRETLS, or the email bounces. `relaxed` only requires TLS with a verified certificate and sends `REQUIRETLS` where the server supports it. |

## Keys and retention

| Variable | Default | |
|---|---|---|
| `BUNZZLE_MASTER_KEY_FILE` | | File with the master key. Create one with `bunzzle master-key`. |
| `BUNZZLE_MASTER_KEY` | | The master key itself, if a file is not possible. |
| `BUNZZLE_KEYS_DIR` | `./keys` | The signer's encrypted key store and DKIM key files. |
| `BUNZZLE_DKIM_KEY_FILE` | | One more DKIM key file to load, next to the ones in `BUNZZLE_KEYS_DIR`. |
| `BUNZZLE_DKIM_ROTATE_DAYS` | `90` | DKIM keys rotate after this many days. 7 to 3650. |
| `BUNZZLE_RETENTION_DAYS` | `30` | Email bodies become unreadable after this many days, backups included. 7 to 3650. |

The master key encrypts the DKIM keys and every email body. Keep it in a file only Bunzzle can read. If it is lost, stored keys and queued email cannot be read again.

## Event log

| Variable | Default | |
|---|---|---|
| `BUNZZLE_EVENT_LOG` | `false` | Write every delivery event to local files as JSON lines. |
| `BUNZZLE_EVENT_LOG_DIR` | `./logs/events` | Where the files go. With the systemd units: `/var/log/bunzzle/events`. |
| `BUNZZLE_EVENT_LOG_MAX_MB` | `100` | A new file starts after this many megabytes, and every day at 00:00 UTC. |
| `BUNZZLE_EVENT_LOG_DAYS` | `30` | Files older than this many days are deleted. |

The current file is `events-YYYYMMDD-HHMMSS.jsonl` (its start time in UTC), so `tail -f` works; finished files are gzipped. Each line is one event, for example:

```json
{"id":1042,"at":"2026-10-19T10:00:01.000Z","email_id":"01a1...","event":"recipient","source":"delivery","data":{"address":"user@example.com","status":"delivered"}}
```

The log starts with the events that happen after it is turned on. `id` grows with every event; after a crash a few lines can appear twice, so readers that need exact counts skip ids they have seen. If the disk is full, the log waits and catches up later; email keeps flowing.

## Inbound

Bounces, complaints and unsubscribe replies. Off unless a port is set.

| Variable | Default | |
|---|---|---|
| `BUNZZLE_INBOUND_PORT` | | Port for inbound mail. `25` in production. |
| `BUNZZLE_INBOUND_HOST` | `0.0.0.0` | Address the inbound port listens on. |
| `BUNZZLE_INBOUND_HOSTNAME` | `BUNZZLE_EHLO_NAME` | Name of this server in the bounce MX records. |
| `BUNZZLE_INBOUND_TLS_CERT_FILE` | | Certificate for STARTTLS on the inbound port. |
| `BUNZZLE_INBOUND_TLS_KEY_FILE` | | Private key for that certificate. |

## Relay

Only for servers whose provider blocks outbound port 25. All mail then goes to this relay instead of the recipients' mail servers, and the per-provider limits, MTA-STS and DANE no longer apply to the first hop. TLS with a valid certificate is always required before the password is sent.

| Variable | Default | |
|---|---|---|
| `BUNZZLE_RELAY_HOST` | | `host` or `host:port`. Port 587 (the default) uses STARTTLS, port 465 TLS from the first byte. |
| `BUNZZLE_RELAY_USERNAME` | | User name for SMTP AUTH. |
| `BUNZZLE_RELAY_PASSWORD_FILE` | | File with the password, readable only by the `bunzzle-delivery` user. |

## TLS reports

Receiving domains that publish an `_smtp._tls` record get a daily report about yesterday's TLS sessions with their mail servers (RFC 8460). Reports to an `https` address are always sent; reports to a `mailto` address need a sender.

| Variable | Default | |
|---|---|---|
| `BUNZZLE_TLSRPT_FROM` | | Sender for emailed reports, on a verified domain. Without it, only HTTPS reports are sent. |
| `BUNZZLE_TLSRPT_ORG` | `BUNZZLE_EHLO_NAME` | Organization name in the reports. |
| `BUNZZLE_TLSRPT_CONTACT` | `mailto:` + the sender | Contact in the reports. |

## SMTP submission

For apps that can only send through SMTP. Off unless a port is set, and it needs a certificate: nothing is accepted before TLS.

| Variable | Default | |
|---|---|---|
| `BUNZZLE_SUBMISSION_PORT` | | Port with STARTTLS. `587` in production. |
| `BUNZZLE_SUBMISSION_TLS_PORT` | | Port with TLS from the first byte. `465` in production. |
| `BUNZZLE_SUBMISSION_HOST` | `0.0.0.0` | Address the submission ports listen on. |
| `BUNZZLE_SUBMISSION_HOSTNAME` | `BUNZZLE_INBOUND_HOSTNAME` or `BUNZZLE_EHLO_NAME` | Name in the greeting; the certificate must match it. |
| `BUNZZLE_SUBMISSION_TLS_CERT_FILE` | | Certificate for the submission ports. Required when a port is set. |
| `BUNZZLE_SUBMISSION_TLS_KEY_FILE` | | Private key for that certificate. Readable by the `bunzzle-api` user. |

## Certificates

With an ACME email address, Bunzzle gets and renews a certificate for the inbound and submission hostnames by itself (Let's Encrypt by default), using DNS-01 challenges through the DNS provider below. Certificate files you set yourself always win.

| Variable | Default | |
|---|---|---|
| `BUNZZLE_ACME_EMAIL` | | Contact address for the certificate authority. Turns automatic certificates on; needs Cloudflare, DNS updates or Route 53. |
| `BUNZZLE_ACME_DIRECTORY` | Let's Encrypt | ACME directory URL of another certificate authority. |
| `BUNZZLE_CERTS_DIR` | `./certs` | Where the certificate and its key are kept. `/var/lib/bunzzle/certs` with the shipped units. |

The certificate is renewed 30 days before it expires. The inbound listener and the submission ports notice the new file within 10 minutes and restart to use it.

## DNS on Cloudflare

| Variable | Default | |
|---|---|---|
| `BUNZZLE_CLOUDFLARE_API_TOKEN_FILE` | | File with a Cloudflare API token. Bunzzle then publishes and rotates its own DNS records. |
| `BUNZZLE_CLOUDFLARE_API_TOKEN` | | The token itself. Set this or the file, not both. |

Give the token only `Zone.DNS: Edit`, and only for the zones you send from. See [security.md](security.md) for what it can reach.

## DNS with RFC 2136 updates

Instead of Cloudflare, Bunzzle can publish and rotate its records on any DNS server that accepts dynamic updates signed with a TSIG key (BIND, Knot, PowerDNS and others). It finds the zone of each record by its SOA and checks the server's signed answer.

| Variable | Default | |
|---|---|---|
| `BUNZZLE_DNS_UPDATE_SERVER` | | Primary server for the zones, `host` or `host:port`. |
| `BUNZZLE_DNS_UPDATE_KEY_NAME` | | Name of the TSIG key. |
| `BUNZZLE_DNS_UPDATE_KEY_FILE` | | File with the key's base64 secret, readable only by the `bunzzle-dns` user. |
| `BUNZZLE_DNS_UPDATE_ALGORITHM` | `hmac-sha256` | `hmac-sha256` or `hmac-sha512`. |

Allow the key to update only the names Bunzzle publishes: `*._domainkey`, `bounce` and `_dmarc` under each sending domain.

## DNS on Route 53

| Variable | Default | |
|---|---|---|
| `BUNZZLE_ROUTE53_ACCESS_KEY_ID` | | Access key ID of an IAM user made for Bunzzle. |
| `BUNZZLE_ROUTE53_SECRET_ACCESS_KEY_FILE` | | File with that user's secret access key, readable only by the `bunzzle-dns` user. |

Bunzzle finds the public hosted zone of each record by name (private zones are skipped) and changes only the values it owns, keeping the rest of the record set. Each change deletes the set as it was read and creates the new one in one batch, so if someone else edits the same set at that moment, the batch fails and Bunzzle reads it again instead of overwriting their edit. It then waits up to 40 seconds for Route 53 to report the change in sync.

Give the IAM user only `route53:ListHostedZonesByName`, `route53:ListResourceRecordSets`, `route53:ChangeResourceRecordSets` and `route53:GetChange`. Limit `ChangeResourceRecordSets` to your hosted zones, and with the `route53:ChangeResourceRecordSetsNormalizedRecordNames` condition key to the names Bunzzle publishes.

## Unsafe

| Variable | Default | |
|---|---|---|
| `BUNZZLE_ALLOW_PRIVATE_DESTINATIONS` | `false` | Allows delivery and webhooks to private networks. Only for local testing. |
