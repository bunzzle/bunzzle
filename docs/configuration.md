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

## Inbound

Bounces, complaints and unsubscribe replies. Off unless a port is set.

| Variable | Default | |
|---|---|---|
| `BUNZZLE_INBOUND_PORT` | | Port for inbound mail. `25` in production. |
| `BUNZZLE_INBOUND_HOST` | `0.0.0.0` | Address the inbound port listens on. |
| `BUNZZLE_INBOUND_HOSTNAME` | `BUNZZLE_EHLO_NAME` | Name of this server in the bounce MX records. |
| `BUNZZLE_INBOUND_TLS_CERT_FILE` | | Certificate for STARTTLS on the inbound port. |
| `BUNZZLE_INBOUND_TLS_KEY_FILE` | | Private key for that certificate. |

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

## DNS on Cloudflare

| Variable | Default | |
|---|---|---|
| `BUNZZLE_CLOUDFLARE_API_TOKEN_FILE` | | File with a Cloudflare API token. Bunzzle then publishes and rotates its own DNS records. |
| `BUNZZLE_CLOUDFLARE_API_TOKEN` | | The token itself. Set this or the file, not both. |

Give the token only `Zone.DNS: Edit`, and only for the zones you send from. See [security.md](security.md) for what it can reach.

## Unsafe

| Variable | Default | |
|---|---|---|
| `BUNZZLE_ALLOW_PRIVATE_DESTINATIONS` | `false` | Allows delivery and webhooks to private networks. Only for local testing. |
