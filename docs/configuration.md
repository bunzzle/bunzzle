# Configuration

Bunzzle reads its settings from environment variables. With the systemd install they live in `/etc/bunzzle/bunzzle.env`; with Docker, pass them to the container.

After editing the file, `sudo systemctl reload 'bunzzle-*'` (or `kill -HUP` on `bunzzle serve` started with `BUNZZLE_ENV_FILE` pointing at the file) applies these settings without a restart: `BUNZZLE_LOG_LEVEL`, `BUNZZLE_RETENTION_DAYS`, `BUNZZLE_GUARD_MIN_VOLUME`, `BUNZZLE_ANOMALY_FLOOR`, `BUNZZLE_DKIM_ROTATE_DAYS`, `BUNZZLE_MIN_FREE_MB` and the destinations in `BUNZZLE_RELAY_FOR`. The log names every other changed setting; restart that role to apply it. A file with a mistake is not applied, and the running settings stay.

[`.env.example`](../.env.example) has the defaults for running from a checkout.

## Server

| Variable | Default | |
|---|---|---|
| `BUNZZLE_HOST` | `127.0.0.1` | Address the API listens on. Use `0.0.0.0` inside Docker. |
| `BUNZZLE_PORT` | `3000` | API port. |
| `BUNZZLE_DATA_DIR` | `./data` | Where the SQLite database lives. |
| `BUNZZLE_RUN_DIR` | `./run` | Unix sockets the roles use to talk to each other. |
| `BUNZZLE_LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error`. |
| `BUNZZLE_PUBLIC_URL` | | Public https URL of the API, used in the one-click unsubscribe links of bulk email. Tracking hosts are a CNAME to its host. |
| `BUNZZLE_TRACK_PORT` | | HTTPS port for open and click tracking, usually `443`. Each tracking host needs a certificate in `BUNZZLE_CERTS_DIR/track/HOST/`. |
| `BUNZZLE_TRACK_HOST` | `0.0.0.0` | Address the tracking port listens on. |

## Sending

| Variable | Default | |
|---|---|---|
| `BUNZZLE_EHLO_NAME` | | Name the server introduces itself with. Must be the reverse DNS (PTR) name of the sending IP. |
| `BUNZZLE_SOURCE_IPS` | | Sending IPs, comma-separated. Add `=name` to put an IP in a named pool: `203.0.113.7,203.0.113.8=bulk,203.0.113.9=acme`. Without a pool an IP is in `main`. |
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
| `BUNZZLE_MIN_FREE_MB` | `1024` | Below this much free space for `BUNZZLE_DATA_DIR`, new email is refused with a temporary error (HTTP 503 with `Retry-After`, SMTP 452 4.3.1) while queued email keeps being delivered. `0` turns the check off. |

The master key encrypts the DKIM keys and every email body. Keep it in a file only Bunzzle can read. If it is lost, stored keys and queued email cannot be read again.

## Event log

| Variable | Default | |
|---|---|---|
| `BUNZZLE_EVENT_LOG` | `false` | Write every delivery event to local files as JSON lines. |
| `BUNZZLE_SHARED_BOUNCES` | `true` | Suppress an address that bounced as not existing for every project, not only the one that sent to it. |
| `BUNZZLE_EVENT_LOG_DIR` | `./logs/events` | Where the files go. With the systemd units: `/var/log/bunzzle/events`. |
| `BUNZZLE_EVENT_LOG_MAX_MB` | `100` | A new file starts after this many megabytes, and every day at 00:00 UTC. |
| `BUNZZLE_EVENT_LOG_DAYS` | `30` | Files older than this many days are deleted. |

The current file is `events-YYYYMMDD-HHMMSS.jsonl` (its start time in UTC), so `tail -f` works; finished files are gzipped. Each line is one event, for example:

```json
{"id":1042,"at":"2026-10-19T10:00:01.000Z","email_id":"01a1...","event":"recipient","source":"delivery","data":{"address":"user@example.com","status":"delivered"}}
```

The log starts with the events that happen after it is turned on. `id` grows with every event; after a crash a few lines can appear twice, so readers that need exact counts skip ids they have seen. If the disk is full, the log waits and catches up later; email keeps flowing.

## Inbound

Bounces, complaints, unsubscribe replies and mail for inbound routes. Off unless a port is set.

| Variable | Default | |
|---|---|---|
| `BUNZZLE_INBOUND_PORT` | | Port for inbound mail. `25` in production. |
| `BUNZZLE_INBOUND_HOST` | `0.0.0.0` | Address the inbound port listens on. |
| `BUNZZLE_INBOUND_HOSTNAME` | `BUNZZLE_EHLO_NAME` | Name of this server in the bounce MX records. |
| `BUNZZLE_INBOUND_MAX_SIZE` | `10485760` | Largest message accepted, in bytes. Bounces and reports stay under 2 MB. |
| `BUNZZLE_INBOUND_TLS_CERT_FILE` | | Certificate for STARTTLS on the inbound port. |
| `BUNZZLE_INBOUND_TLS_KEY_FILE` | | Private key for that certificate. |
| `BUNZZLE_INBOUND_BLOCKLISTS` | | Lists the sending IP of route mail is looked up on: comma-separated, from `spamhaus`, `barracuda`, `spamcop`, `mailspike`, `psbl`. |
| `BUNZZLE_INBOUND_REFUSE` | | Route mail to refuse during the SMTP session: comma-separated, from `spf` (SPF fail), `dmarc` (DMARC fail with `p=reject`) and `blocklist` (listed on one of the lists above). |

Mail for inbound routes is checked for SPF (MAIL FROM, or the HELO name when MAIL FROM is empty), every DKIM signature, DMARC for the From domain, and the lists above. The results are in the `auth` field of the route request. With `dmarc` in `BUNZZLE_INBOUND_REFUSE`, a DMARC check that cannot finish because of a DNS error is answered with a temporary error, and a `quarantine` policy or `t=y` is delivered with the result. Inbound uses the public Spamhaus zone, so Spamhaus needs a local resolver there.

## Blocklists

Every 6 hours, each sending IP is looked up on Spamhaus ZEN, Barracuda, SpamCop, Mailspike and PSBL (IPv6 addresses on Spamhaus only). A list is used only when it returns its standard test entries correctly through your resolver (RFC 5782): a resolver that answers for names that do not exist, or a list that refuses the resolver, shows up as "could not check", never as a listing. A new listing is logged as a warning, `bunzzle doctor` shows it with the list's removal page, and mail moves to the sending IPs that are not listed while there are any.

Spamhaus refuses queries that come through large public resolvers. Run a local resolver, or use a free Spamhaus Data Query Service key:

| Variable | Default | |
|---|---|---|
| `BUNZZLE_SPAMHAUS_KEY_FILE` | | File with a Spamhaus Data Query Service key, readable only by the `bunzzle-delivery` user. |

## IP pools

Transactional mail goes out from the `main` pool and `"lane": "bulk"` mail from the `bulk` pool, when there is one. Any other pool name is for dedicated IPs: `bunzzle domains pool acme.test acme` (or `PATCH /domains/acme.test` with `{"ip_pool": "acme"}`) sends all of that domain's mail, both lanes, only from the IPs in `acme`, and `bunzzle keys create --pool acme` does the same for one API key, ahead of the domain's pool. If the pool has no usable IP, the mail waits instead of going out from shared IPs; `bunzzle doctor` shows it. `none` puts the domain back on the shared IPs. Warm-up and per-destination limits stay per IP. With several projects, `bunzzle pools own POOL PROJECT` keeps a pool for one project (see [projects.md](projects.md)).

## Relay

A relay takes all mail (for servers whose provider blocks outbound port 25), or only some of it while the rest goes straight to the recipients' mail servers. For mail sent through the relay, MTA-STS and DANE no longer apply to the first hop. TLS with a valid certificate is always required before the password is sent.

With `BUNZZLE_RELAY_FOR` set to a list, the relay takes mail for the listed recipient domains and providers (`google`, `microsoft`, `yahoo`, `apple` and the others `bunzzle paths` shows). With `blocked` in the list, mail for a destination that has blocked every sending IP goes through the relay while direct delivery there is paused; one probe email still goes direct, and once it is accepted, direct delivery resumes. Emails sent with `require_tls` never go through the relay this way. Each attempt in `GET /emails/:id` shows `"via": "relay"` or `"via": "direct"`.

| Variable | Default | |
|---|---|---|
| `BUNZZLE_RELAY_HOST` | | `host` or `host:port`. Port 587 (the default) uses STARTTLS, port 465 TLS from the first byte. |
| `BUNZZLE_RELAY_USERNAME` | | User name for SMTP AUTH. |
| `BUNZZLE_RELAY_PASSWORD_FILE` | | File with the password, readable only by the `bunzzle-delivery` user. |
| `BUNZZLE_RELAY_FOR` | `all` | `all`, or a comma-separated list of recipient domains, providers and `blocked`: `microsoft,blocked`. |

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

With an ACME email address, Bunzzle gets and renews a certificate for the inbound and submission hostnames, and one for each verified tracking host when `BUNZZLE_TRACK_PORT` is set, by itself (Let's Encrypt by default), using DNS-01 challenges through the DNS provider below. Certificate files you set yourself always win.

| Variable | Default | |
|---|---|---|
| `BUNZZLE_ACME_EMAIL` | | Contact address for the certificate authority. Turns automatic certificates on; needs Cloudflare, DNS updates, Route 53 or deSEC. |
| `BUNZZLE_ACME_DIRECTORY` | Let's Encrypt | ACME directory URL of another certificate authority. |
| `BUNZZLE_CERTS_DIR` | `./certs` | Where the certificate and its key are kept. `/var/lib/bunzzle/certs` with the shipped units. |

The certificate is renewed 30 days before it expires. The inbound listener, the submission ports and the tracking port notice the new file within 10 minutes and restart to use it.

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

## DNS on deSEC

| Variable | Default | |
|---|---|---|
| `BUNZZLE_DESEC_TOKEN_FILE` | | File with a deSEC API token, readable only by the `bunzzle-dns` user. |

Bunzzle finds the domain that owns each record name and changes only the values it owns, keeping the rest of the RRset. New RRsets get a TTL of 3600 seconds, the lowest deSEC accepts by default; existing ones keep their TTL. When the API asks Bunzzle to slow down, it waits as long as the answer says, up to a minute, and tries again.

Give the token no permission to manage tokens, and restrict it with token policies: a default policy without write permission, then one policy with write permission for each name Bunzzle publishes (`*._domainkey`, `bounce`, `_dmarc` and, with automatic certificates, `_acme-challenge` names under each sending domain). Set its allowed subnets to your server's addresses.

## Gmail Postmaster Tools

Gmail does not send a report for each complaint, so its spam rate is only visible in Postmaster Tools. With these settings, the `dns` role reads each verified domain's daily numbers every 6 hours. Bulk mail for a domain is held when Gmail reports a spam rate of 0.3% or more, or a BAD domain reputation, and a warning is logged from 0.1% or a LOW reputation. `bunzzle doctor` and `GET /domains/:name` (`gmail`) show the latest day: spam rate, reputation, SPF, DKIM and DMARC pass rates and the share sent over TLS.

| Variable | Default | |
|---|---|---|
| `BUNZZLE_POSTMASTER_CLIENT_ID` | | OAuth client ID (type "Desktop app") from a Google Cloud project with the Gmail Postmaster Tools API turned on. |
| `BUNZZLE_POSTMASTER_CLIENT_SECRET_FILE` | | File with that client's secret, readable only by the `bunzzle-dns` user. |
| `BUNZZLE_POSTMASTER_REFRESH_TOKEN_FILE` | | File with the refresh token from `bunzzle postmaster auth`, readable only by the `bunzzle-dns` user. |

Add and verify your domains in Postmaster Tools first. Then, on a machine with a browser, run `bunzzle postmaster auth --client-id ID --client-secret-file FILE --out FILE`, sign in with the same Google account, and copy the file it writes to the server. The command asks only for read access to Postmaster Tools, and prints neither the secret nor the token.

## Delegated DNS zone

With these settings the `ns` role answers DNS for one zone over UDP and TCP. Set the zone's NS records and glue at the parent to the names and addresses below. The role answers only for this zone and never resolves other names; zone transfers and dynamic updates are refused. Each client network gets a response rate limit, separately for answers, negative answers and errors; answers over the limit are dropped. Queries are not logged one by one; when limits were hit, one warning per minute gives the counts. The zone is saved to `BUNZZLE_DATA_DIR/ns-zone.json` and served from there after a restart. Core builds the zone and sends it to the `ns` role at start and after every change: `_spf.<zone>` with the sending IPs, `_check.<zone>` with the zone serial, and for each delegated domain a return-path MX and SPF record and its DKIM keys.

| Variable | Default | |
|---|---|---|
| `BUNZZLE_NS_ZONE` | | The delegated zone, for example `dz.mail.example.net`. Turns on the `ns` role. |
| `BUNZZLE_NS_NAMES` | | Comma-separated name server host names outside the zone, for example `ns1.mail.example.net,ns2.mail.example.net`. |
| `BUNZZLE_NS_LISTEN` | | Comma-separated public IP addresses to listen on. |
| `BUNZZLE_NS_PORT` | `53` | Port for UDP and TCP. |
| `BUNZZLE_NS_TTL` | `300` | TTL in seconds for the records in the zone (60 to 86400). |
| `BUNZZLE_NS_RRL_V4_PREFIX` | `24` | IPv4 prefix length that counts as one client network for the rate limit. |
| `BUNZZLE_NS_RRL_V6_PREFIX` | `56` | IPv6 prefix length that counts as one client network for the rate limit. |
| `BUNZZLE_NS_RRL_SLIP` | `0` | Send every Nth answer over the limit as an empty truncated reply, so real resolvers in a limited network can retry over TCP. `0` drops them all. |

To add a domain in delegated mode, run `bunzzle domains add DOMAIN --delegated` or send `"mode": "delegated"` to `POST /domains`; this needs `BUNZZLE_NS_ZONE` and `BUNZZLE_SOURCE_IPS`. The domain then lists CNAME records instead of TXT records: four for DKIM (`bza-r`, `bzb-r`, `bza-e` and `bzb-e` under `_domainkey`), one for `bounce.DOMAIN`, and an SPF record with `include:_spf.<zone>`. The domain verifies once each DKIM name leads to its target in the zone, directly or through more CNAMEs under the domain itself (up to eight names). A chain with a name outside the domain and the zone does not verify. Key rotation needs no DNS changes for a delegated domain: the new keys go into the free slot (`bza` or `bzb`), signing switches to them once the domain's DKIM names resolve to them and a signed test message verifies, and the old slot is emptied seven days later. To switch an existing domain, run `bunzzle domains mode DOMAIN delegated` (or `records`) or send `"mode"` to `PATCH /domains/DOMAIN`. Its current keys keep signing and its current records stay required until the new ones resolve; then signing switches and the old keys are removed seven days later. A domain switches only when it is verified and no key rotation is running. Without a mode, a domain uses `records`: the DKIM, SPF and return-path records go straight into its own zone.

To set up the zone, add NS records for `BUNZZLE_NS_ZONE` at its parent zone, one per name in `BUNZZLE_NS_NAMES`, and A or AAAA records for those names that point to the addresses in `BUNZZLE_NS_LISTEN`. Open port 53 (or `BUNZZLE_NS_PORT`) for both UDP and TCP on those addresses.

`bunzzle ns-check` shows the state of the zone: whether each listener answers over UDP and over TCP and serves the current serial, whether the delegation at the parent matches `BUNZZLE_NS_NAMES` and `BUNZZLE_NS_LISTEN`, and the DKIM slots of each delegated domain with the time a retiring slot is emptied. It exits with 1 when something is wrong.

Bunzzle checks the same things by itself: each listener every minute (every 10 seconds while one is down) and the delegation once a day (every hour while it does not match). `/metrics` reports `bunzzle_ns_up{ns,proto}`, `bunzzle_ns_serial_lag_seconds{ns}`, `bunzzle_ns_failures{ns}` and `bunzzle_ns_delegation_problems` from the last check, and `bunzzle_ns_healthy{ns}` and `bunzzle_ns_delegation_ok`, which stay 0 for as long as the problem lasts, while the event below is raised only once. The admin event log gets `ns.unhealthy` after three failed checks in a row or when a listener is more than 120 seconds behind, `ns.healthy` once it has passed every check for 10 minutes and at least an hour after it turned unhealthy, `ns.delegation_mismatch` when the delegation stops matching and `ns.delegation_ok` after two good checks in a row. A listener or delegation that keeps flapping therefore raises at most one pair of events an hour. These checks run on the Bunzzle host itself, so they cannot see a firewall or routing problem between the internet and the host. Also watch the zone from outside, for example by asking each address in `BUNZZLE_NS_LISTEN` for `_check.<zone>` TXT over UDP and TCP from another network.

All names in `BUNZZLE_NS_NAMES` are served by this one host. When the host is down, receivers cannot look up the DKIM keys and return path of delegated domains once their cached answers expire (`BUNZZLE_NS_TTL`), so DKIM fails for mail from those domains until the host is back.

## Testing the DNS provider

`bunzzle dns-test DOMAIN` checks the configured provider without `serve` running, so you can try it from any machine with the same variables. It publishes a TXT record at `_bunzzle-test.DOMAIN` with a random value longer than 255 characters, asks the provider for it again, waits up to two minutes until every name server of the zone answers with it, and removes it, also when a step fails. Each step prints `[ok]` or `[FAIL]`, and the command exits with 1 when one fails. The time it prints is how long the provider takes to publish a change.

```sh
BUNZZLE_DESEC_TOKEN_FILE=./desec-token bunzzle dns-test example.com
```

## Unsafe

| Variable | Default | |
|---|---|---|
| `BUNZZLE_ALLOW_PRIVATE_DESTINATIONS` | `false` | Allows delivery and webhooks to private networks. Only for local testing. |
