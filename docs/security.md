# Security design

How Bunzzle limits what an attacker gets. To report a vulnerability, see [SECURITY.md](../SECURITY.md).

## Six roles

| Role | Holds | Talks to | Outside input |
|---|---|---|---|
| api | nothing secret | core | HTTP requests |
| core | the database (bodies encrypted) | signer, delivery, dns | none |
| delivery | one email at a time while sending | signer | DNS answers, SMTP replies, HTTPS (webhooks, MTA-STS) |
| dns | the DNS provider token, if one is set | the DNS provider's API | its API replies |
| signer | DKIM keys, master key | nobody | none |
| inbound | its TLS key, if STARTTLS is on | core | SMTP from the internet |

- Roles exchange small JSON messages over Unix sockets; every message is validated on arrival.
- The roles that read outside input hold nothing worth stealing (at most the inbound TLS key) and can't open the database.
- Only `core` opens the database, and `core` has no network. To reach stored data, an attacker has to break two roles.
- A broken `delivery` or `core` can still ask the signer for signatures, but can never read a key. Key rotation and the volume guards limit the rest.

With the systemd units or the six-container compose file, each role is a separate user in its own sandbox (see [install.md](install.md)). With `bunzzle serve` (one container, or a laptop) the roles are separate processes of one user: the boundaries in the code still hold, but the OS doesn't enforce them.

## Data

- **Master key** outside the database: a file or a systemd credential, given only to the signer.
- **DKIM keys** are encrypted with the master key; only the signer decrypts them.
- **Every email body** is encrypted with its own key, wrapped for the signer. `core` can encrypt bodies but can't decrypt them. When retention ends (30 days by default), the key is destroyed and the body is unreadable everywhere, backups included.
- **API keys** are stored as SHA-256 hashes and shown once.
- **Webhook secrets** are derived from the master key in the signer and never stored.
- **Logs** never contain bodies.
- **Opens and clicks** keep the user agent and the link, never the IP address.
- **Cloudflare API token** (optional, for publishing DNS records and rotating DKIM keys without manual steps) is held only by `dns`, a role that sees no email, no keys and no database, and whose only network access is the provider's API. Someone who takes over `delivery` cannot use it. Create it with only `Zone.DNS: Edit`, limited to the zones Bunzzle sends for. A Route 53 access key, a deSEC token, a TSIG key or a Postmaster Tools refresh token is held the same way; give it only the permissions listed in [configuration.md](configuration.md). Without a token, Bunzzle prints the records and waits for you to publish them; rotation then pauses at that step and keeps signing with the current keys.

## Outside input

Every parser has limits:
- HTTP bodies: size cap.
- SMTP replies: line and reply length caps.
- DNS: name length, pointer loops.
- Inbound mail: 10 MB (`BUNZZLE_INBOUND_MAX_SIZE`), 10 recipients; bounces and reports 2 MB, 500 headers, 50 parts, depth 5; mail for routes 1,000 headers, 200 parts, depth 10.
- Templates: 998 characters of subject, 2 MB of HTML and of text, blocks nested 10 deep, 40 MB of output per part. Variables are filled in HTML-escaped unless `{{{ }}}` asks otherwise; a line break in a filled subject is refused.
- HTML for tracking: 200 links per email, 2,000 characters per link; longer links are left as they are.
- IPC frames: size cap.

Every one of these is fuzzed (`test/fuzz`): a few thousand inputs per target in every test run, 200,000 per target nightly in CI. Reproduce a failure with `BUNZZLE_FUZZ_SEED=<seed> bun test test/fuzz`.

## Network

One private-network filter covers SMTP, webhooks, inbound routes, MTA-STS and DNS provider requests. Delivery resolves names itself and connects to the vetted IP, while TLS still checks the name. This stops DNS rebinding. Redirects are never followed.

## Abuse

- Only verified domains can send.
- Inbound accepts only signed bounce and unsubscribe addresses and addresses with a route, and never sends mail on, so it is never an open relay.
- Mail for a route is stored encrypted until the app accepts it. Core cannot read it; only the signer opens it, for the delivery role to post.
- Tracking links are signed with the email id and the address they lead to, so a tracking host only redirects to addresses that were in an email.
- Bulk mail is held at a 0.3% complaint rate or 5% hard bounces.
- Bulk mail from an API key is held when it sends ten times its normal hourly volume, as a leaked key would.

## Supply chain

The only runtime dependency is Bun itself. Releases are built in GitHub Actions (actions pinned by commit) and ship with checksums, Sigstore signatures, SBOMs and build provenance (see [verify.md](verify.md)).
