# Security design

How Bunzzle limits what an attacker gets. To report a vulnerability, see [SECURITY.md](../SECURITY.md).

## Five roles

| Role | Holds | Talks to | Outside input |
|---|---|---|---|
| api | nothing secret | core | HTTP requests |
| core | the database (bodies encrypted) | signer, delivery | none |
| delivery | one email at a time while sending | signer | DNS answers, SMTP replies, HTTPS (webhooks, MTA-STS, Cloudflare) |
| signer | DKIM keys, master key | nobody | none |
| inbound | its TLS key, if STARTTLS is on | core | SMTP from the internet |

- Roles exchange small JSON messages over Unix sockets; every message is validated on arrival.
- The roles that read outside input hold nothing worth stealing (at most the inbound TLS key) and can't open the database.
- Only `core` opens the database, and `core` has no network. To reach stored data, an attacker has to break two roles.
- A broken `delivery` or `core` can still ask the signer for signatures, but can never read a key. Key rotation and the volume guards limit the rest.

With the systemd units or the five-container compose file, each role is a separate user in its own sandbox (see [install.md](install.md)). With `bunzzle serve` (one container, or a laptop) the roles are separate processes of one user: the boundaries in the code still hold, but the OS doesn't enforce them.

## Data

- **Master key** outside the database: a file or a systemd credential, given only to the signer.
- **DKIM keys** are encrypted with the master key; only the signer decrypts them.
- **Every email body** is encrypted with its own key, wrapped for the signer. `core` can encrypt bodies but can't decrypt them. When retention ends (30 days by default), the key is destroyed and the body is unreadable everywhere, backups included.
- **API keys** are stored as SHA-256 hashes and shown once.
- **Webhook secrets** are derived from the master key in the signer and never stored.
- **Logs** never contain bodies.
- **Cloudflare API token** (optional, for publishing DNS records and rotating DKIM keys without manual steps) is held by `delivery`, the only role with outbound network. Someone who takes over `delivery` can use it to change the records of the zones it covers. Create it with only `Zone.DNS: Edit`, limited to the zones Bunzzle sends for. Without a token, Bunzzle prints the records and waits for you to publish them; rotation then pauses at that step and keeps signing with the current keys.

## Outside input

Every parser has limits:
- HTTP bodies: size cap.
- SMTP replies: line and reply length caps.
- DNS: name length, pointer loops.
- Inbound mail: 1 MB, 10 recipients, 500 headers, 50 parts, depth 5.
- IPC frames: size cap.

Every one of these is fuzzed (`test/fuzz`): a few thousand inputs per target in every test run, 200,000 per target nightly in CI. Reproduce a failure with `BUNZZLE_FUZZ_SEED=<seed> bun test test/fuzz`.

## Network

One private-network filter covers SMTP, webhooks, MTA-STS and Cloudflare requests. Delivery resolves names itself and connects to the vetted IP, while TLS still checks the name. This stops DNS rebinding. Redirects are never followed.

## Abuse

- Only verified domains can send.
- Inbound accepts only signed bounce and unsubscribe addresses, so it is never an open relay.
- Bulk mail is held at a 0.3% complaint rate or 5% hard bounces.
- Bulk mail from an API key is held when it sends ten times its normal hourly volume, as a leaked key would.

## Supply chain

The only runtime dependency is Bun itself. Releases are built in GitHub Actions (actions pinned by commit) and ship with checksums, Sigstore signatures, SBOMs and build provenance (see [verify.md](verify.md)).
