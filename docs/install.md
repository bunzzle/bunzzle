# Install

Bunzzle runs on any Linux server with systemd, or in Docker. For real sending the server needs outbound port 25, a static IP and a reverse DNS (PTR) record you control.

## Linux with systemd (recommended)

```sh
curl -fsSLO https://github.com/bunzzle/bunzzle/releases/latest/download/install.sh
sudo sh install.sh
```

`install.sh` downloads the binary and the deploy files for your architecture, checks them against `SHA256SUMS`, and then:

- creates a user per role (`bunzzle-signer`, `-core`, `-delivery`, `-dns`, `-link`, `-api`, `-inbound`);
- installs a hardened systemd unit per role and `bunzzle.target` to start and stop them together;
- writes `/etc/bunzzle/bunzzle.env` (settings) and `/etc/bunzzle/master.key` (secret, root only) if they don't exist yet;
- starts everything and fails loudly if any role isn't running.

To verify the signature yourself before installing, see [verify.md](verify.md). To install a specific version: `sudo BUNZZLE_VERSION=v0.2.0 sh install.sh`. From a checkout: `sudo ./deploy/install.sh path/to/bunzzle`.

Then:

1. **Back up `/etc/bunzzle/master.key`** somewhere safe. Without it, DKIM keys and queued email can't be read.
2. Edit `/etc/bunzzle/bunzzle.env`: `BUNZZLE_EHLO_NAME` (the PTR name of your IP), `BUNZZLE_SOURCE_IPS`, `BUNZZLE_PUBLIC_URL`. Then `sudo systemctl restart bunzzle.target`. All settings: [configuration.md](configuration.md).
3. Optional, recommended: the egress filter. Only `delivery` may open outbound connections, and only to ports 25, 53 and 443:
   ```sh
   sudo nft -f /etc/bunzzle/bunzzle.nft
   ```
4. Put the API behind your reverse proxy with TLS (it listens on `127.0.0.1:3000`).
5. Create a key and a domain:
   ```sh
   sudo bunzzle keys create --name my-app --scope full
   sudo bunzzle domains add your.domain
   sudo bunzzle doctor
   ```

Admin commands talk to the running server through `/run/bunzzle/admin.sock`, which only root and the core role can open, so run them as root.

Logs: `journalctl -u 'bunzzle-*' -f`. Status: `systemctl status 'bunzzle-*'`.

### Optional secrets

Secrets are passed as systemd credentials, readable only by the role that needs them. To let Bunzzle publish its DNS records on Cloudflare, create an API token with only `Zone.DNS: Edit`, limited to the zones you send from (see [security.md](security.md) for why):

```sh
sudo install -m 0600 /dev/stdin /etc/bunzzle/cloudflare-token <<< "your-token"
sudo systemctl edit bunzzle-dns
```
```ini
[Service]
LoadCredential=cloudflare-token:/etc/bunzzle/cloudflare-token
Environment=BUNZZLE_CLOUDFLARE_API_TOKEN_FILE=%d/cloudflare-token
```

Every other secret file works the same way, in the unit of the role that reads it: `bunzzle-dns` for `BUNZZLE_DNS_UPDATE_KEY_FILE`, `BUNZZLE_ROUTE53_SECRET_ACCESS_KEY_FILE`, `BUNZZLE_DESEC_TOKEN_FILE` and the two `BUNZZLE_POSTMASTER_*_FILE` settings, `bunzzle-delivery` for `BUNZZLE_RELAY_PASSWORD_FILE` and `BUNZZLE_SPAMHAUS_KEY_FILE`.

To offer STARTTLS on the inbound port, give the inbound role a certificate for `BUNZZLE_INBOUND_HOSTNAME` (for example from Let's Encrypt):

```sh
sudo systemctl edit bunzzle-inbound
```
```ini
[Service]
LoadCredential=inbound.pem:/etc/letsencrypt/live/mail.your.domain/fullchain.pem
LoadCredential=inbound.key:/etc/letsencrypt/live/mail.your.domain/privkey.pem
Environment=BUNZZLE_INBOUND_TLS_CERT_FILE=%d/inbound.pem
Environment=BUNZZLE_INBOUND_TLS_KEY_FILE=%d/inbound.key
```

The certificate is read at start, so restart the role after renewal, for example with certbot's `--deploy-hook "systemctl restart bunzzle-inbound"`. Senders that don't use TLS are still accepted.

### Systemd in a container

When systemd runs inside a container (seen with Docker), it may pass no `LoadCredential=` files to a service. The signer then stops with `systemd passed no credentials to this service`, and `install.sh` reports the roles as not running. Give the signer the master key through a runtime directory instead:

```sh
sudo mkdir -p /etc/systemd/system/bunzzle-signer.service.d
sudo tee /etc/systemd/system/bunzzle-signer.service.d/container.conf >/dev/null <<'EOF'
[Service]
LoadCredential=
RuntimeDirectory=bunzzle-signer-key
RuntimeDirectoryMode=0700
ExecStartPre=+/usr/bin/install -o bunzzle-signer -m 0400 /etc/bunzzle/master.key /run/bunzzle-signer-key/master.key
Environment=BUNZZLE_MASTER_KEY_FILE=/run/bunzzle-signer-key/master.key
EOF
sudo systemctl daemon-reload
sudo systemctl restart bunzzle.target
```

The key stays readable only by the signer, in memory under `/run`, and is removed when the signer stops.

### What the sandbox does

| Role | User | Network | Can write |
|---|---|---|---|
| signer | bunzzle-signer | none | `/var/lib/bunzzle/keys` |
| core | bunzzle-core | none | `/var/lib/bunzzle/data` |
| link | bunzzle-link | outbound to the IPs of delivery nodes and egresses only | nothing |
| delivery | bunzzle-delivery | outbound (25, 53, 443 with the filter) | nothing |
| api | bunzzle-api | listen on its port | nothing |
| inbound | bunzzle-inbound | listen on 25 | nothing |

Sockets between roles are restricted by group: `api` and `inbound` can reach only `core`, `delivery` only `signer`, `core` reaches `signer`, `delivery`, `dns` and `link`. `systemd-analyze security` rates signer and core 0.4 (SAFE), the others 1.3–1.4 (OK). The remaining points are the network access these roles need and Bun's JIT, which needs writable executable memory (so no `MemoryDenyWriteExecute`).

## Docker, one container

```sh
docker run -d --name bunzzle \
  -e BUNZZLE_MASTER_KEY_FILE=/run/secrets/master.key -v ./master.key:/run/secrets/master.key:ro \
  -e BUNZZLE_EHLO_NAME=mail.your.domain \
  -v bunzzle:/var/lib/bunzzle -p 127.0.0.1:3000:3000 -p 25:2525 \
  --read-only --tmpfs /run/bunzzle:uid=10001,gid=10001,mode=0750 \
  --cap-drop ALL --security-opt no-new-privileges:true \
  ghcr.io/bunzzle/bunzzle:latest
```

Create the key file first with `docker run --rm ghcr.io/bunzzle/bunzzle master-key > master.key` and make it readable by uid 10001. The roles run as processes of one user (uid 10001) inside the container. For separate users, use compose.

## Docker compose

`deploy/compose.yaml` runs each role in its own container with its own uid; `signer` and `core` have no network at all. In the `deploy` directory:

```sh
docker run --rm ghcr.io/bunzzle/bunzzle master-key > master.key
: > cloudflare-token
sudo chown 10011 master.key && sudo chmod 0400 master.key
docker compose up -d --wait
docker compose exec core bunzzle keys create --name my-app --scope full
```

Settings go in `deploy/bunzzle.env`. `delivery` uses the host network, so mail leaves from your server's own IPs.

## Upgrade

Run `install.sh` again (or pull the new image). The database migrates itself on start.

To keep sending during an upgrade, restart the roles one at a time instead of the whole target: `sudo systemctl restart bunzzle-signer bunzzle-dns bunzzle-link`, then `bunzzle-delivery`, `bunzzle-inbound`, `bunzzle-api` and `bunzzle-core` last, waiting for each to come back (`systemctl is-active`). Email that was being sent when a role stopped is checked and resent only if it did not go out; API calls during a restart get a 503 with `Retry-After: 1`.

## Backup and restore

`bunzzle backup --to DIR` writes a consistent copy of the database and the key files into an empty directory, with a `manifest.json` that lists every file and its SHA-256. It is safe to run while Bunzzle is running.

```sh
sudo bunzzle backup --to /var/backups/bunzzle/2026-10-19
```

The backup does not contain the master key, and everything secret in it is encrypted with that key. Keep the master key somewhere other than the backups: a backup without its master key cannot be read, and a master key without the backup is useless to anyone else.

To restore, stop Bunzzle, set the same master key and run:

```sh
sudo systemctl stop bunzzle
sudo bunzzle restore --from /var/backups/bunzzle/2026-10-19
sudo systemctl start bunzzle
```

`restore` checks every file against the manifest and refuses a different master key. The files it replaces are moved into `before-restore-<time>` in the data directory, not deleted.
