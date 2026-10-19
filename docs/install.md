# Install

Bunzzle runs on any Linux server with systemd, or in Docker. For real sending the server needs outbound port 25, a static IP and a reverse DNS (PTR) record you control.

## Linux with systemd (recommended)

```sh
curl -fsSLO https://github.com/bunzzle/bunzzle/releases/latest/download/install.sh
sudo sh install.sh
```

`install.sh` downloads the binary and the deploy files for your architecture, checks them against `SHA256SUMS`, and then:

- creates five users (`bunzzle-signer`, `-core`, `-delivery`, `-api`, `-inbound`), one per role;
- installs a hardened systemd unit per role and `bunzzle.target` to start and stop them together;
- writes `/etc/bunzzle/bunzzle.env` (settings) and `/etc/bunzzle/master.key` (secret, root only) if they don't exist yet;
- starts everything and fails loudly if any role isn't running.

To verify the signature yourself before installing, see [verify.md](verify.md). To install a specific version: `sudo BUNZZLE_VERSION=v0.1.0 sh install.sh`. From a checkout: `sudo ./deploy/install.sh path/to/bunzzle`.

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

Admin commands talk to the running server through `/run/bunzzle/core.sock`, so run them as root.

Logs: `journalctl -u 'bunzzle-*' -f`. Status: `systemctl status 'bunzzle-*'`.

### Optional secrets

Secrets are passed as systemd credentials, readable only by the role that needs them. To let Bunzzle publish its DNS records on Cloudflare, create an API token with only `Zone.DNS: Edit`, limited to the zones you send from (see [security.md](security.md) for why):

```sh
sudo install -m 0600 /dev/stdin /etc/bunzzle/cloudflare-token <<< "your-token"
sudo systemctl edit bunzzle-delivery
```
```ini
[Service]
LoadCredential=cloudflare-token:/etc/bunzzle/cloudflare-token
Environment=BUNZZLE_CLOUDFLARE_API_TOKEN_FILE=%d/cloudflare-token
```

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

### What the sandbox does

| Role | User | Network | Can write |
|---|---|---|---|
| signer | bunzzle-signer | none | `/var/lib/bunzzle/keys` |
| core | bunzzle-core | none | `/var/lib/bunzzle/data` |
| delivery | bunzzle-delivery | outbound (25, 53, 443 with the filter) | nothing |
| api | bunzzle-api | listen on its port | nothing |
| inbound | bunzzle-inbound | listen on 25 | nothing |

Sockets between roles are restricted by group: `api` and `inbound` can reach only `core`, `delivery` only `signer`, `core` reaches `signer` and `delivery`. `systemd-analyze security` rates signer and core 0.4 (SAFE), the others 1.3–1.4 (OK). The remaining points are the network access these roles need and Bun's JIT, which needs writable executable memory (so no `MemoryDenyWriteExecute`).

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

Create the key file first with `docker run --rm ghcr.io/bunzzle/bunzzle master-key > master.key` and make it readable by uid 10001. The five roles run as processes of one user (uid 10001) inside the container. For separate users, use compose.

## Docker compose, five containers

`deploy/compose.yaml` runs each role in its own container with its own uid; `signer` and `core` have no network at all. In the `deploy` directory:

```sh
docker run --rm ghcr.io/bunzzle/bunzzle master-key > master.key
: > cloudflare-token
sudo chown 10011 master.key && sudo chmod 0400 master.key
docker compose up -d --wait
docker compose exec api bunzzle keys create --name my-app --scope full
```

Settings go in `deploy/bunzzle.env`. `delivery` uses the host network, so mail leaves from your server's own IPs.

## Upgrade

Run `install.sh` again (or pull the new image). The database migrates itself on start.
