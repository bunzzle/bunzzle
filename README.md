<p align="center"><img src="assets/logo/bunzzle.svg" width="140" alt="Bunzzle"></p>

# Bunzzle

Self-hosted email delivery engine for apps. Delivers straight to your recipients' mail servers. Bun-native, one binary, one SQLite file.

> Status: v0.2.0. Test it on a throwaway domain before sending real mail.

## Features

- Delivers over SMTP to every receiver itself, with an optional relay for some or all mail.
- HTTP API (`POST /emails`) and SMTP submission on 587 or 465.
- Webhooks signed in the Standard Webhooks format.
- DKIM signing with automatic key rotation, optionally with keys in an external key store.
- A sending speed per destination that follows its replies, and automatic IP warm-up.
- Bounces, complaints and unsubscribes suppressed automatically.
- Inbound routes: mail for an address posted to your app.
- Hooks to check, scan or filter email before it is queued.
- Several projects on one server, each with its own keys, domains and data.
- Metrics (`GET /metrics`) and OpenTelemetry export.

It does not host mailboxes (no IMAP) and has no campaign editor.

## Install

On a Linux server with systemd, outbound port 25 open and a static IP whose reverse DNS (PTR) you can set:

```sh
curl -fsSLO https://github.com/bunzzle/bunzzle/releases/latest/download/install.sh
sudo sh install.sh
```

Docker and the details: [Install](https://bunzzle.com/docs/install/).

## Quickstart

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

## Docs

- [Quickstart](https://bunzzle.com/docs/quickstart/), [Install](https://bunzzle.com/docs/install/), [API](https://bunzzle.com/docs/api/)
- [Deliverability](https://bunzzle.com/docs/deliverability/), [Templates](https://bunzzle.com/docs/templates/), [Open and click tracking](https://bunzzle.com/docs/tracking/), [Test mode](https://bunzzle.com/docs/test-mode/), [SMTP submission](https://bunzzle.com/docs/smtp/)
- [Hooks](https://bunzzle.com/docs/hooks/), [Inbound routes](https://bunzzle.com/docs/inbound-routes/), [Monitoring](https://bunzzle.com/docs/monitoring/)
- [Security design](https://bunzzle.com/docs/security/), [Verify a release](https://bunzzle.com/docs/verify/), [Reporting a vulnerability](SECURITY.md)
- [All settings](docs/configuration.md), [Projects](docs/projects.md), [Develop](docs/develop.md)

## License

[AGPL-3.0](LICENSE). The SDK in [sdk/typescript](sdk/typescript) is [MIT](sdk/typescript/LICENSE).
