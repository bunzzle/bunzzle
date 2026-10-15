# Bunzzle

Self-hosted email delivery engine for apps. Delivers straight to your recipients' mail servers. Bun-native, one binary, one SQLite file.

> Status: early development (milestone M3). Not usable in production yet.

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
./dist/bunzzle serve
curl localhost:3000/health
```

Configuration is read from environment variables. See `.env.example`.

## Send one email

```sh
./dist/bunzzle dkim keygen --domain your.domain --out dkim.json   # prints the DNS records to add
./dist/bunzzle send --from "You <hello@your.domain>" --to someone@example.com \
  --subject "Hello" --text "Sent by Bunzzle" --dkim-keys dkim.json --ehlo mail.your.domain
```

The sending server needs outbound port 25 and a reverse DNS (PTR) record matching `--ehlo`.

## License

The server is licensed under [AGPL-3.0](LICENSE). SDKs will be MIT.
