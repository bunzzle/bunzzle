# Bunzzle

Self-hosted email sending on your own Amazon SES. Bun-native, one binary, one SQLite file.

> Status: early development (milestone M1). Not usable yet.

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

## License

The server is licensed under [AGPL-3.0](LICENSE). SDKs will be MIT.
