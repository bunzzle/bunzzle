# Develop

Requires [Bun](https://bun.sh) 1.4+ and [Biome](https://biomejs.dev) (`brew install biome`).

```sh
bun install
bun run dev
bun run check
bun run build
```

`dev` starts the server and reloads on save, `check` runs the type check, the linter and the tests, and `build` makes a single binary at `dist/bunzzle`. After changing the API, `bun run openapi` writes `openapi.json` and the SDK again; a test fails while they are out of date.

Tests include fuzzing of every parser that reads outside input (`test/fuzz`, more iterations with `BUNZZLE_FUZZ_ITERATIONS`) and an end-to-end check for any installed server (`test/system/e2e.ts`).

## Run locally

Keep the master key somewhere safe, outside the database.

```sh
export BUNZZLE_MASTER_KEY=$(./dist/bunzzle master-key)
./dist/bunzzle serve
curl localhost:3000/health
```

Configuration is read from environment variables. Every setting is listed in [configuration.md](configuration.md).

One server can hold several projects, each with its own keys, domains and data: see [projects.md](projects.md).
