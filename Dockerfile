FROM oven/bun:1.4.3@sha256:ec06c3b6cea04192ae6770c434f668ca41d343ad19fa6472216c7b48be39c598 AS build
WORKDIR /src
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile --production
COPY tsconfig.json ./
COPY src ./src
RUN bun build src/cli/main.ts --compile --minify --sourcemap --outfile dist/bunzzle && ./dist/bunzzle --version

FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
RUN groupadd --system --gid 10001 bunzzle \
 && useradd --system --uid 10001 --gid bunzzle --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin bunzzle \
 && mkdir -p /var/lib/bunzzle/data /var/lib/bunzzle/keys /run/bunzzle \
 && chown -R 10001:10001 /var/lib/bunzzle /run/bunzzle \
 && chmod 0700 /var/lib/bunzzle/data /var/lib/bunzzle/keys
COPY --from=build /src/dist/bunzzle /usr/local/bin/bunzzle
ENV BUNZZLE_HOST=0.0.0.0 \
    BUNZZLE_PORT=3000 \
    BUNZZLE_INBOUND_PORT=2525 \
    BUNZZLE_DATA_DIR=/var/lib/bunzzle/data \
    BUNZZLE_KEYS_DIR=/var/lib/bunzzle/keys \
    BUNZZLE_RUN_DIR=/run/bunzzle
USER 10001:10001
VOLUME ["/var/lib/bunzzle"]
EXPOSE 3000 2525
ENTRYPOINT ["/usr/local/bin/bunzzle"]
CMD ["serve"]
