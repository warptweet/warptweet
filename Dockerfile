# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
FROM golang:1.26.5-alpine3.23@sha256:622e56dbc11a8cfe87cafa2331e9a201877271cbff918af53d3be315f3da88cc AS release-verifier
WORKDIR /source
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked \
    go mod download && \
    go mod verify
COPY cmd/verify-public-release ./cmd/verify-public-release
COPY internal/adoptionresult ./internal/adoptionresult
COPY internal/locator ./internal/locator
COPY internal/publicrelease ./internal/publicrelease
COPY internal/releaseevidence ./internal/releaseevidence
COPY internal/strictjson ./internal/strictjson
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" \
    -o /out/verify-public-release ./cmd/verify-public-release

FROM node:24.19.0-alpine3.23@sha256:244cc2b53f46f9e876304391d17682b0ddae9ac33491f4857e25e35a36ba7995 AS build
ENV ASTRO_TELEMETRY_DISABLED=1 \
    COREPACK_ENABLE_DOWNLOAD_PROMPT=0 \
    WARPTWEET_PUBLIC_RELEASE_VERIFIER=/usr/local/bin/verify-public-release
WORKDIR /site
COPY --from=release-verifier /out/verify-public-release /usr/local/bin/verify-public-release
COPY package.json pnpm-lock.yaml .npmrc ./
RUN --mount=type=cache,target=/root/.local/share/pnpm/store,sharing=locked \
    corepack enable && \
    corepack prepare pnpm@10.15.1 --activate && \
    test "$(pnpm --version)" = 10.15.1 && \
    pnpm install --frozen-lockfile --ignore-scripts
COPY astro.config.mjs tsconfig.json Caddyfile ./
COPY packaging/evidence ./packaging/evidence
COPY public ./public
COPY schemas ./schemas
COPY src ./src
RUN pnpm run verify

FROM caddy:2.11.4-alpine@sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648 AS runtime
ENV HOME=/tmp \
    XDG_CONFIG_HOME=/tmp/caddy-config \
    XDG_DATA_HOME=/tmp/caddy-data
COPY Caddyfile /etc/caddy/Caddyfile
COPY --from=build --chown=0:0 /site/dist/ /var/www/warptweet/
RUN addgroup -g 10001 -S warptweet-site && \
    adduser -u 10001 -S -D -H -h /tmp -s /sbin/nologin -G warptweet-site warptweet-site && \
    setcap -r /usr/bin/caddy && \
    test -z "$(getcap /usr/bin/caddy)" && \
    caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
USER 10001:10001
EXPOSE 8080
STOPSIGNAL SIGTERM
CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
