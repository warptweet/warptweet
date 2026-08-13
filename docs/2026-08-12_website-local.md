# Local website

WarpTweet's public landing page is a static Astro build served by an unprivileged Caddy container. Node.js is a build tool for Astro only. It is not part of WarpTweet's Go/OpenSSH product or the website runtime.

The site has no browser JavaScript, remote fonts, analytics, forms, cookies, or external runtime requests.

## Run

```sh
docker compose up --build --detach --wait website
```

Open `http://127.0.0.1:4322`. Set `WARPTWEET_SITE_PORT` before starting Compose to choose a different loopback port. Port 4321 remains available for Astro's developer server.

Check the container and endpoint:

```sh
docker compose ps
curl -fsS http://127.0.0.1:4322/healthz
```

Stop the local site:

```sh
docker compose down --remove-orphans
```

## Verify source

```sh
corepack enable
corepack prepare pnpm@10.15.1 --activate
pnpm install --frozen-lockfile --ignore-scripts
pnpm run verify
docker compose config --quiet
```

The container is loopback-only, read-only, capability-free, and runs as the dedicated `warptweet-site` identity. Caddy's administration endpoint and automatic HTTPS are disabled for this local HTTP service, and the build context is allowlisted to the website sources and configuration.
