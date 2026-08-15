# Local website

WarpTweet's public landing page is a static Astro site. Node.js and pnpm are
build/dev tools only. They are not part of the Go/OpenSSH product runtime.

The production image is still an unprivileged Caddy container. Day-to-day
editing uses the Astro dev server.

The site has no remote fonts, analytics, forms, cookies, or external runtime
requests. Typography is self-hosted IBM Plex Sans (variable) and IBM Plex Mono
via fontsource packages bundled at build time. The install panel may include a
small copy-button script only when the Homebrew CTA is enabled.

## Develop (default)

```sh
corepack enable
corepack prepare pnpm@10.15.1 --activate
pnpm install --frozen-lockfile --ignore-scripts
make site-up
```

Opens the hot-reload server at `http://127.0.0.1:4321/`. Stop with Ctrl+C.

Override host/port if needed:

```sh
make site-up SITE_DEV_PORT=4330
```

Or:

```sh
pnpm dev
```

## Verify source

```sh
pnpm run verify
```

## Production-like container (optional)

CI and hardened runtime checks still use Compose:

```sh
make site-preview
curl -fsS "http://127.0.0.1:${WARPTWEET_SITE_PORT:-4322}/healthz"
make site-preview-down
```

Set `WARPTWEET_SITE_PORT` before `site-preview` to change the published loopback
port (default `4322`). The container is loopback-only, read-only, capability-free,
and runs as the dedicated `warptweet-site` identity.
