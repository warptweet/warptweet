.PHONY: bench build check check-go fmt-check script-check gosec site-build site-check site-down site-preview site-up test test-enrollment-control-plane test-openssh-integration test-race vet interop interop-help linux-rc

GOCACHE ?= /private/tmp/warptweet-go-build
SITE_DEV_HOST ?= 127.0.0.1
SITE_DEV_PORT ?= 4321
ifeq ($(shell uname -s),Darwin)
export MACOSX_DEPLOYMENT_TARGET ?= 13.0
export CGO_CFLAGS += -mmacosx-version-min=$(MACOSX_DEPLOYMENT_TARGET)
export CGO_LDFLAGS += -mmacosx-version-min=$(MACOSX_DEPLOYMENT_TARGET)
endif

# Dual-host local-dev interop: zero args. Configure via repo-root .env (see .env.example).
# Auto-builds missing artifacts/*.deb + *.pkg (OpenSSH stages cached). Partial evidence fails.

build:
	mkdir -p bin
	CGO_ENABLED=1 GOCACHE=$(GOCACHE) go build -trimpath -buildvcs=false -ldflags="-buildid=" -o bin/warptweet ./cmd/warptweet
	CGO_ENABLED=1 GOCACHE=$(GOCACHE) go build -trimpath -buildvcs=false -ldflags="-buildid=" -o bin/warptweet-provisioner ./cmd/warptweet-provisioner

fmt-check:
	@test -z "$$(gofmt -l $$(find cmd internal tests -name '*.go' -type f -print))"

vet:
	GOCACHE=$(GOCACHE) go vet ./...

script-check:
	./scripts/check-shell.sh

gosec:
	./scripts/check-gosec.sh

test:
	GOCACHE=$(GOCACHE) go test ./...

bench:
	./scripts/run-bench.sh

test-enrollment-control-plane:
	./scripts/test-enrollment-control-plane.sh

interop-help:
	@printf 'make interop  — zero-arg dual-host happy path (loads .env)\n'
	@printf '  copy .env.example → .env and set SERVER_HOST + SSH_IDENTITY\n'
	@printf '  missing packages are built automatically (client local, server Docker)\n'
	@printf '  unlock key: ssh-add $$WARPTWEET_INTEROP_SSH_IDENTITY\n\n'
	./scripts/interop/orchestrate.sh --help

# Complete local+remote round trip from .env (no make arguments).
interop:
	./scripts/interop/dev-run.sh

# Signed Linux host RC on the persistent Ubuntu builder.
# Host, SSH identity, and GPG key come from .env. VERSION must match command.Version.
linux-rc:
	@test -n "$(VERSION)" || { echo "usage: make linux-rc VERSION=0.1.0-rc.8" >&2; exit 64; }
	WARPTWEET_VERSION=$(VERSION) ./scripts/build-linux-rc-remote.sh

test-race:
	GOCACHE=$(GOCACHE) go test -race ./...

test-openssh-integration:
	@if [ -z "$(WARPTWEET_OPENSSH_PREFIX)" ]; then echo "WARPTWEET_OPENSSH_PREFIX is required" >&2; exit 64; fi
	GOCACHE=$(GOCACHE) go test -count=1 -v ./tests/integration

site-check:
	pnpm run verify

# Instant local website: Astro dev server (hot reload). Stop with Ctrl+C.
site-up:
	@command -v pnpm >/dev/null 2>&1 || { echo "pnpm is required (corepack prepare pnpm@10.15.1 --activate)" >&2; exit 69; }
	@test -d node_modules || pnpm install --frozen-lockfile --ignore-scripts
	@printf '\n  WarpTweet site  http://%s:%s/\n\n' "$(SITE_DEV_HOST)" "$(SITE_DEV_PORT)"
	pnpm exec astro dev --host "$(SITE_DEV_HOST)" --port "$(SITE_DEV_PORT)"

# No-op for dev-server workflow; use Ctrl+C on site-up.
site-down:
	@printf 'Dev server is foreground-only. Stop site-up with Ctrl+C.\n'
	@printf 'For the production-like container: make site-preview-down\n'

# Optional production-like container (CI parity), not the default edit loop.
site-preview:
	docker compose up --build --detach --wait website
	@printf 'WarpTweet preview: http://127.0.0.1:%s/\n' "$${WARPTWEET_SITE_PORT:-4322}"
	@printf 'Health check:      http://127.0.0.1:%s/healthz\n' "$${WARPTWEET_SITE_PORT:-4322}"

site-preview-down:
	docker compose down --remove-orphans

site-build:
	docker compose config --quiet
	docker compose build website

check-go: fmt-check script-check vet test test-enrollment-control-plane

check: check-go site-check
