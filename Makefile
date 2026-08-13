.PHONY: build check check-go fmt-check script-check site-build site-check site-down site-up test test-openssh-integration test-race vet

GOCACHE ?= /private/tmp/warptweet-go-build

build:
	mkdir -p bin
	GOCACHE=$(GOCACHE) go build -trimpath -o bin/warptweet ./cmd/warptweet

fmt-check:
	@test -z "$$(gofmt -l $$(find cmd internal tests -name '*.go' -type f -print))"

vet:
	GOCACHE=$(GOCACHE) go vet ./...

script-check:
	@for script in scripts/*.sh; do sh -n "$$script"; done

test:
	GOCACHE=$(GOCACHE) go test ./...

test-race:
	GOCACHE=$(GOCACHE) go test -race ./...

test-openssh-integration:
	@if [ -z "$(WARPTWEET_OPENSSH_PREFIX)" ]; then echo "WARPTWEET_OPENSSH_PREFIX is required" >&2; exit 64; fi
	GOCACHE=$(GOCACHE) go test -count=1 -v ./tests/integration

site-check:
	pnpm run verify

site-build:
	docker compose config --quiet
	docker compose build website

site-up:
	docker compose up --build --detach --wait website
	@printf 'WarpTweet site: http://127.0.0.1:%s/\n' "$${WARPTWEET_SITE_PORT:-4322}"
	@printf 'Health check:   http://127.0.0.1:%s/healthz\n' "$${WARPTWEET_SITE_PORT:-4322}"

site-down:
	docker compose down --remove-orphans

check-go: fmt-check script-check vet test

check: check-go site-check
