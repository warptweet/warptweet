#!/bin/sh
set -eu
LC_ALL=C
export LC_ALL

WT_SCRIPT_DIRECTORY=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
WT_REPOSITORY_ROOT=$(CDPATH= cd -- "$WT_SCRIPT_DIRECTORY/.." && pwd)
GOSEC_VERSION=v2.28.0
WT_CACHE="$WT_REPOSITORY_ROOT/.cache/gosec/$GOSEC_VERSION"
mkdir -p "$WT_CACHE"
GOBIN="$WT_CACHE" go install "github.com/securego/gosec/v2/cmd/gosec@${GOSEC_VERSION}"
CDPATH= cd -- "$WT_REPOSITORY_ROOT"
exec "$WT_CACHE/gosec" -quiet ./...
