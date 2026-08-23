#!/bin/sh
set -eu
LC_ALL=C
export LC_ALL

# Fail if any Mach-O requires a newer macOS than the cask floor (Ventura 13.0).

WT_MAX_MINOS=${WARPTWEET_MACOS_DEPLOYMENT_TARGET:-13.0}

usage() {
    echo "usage: $0 FILE..." >&2
    exit 64
}

if [ "$#" -lt 1 ]; then
    usage
fi

version_num() {
    printf '%s\n' "$1" | awk -F. '{
        printf "%d\n", ($1 + 0) * 10000 + ($2 + 0) * 100 + ($3 + 0)
    }'
}

WT_LIMIT=$(version_num "$WT_MAX_MINOS")
WT_FAILED=0
for WT_FILE in "$@"; do
    if [ ! -f "$WT_FILE" ] || [ -L "$WT_FILE" ]; then
        echo "not a regular file: $WT_FILE" >&2
        WT_FAILED=1
        continue
    fi
    WT_HIGHEST=0
    WT_HIGHEST_TEXT=
    while IFS= read -r WT_MINOS; do
        [ -n "$WT_MINOS" ] || continue
        WT_NUM=$(version_num "$WT_MINOS")
        if [ "$WT_NUM" -gt "$WT_HIGHEST" ]; then
            WT_HIGHEST=$WT_NUM
            WT_HIGHEST_TEXT=$WT_MINOS
        fi
    done <<EOF
$(otool -l "$WT_FILE" | awk '/minos/{ print $2 }')
EOF
    if [ -z "$WT_HIGHEST_TEXT" ]; then
        echo "no LC_BUILD_VERSION minos in $WT_FILE" >&2
        WT_FAILED=1
        continue
    fi
    if [ "$WT_HIGHEST" -gt "$WT_LIMIT" ]; then
        echo "$WT_FILE minos $WT_HIGHEST_TEXT exceeds $WT_MAX_MINOS" >&2
        WT_FAILED=1
    fi
done
if [ "$WT_FAILED" -ne 0 ]; then
    exit 65
fi
