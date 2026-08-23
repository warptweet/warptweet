#!/bin/bash
# Run profile benches and write a dated result folder under benchmarks/.
set -euo pipefail

WT_REPOSITORY_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$WT_REPOSITORY_ROOT"

WT_STAMP=$(date -u +%Y-%m-%dT%H%M%SZ)
WT_RUN_ID=$(dd if=/dev/urandom bs=4 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n')
if [ ${#WT_RUN_ID} -lt 8 ]; then
	WT_RUN_ID=$(printf '%08x' "$$")
fi

WT_VERSION=$(sed -n 's/^[[:space:]]*Version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' internal/command/command.go | head -n 1)
WT_PROFILE=$(sed -n 's/^[[:space:]]*CurrentID = "\(.*\)"/\1/p' internal/profile/profile.go | head -n 1)
if [ -z "$WT_VERSION" ] || [ -z "$WT_PROFILE" ]; then
	echo "run-bench: cannot read version or profile id" >&2
	exit 1
fi

WT_COMMIT=$(git rev-parse HEAD)
WT_COMMIT_SHORT=$(git rev-parse --short HEAD)
WT_KIND=offcycle
WT_TAG=
if WT_TAG=$(git describe --tags --exact-match HEAD 2>/dev/null); then
	case "$WT_TAG" in
		"v$WT_VERSION" | "$WT_VERSION")
			if [ -z "$(git status --porcelain)" ]; then
				WT_KIND=release
			fi
			;;
	esac
fi

if [ "$WT_KIND" = release ]; then
	WT_DIR_NAME="${WT_STAMP}-release-${WT_VERSION}-${WT_RUN_ID}"
else
	WT_DIR_NAME="${WT_STAMP}-offcycle-${WT_RUN_ID}"
fi

WT_OUT="$WT_REPOSITORY_ROOT/benchmarks/$WT_DIR_NAME"
mkdir -p "$WT_OUT"

WT_GOOS=$(go env GOOS)
WT_GOARCH=$(go env GOARCH)
WT_GOVER=$(go env GOVERSION)
WT_NCPU=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 0)

{
	printf '{\n'
	printf '  "version": "%s",\n' "$WT_VERSION"
	printf '  "profile_id": "%s",\n' "$WT_PROFILE"
	printf '  "kind": "%s",\n' "$WT_KIND"
	printf '  "utc": "%s",\n' "$WT_STAMP"
	printf '  "run_id": "%s",\n' "$WT_RUN_ID"
	printf '  "git_commit": "%s",\n' "$WT_COMMIT"
	printf '  "git_commit_short": "%s",\n' "$WT_COMMIT_SHORT"
	printf '  "git_tag": "%s",\n' "$WT_TAG"
	printf '  "dirty": %s,\n' "$(git status --porcelain | awk 'END{print (NR>0)?"true":"false"}')"
	printf '  "goos": "%s",\n' "$WT_GOOS"
	printf '  "goarch": "%s",\n' "$WT_GOARCH"
	printf '  "go_version": "%s",\n' "$WT_GOVER"
	printf '  "ncpu": %s\n' "$WT_NCPU"
	printf '}\n'
} >"$WT_OUT/meta.json"

echo "run-bench: writing $WT_OUT"
GOCACHE=${GOCACHE:-/private/tmp/warptweet-go-build} \
	go test ./internal/dataplane ./internal/composite \
	-run '^$' \
	-bench . \
	-benchmem \
	-count 3 \
	-timeout 30m \
	| tee "$WT_OUT/go-test-bench.txt"

python3 - "$WT_OUT" <<'PY'
import json, re, statistics, sys
from pathlib import Path

out = Path(sys.argv[1])
meta = json.loads((out / "meta.json").read_text())
line_re = re.compile(
    r"^(Benchmark\S+)\s+(\d+)\s+([0-9.]+)\s+ns/op"
    r"(?:\s+([0-9.]+)\s+MB/s)?"
    r"(?:\s+(\d+)\s+B/op)?"
    r"(?:\s+(\d+)\s+allocs/op)?"
)
samples = {}
for line in (out / "go-test-bench.txt").read_text().splitlines():
    m = line_re.match(line)
    if not m:
        continue
    name = m.group(1).rsplit("-", 1)[0]
    rec = {
        "iterations": int(m.group(2)),
        "ns_per_op": float(m.group(3)),
        "mb_per_s": float(m.group(4)) if m.group(4) else None,
        "b_per_op": int(m.group(5)) if m.group(5) else None,
        "allocs_per_op": int(m.group(6)) if m.group(6) else None,
    }
    samples.setdefault(name, []).append(rec)

def median(values):
    return statistics.median(values) if values else None

benches = []
for name, rows in samples.items():
    ns = [r["ns_per_op"] for r in rows]
    mb = [r["mb_per_s"] for r in rows if r["mb_per_s"] is not None]
    entry = {
        "name": name,
        "runs": len(rows),
        "median_ns_per_op": median(ns),
        "median_ms_per_op": None if not ns else median(ns) / 1e6,
        "median_mb_per_s": median(mb),
        "samples": rows,
    }
    benches.append(entry)

results = {"meta": meta, "benchmarks": benches}
(out / "results.json").write_text(json.dumps(results, indent=2) + "\n")

headline = [
    ("handshake_ms", "BenchmarkLoopbackHandshake"),
    ("rtt_us", "BenchmarkLoopbackRTT"),
    ("forward_1kib_mb_s", "BenchmarkLoopbackForward1KiB"),
    ("forward_64kib_mb_s", "BenchmarkLoopbackForward64KiB"),
    ("raw_tcp_64kib_mb_s", "BenchmarkRawTCPForward64KiB"),
    ("hybrid_kex_us", "BenchmarkHybridKEX"),
    ("composite_sign_us", "BenchmarkCompositeSign"),
    ("composite_verify_us", "BenchmarkCompositeVerify"),
]
by_name = {b["name"]: b for b in benches}
lines = [
    "WarpTweet bench",
    f"version   {meta['version']}",
    f"profile   {meta['profile_id']}",
    f"kind      {meta['kind']}",
    f"utc       {meta['utc']}",
    f"run_id    {meta['run_id']}",
    f"commit    {meta['git_commit'][:12]}",
    f"go        {meta['go_version']} {meta['goos']}/{meta['goarch']}",
    "",
    "headline (median of 3)",
]
for label, name in headline:
    row = by_name.get(name)
    if not row:
        lines.append(f"  {label:24} (missing)")
        continue
    if label.endswith("_mb_s"):
        value = row["median_mb_per_s"]
        lines.append(f"  {label:24} {value:.2f}" if value is not None else f"  {label:24} n/a")
    elif label.endswith("_ms"):
        lines.append(f"  {label:24} {row['median_ms_per_op']:.3f}")
    else:
        lines.append(f"  {label:24} {row['median_ns_per_op'] / 1000:.1f}")
lines.append("")
(out / "summary.txt").write_text("\n".join(lines) + "\n")
print((out / "summary.txt").read_text(), end="")
PY

echo "run-bench: done $WT_OUT"
