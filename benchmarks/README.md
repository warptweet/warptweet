# Benchmarks

`make bench` writes one result folder per run.

Name shape:

- offcycle: `YYYY-MM-DDTHHMMSSZ-offcycle-<run-id>`
- release: `YYYY-MM-DDTHHMMSSZ-release-<version>-<run-id>`

Release means HEAD is tagged exactly `v<command.Version>` or `<command.Version>`. The trailing `run-id` is eight hex bytes so two runs in the same UTC second do not collide.

Each folder has:

- `meta.json` machine identity (version, profile, commit, dirty, Go, CPU)
- `results.json` parsed medians and raw samples
- `summary.txt` headline numbers
- `go-test-bench.txt` raw `go test -bench` output

Headline numbers are handshake, 1-byte RTT, 1KiB and 64KiB tunnel forward versus raw TCP, hybrid KEX, and composite sign/verify. Keep these folders in git.
