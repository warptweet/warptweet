# Release paths

The OpenSSH fetch and build scripts treat every caller path as untrusted input.

## Invariants

- Inputs must be clean absolute paths using the allow-listed ASCII path characters. Final basenames must begin with an alphanumeric character and contain only letters, digits, `.`, `_`, or `-`.
- The immediate parent must already exist. Each script resolves it to a physical path, rejects an unsafe resolved path, and records its device and inode identity.
- A fetch destination or build stage must not exist when the script starts or when publication begins.
- Work occurs under a mode `0700`, randomly named sibling directory created by `mktemp`. Downloads, source extraction, compilation, testing, installation, receipts, and hashes complete there.
- The build hashes and extracts only its private archive copy. It checks the caller archive and source-parent identities before and after that copy.
- Publication uses no-clobber move behavior. GNU systems use `mv -nT`; macOS uses `mv -hn`. The scripts verify afterward that the private publication directory was consumed and that the published device and inode identity is the expected one.
- Cleanup recursively removes only the randomly named private root after confirming both its identity and the parent identity. It never recursively removes the caller-supplied destination or stage path.
- Any identity change, unexpected target, failed move, or publication mismatch fails closed. An unexpected final target remains untouched for operator inspection.

Use a dedicated parent directory that is not writable by untrusted users. Path validation and identity checks do not turn an untrusted shared parent into a trusted publication boundary.

## Portable-shell residual

POSIX shell does not expose a retained directory descriptor plus an atomic no-replace directory rename. These scripts therefore have a narrow check-to-operation interval around path-based `stat`, `mv`, and `rm` calls. A process with the same credentials, or a privileged process, can still race those operations.

On macOS, `mv -h` prevents following a destination symlink and `mv -n` requests no replacement. If a real directory appears in the final interval, BSD `mv` can place the private publication directory inside it. The post-move identity check detects this and the script fails, but it deliberately does not recurse into the unexpected target to reclaim the nested directory. This can leave authenticated source or staged files for operator recovery.

Eliminating that residual requires a small native publication helper that opens and validates the parent directory and invokes the platform no-replace primitive, such as Linux `renameat2` with `RENAME_NOREPLACE` or macOS `renameatx_np` with `RENAME_EXCL`. Until then, release automation must use dedicated, access-controlled parents.
