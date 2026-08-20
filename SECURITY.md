# Security policy

WarpTweet is implemented and reviewable security software. Its controller is present, but it has no supported end-to-end release outside the published platform and evidence matrix and has not been represented as standardized, quantum-proof, or FIPS validated.

## Private reporting

Report suspected vulnerabilities to `security@warptweet.com`.

Do not file a public issue for a suspected vulnerability before maintainers have had an opportunity to assess it privately.

## What to include

Provide enough information to reproduce and assess the issue without sending secrets:

- affected commit, build, package, and operating system;
- whether the client, server, manifest parser, engine boundary, supervisor, packaging, or key lifecycle is affected;
- prerequisites and a minimal reproduction;
- expected and observed behavior;
- security impact and the boundary crossed;
- relevant logs with identities, filesystem paths, network addresses, and tunneled content redacted;
- whether the issue has been disclosed elsewhere.

Never send private-key material, ML-DSA or Ed25519 seeds, passphrases, agent credentials, production `.wt` manifests, host inventories, or captured tunneled data. Construct a minimal synthetic manifest when reproduction requires one.

## In scope

Security reports are especially useful for:

- a classical downgrade or fallback path;
- acceptance of the wrong KEX, host key, client key, cipher, engine version, or executable digest;
- failure to require both composite signature components;
- host-key pinning or client authorization bypass;
- `.wt` strict-decoding, validation, path, or secret-smuggling flaws;
- command, OpenSSH configuration, path, tunnel ID, user, or systemd injection;
- unauthorized shell, command, subsystem, forwarding, listener, or target access;
- private-key disclosure through logs, diagnostics, manifests, process arguments, permissions, or cleanup;
- symlink, replacement, race, or time-of-check/time-of-use attacks on the engine, keys, pins, or runtime configuration;
- unbounded packet, connection, authentication, channel, restart, memory, CPU, or log consumption;
- sandbox or privilege-boundary escape;
- dependency or bundled-engine provenance failures.

An OpenSSH vulnerability may belong upstream. If it affects WarpTweet's pinned integration or policy, report it privately to both projects as appropriate and avoid public disclosure until coordination is established.

## Expected handling

Maintainers should:

1. Acknowledge the report through a private, authenticated channel.
2. Reproduce it without requesting production secrets.
3. Classify the affected invariant and supported repository state.
4. Coordinate with upstream projects when the defect is not WarpTweet-specific.
5. Prepare a fix, regression test, release note, and migration or revocation guidance where required.
6. Credit the reporter if requested and safe.
7. Publish only after affected users have actionable remediation and disclosure is coordinated.

## Supported versions

There is currently no supported production release. The repository's default branch is the only review target, and its security properties are limited to what tests and documentation demonstrate. Passing unit tests does not establish end-to-end security.

When releases begin, this section must be replaced with an explicit supported-version policy and signed release provenance.

## Safe research

Use systems and identities you own or have explicit permission to test. Do not disrupt shared services, access third-party data, retain secrets, or test a production target through WarpTweet without authorization. Stop if testing crosses the declared local-forward or managed-endpoint boundary.
