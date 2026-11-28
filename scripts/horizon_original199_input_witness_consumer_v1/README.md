# Explicit original199 input witness consumer

This library consumes the genuine, normally sealed five-input verification
witness through an explicitly selected, hash-bound context. It rechecks each
original file's complete identity metadata without opening its body. Consumers
that need the quarantined state JSON read its independently verified, normally
sealed exact-byte copy and recheck the original identity on both sides.

The selector preserves the original enrollment and terminal context. Unknown
contexts, changed inputs, incomplete witnesses, crossed enrollments, unqualified
producers and expanded authority fail closed. No ambient cache lookup, PID
exemption, resource release or replay admission is provided.

Qualification used Rust 1.98 and the existing five-artifact dependency graph.
Production/test Clippy, library/test builds, all 15 ordinary tests and the
explicit installed-context control passed. The seven original scopes completed
and drained. The production library and its artifact proof are sealed at:

```
/usr/local/lib/jetstreamer/horizon-original199-witness-consumer-library-tools-20261107-v1
```

Exact source, arguments, dependency digests and original execution receipts are
recorded in:

```
/home/sol/.jetstreamer-private/original199-witness-consumer-qualification-20261107-v1
```

The ordinary filesystem cases require a booked Root sandbox and a precreated,
Root-private `TMPDIR` below
`/var/lib/jetstreamer/horizon-original199-witness-consumer-qa-20261107-v1`.
The ignored installed-context test must run explicitly after normal sealing.
It reads original input identity metadata and the sealed state copy only.

Full-reader integration, rebuilding its opaque consumers, genuine current
accounting and fresh replay admission remain required. The library's successful
control alone establishes no running replay lane or completed epoch.
