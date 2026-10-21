# Failed 220–223 cohort: primary-source prefix evidence

`jetstreamer-epoch220-prefix-evidence` captures the exact quarantined producer
`c2adebaad0cb42b385156631156813fe` and stopped controller
`0b69b5009dc74bbda94b94d059a3daa7`. It is a read-only, incident-specific collector,
not a recovery importer or a runtime qualification gate.

Run the sealed binary as root with an absolute, absent output filename below a
root-owned owner-only directory and its independently supplied executable SHA-256:

```text
jetstreamer-epoch220-prefix-evidence OUTPUT --self-sha256 HEX
```

It independently hashes the original immutable node and preflight report, checks
their fixed identities, and requires both original service invocations to remain
terminal with zero restarts. It captures bounded JSON journal records for the
original invocation, authenticates their service, executable, UID and PID,
requires distinct ordered journal cursors, and mechanically extracts all seven
complete checkpoint tuples. Each 220–222 root accounts hash must equal its entry
in the independently hash-bound original manifest. Bootstrap, per-epoch root,
terminal, archive-close and retained-validation messages must occur in order,
before the exact epoch-223 post-update-count failure. Missing, duplicate,
foreign, changed or incomplete records fail closed. Inputs and terminal service
identities are rechecked before a no-clobber, fsynced root-only receipt is written.

The receipt preserves the raw selected JSON journal and digest. It observes no
replay resources, changes no service, creates no segment manifest or canonical
sidecar, grants no restart/import/publication/retirement authority, and performs
no network or R2 mutation. In particular, observing a root hash in the journal
does not independently reread the retained archives or prove their current bytes.

Complete private 220–222 archives still need independent rereads, a separately
reviewed failed-prefix recovery/import path, and normal full/current-plugin and
authenticated R2 delivery gates. The whole-cohort unreceipted recovery command
requires a different terminal/guard history and must not be used for this failure.
Preserve the original prefix and partial 223; never fabricate missing manifests,
truncate updates, or replay 220–222 merely to recover 223.
