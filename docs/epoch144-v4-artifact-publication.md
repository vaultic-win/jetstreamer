# Exact epoch144 V4 artifact import

`jetstreamer-epoch144-publish` is a separate exact-artifact publisher, not a
runtime registry promotion or a general V4 publication route. Its source alone
does not grant deployment, admission, or publication qualification.

It consumes the distinct read-only [two-scan evidence](epoch144-publication-evidence.md),
requires the pinned evidence collector and both underlying private receipts/logs,
and keeps the scanner's original ten-element source identity. It preserves the
root-owned original assembly and creates a separately owned, distinct-inode copy
under a fresh private stage. The copy is guarded before every write, hashed while
copying, fsynced, checked for full432000-slot V4 coverage and independently
expected provenance, and completely reread after assigning final permissions.
Any mismatch, changed source or changed live owner fails closed; failed copies
are preserved for diagnosis and no-clobber recovery, never retried in place.

Before canonical import it reopens/revalidates the original and evidence, then
permanently drops all user/group saved IDs to sol UID1001 / horizon GID1003 and
checks that no permitted/effective/ambient capabilities remain. It uses the
existing inode-locked, absence-only recoverable archive transaction and writes
the canonical checksum last. Publication evidence becomes durable before the
standard full/plugin gate descriptors become parseable. It acknowledges the
transaction only after those private gates are durable. An interrupted local
transaction requires explicit recovery, not another attempt over the same stage.

The fixed target is `/home/sol/horizon`, exact owner/group/mode1001/1003/3770.
No R2 client is called. The full/plugin gates use the original private scan runner
SHA as script identity; a future uploader must explicitly qualify those exact
binary/runner hashes and receipt directories, not reuse an unrelated allowlist.
Both boundary receipts are still required before normal local retirement.

## Resource and filesystem gates

The initial profile deliberately retains4740696923590bytes of inherited
protection and adds the complete109177480876-byte copy plus1GiB of margin. This
is **not** a4.74TB century floor: the bound verified201 sample is separately
rehash-validated and its205211459014-byte floor is recomputed. No running guard
is changed. The initial profile requires at least4850948146290bytes available
in both a fresh coordinated v2 sample and actual admission. Every copy iteration
requires the remaining copy debt above the same protection. It also checks the
sample and actual192GiB memory reserve and exact current owners against the
complete accepted campaign fleet, again before import.

The accepted11:58 sample has4762076106752bytes available, so it cannot admit this
initial profile (88872039538bytes short). This is an evidence-bound result for
that sample/profile, not a fresh resource observation or a conclusion that the
machine cannot fit a differently qualified envelope. Do not lower live guards,
mislabel their protected claims as the century floor, or bypass the guard to
make this copy fit. Safe reclamation or a separately reviewed, measured envelope
transition remains necessary if a later accepted sample still fails.

The intended work root is a precreated root-owned mode0711 direct child of
`/home/sol/.jetstreamer-private` named `epoch144-publication-work-UNIQUE`.
`stage/` must be absent. A root-owned mode0700 receipt root beneath
`/var/lib/jetstreamer/horizon-epoch144-publication-UNIQUE` must have distinct
root-owned mode0700 `full/` and `plugin/` children. The sealed strict plan binds
the scan evidence, observer, fleet, century floor, work and receipt directories,
and grants only `artifact_publication_authorized: true`; registry, remote and R2
mutation flags must stay false.

An equivalent sandboxed `--check-only` invocation validates evidence, absence,
same statx mount ID and actual admission without writes, archive hashing or a
copy. Import additionally installs process-local Landlock ABI>=3 confinement to
only the exact work root, receipt root and public destination. It reuses the
existing epoch213 kernel policy implementation, reporting that policy identity
without relabelling epoch213 producer/verification evidence as epoch144.
Do not bind work and destination as separate writable mount aliases: equal
device numbers alone do not prove rename capability.

## Disposable kernel capability proof

`--capability-probe ROOT --self-sha256 SHA` is a separate no-campaign mode.
ROOT must be an empty root-owned mode0711 direct child of the private root named
`epoch144-publication-capability-UNIQUE`. The sealed executable creates only fake
bytes, a local destination and root-private receipt sinks beneath that root.
It exercises the real write confinement, denial of an outside write, permanent
UID1001/GID1003 drop, checksum-last absence-only transaction, retained root
receipt FD and transaction acknowledgement. It never opens the campaign source
or public directory. The resulting receipt explicitly denies campaign import,
registry promotion and R2 authority.

Qualify this actual mode under the intended sandbox before any real import.
Root needs only the reviewed traversal/ownership/credential-drop capabilities
(DAC_OVERRIDE, CHOWN, SETUID and SETGID); verify effective capabilities at the
transition. Keep the common data-filesystem mount identity intact and use the
process-local narrow write policy rather than separate bind mounts that cause
EXDEV. Evidence collection, kernel capability, fresh resource admission,
production check-only, actual local import, delivery and retirement are distinct
gates. Never restart a healthy scanner or replay to obtain any of them.
