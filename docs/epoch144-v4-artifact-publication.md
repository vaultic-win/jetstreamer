# Exact epoch 144 V4 artifact import

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
permanently drops all user/group saved IDs to sol UID 1001 / horizon GID 1003 and
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

The initial profile deliberately retains 4740696923590 bytes of inherited
protection and adds the complete109177480876-byte copy plus 1 GiB of margin. This
is **not** a4.74 TB century floor: the bound verified 201 sample is separately
rehash-validated and its205211459014-byte floor is recomputed. No running guard
is changed. The initial profile requires at least 4850948146290 bytes available
in both a fresh coordinated v2 sample and actual admission. Every copy iteration
requires the remaining copy debt above the same protection. It also checks the
sample and actual 192 GiB memory reserve and exact current owners against the
complete accepted campaign fleet, again before import.

The accepted 11:58 sample has 4762076106752 bytes available, so it cannot admit this
initial profile (88872039538 bytes short). This is an evidence-bound result for
that sample/profile, not a fresh resource observation or a conclusion that the
machine cannot fit a differently qualified envelope. Do not lower live guards,
mislabel their protected claims as the century floor, or bypass the guard to
make this copy fit. Safe reclamation or a separately reviewed, measured envelope
transition remains necessary if a later accepted sample still fails.

### Separately qualified four-producer delivery envelope

Plan schema `jetstreamer-exact144-v4-publication-plan-v2` requires a
`refreshed_capacity` object with schema
`jetstreamer-exact144-delivery-capacity-refresh-v1` and four hash-bound
`growth_claims`, ordered152-153,155-156,160,191-194. The original v1 profile
continues unchanged and rejects this additional authority-bearing input.

The refresh is specific to the exact nine active claims and four unchanged
producers. Each claim must be produced by the pinned Rust growth verifier from
at least six chained routine v2 samples, end at this plan's observer, and bind
the current controller/producer invocations. The plans and sample files are
rehash-validated. Budgets remain 512,512,768,512 GiB, respectively; no shrinkage
or proposed deletion is credited. Each already includes one twice-max-jet
allowance. Add five more such allowances for the remaining claimed epochs,
the independently recomputed century floor, and 64 GiB of staging/uncertainty
margin. This covers all nine downstream archive debts, not just four workers.

Protection is the larger of that complete sum and every unchanged live guard
threshold. Exact current guard commands, immutable script digests, successful
actual fires within 180 seconds, zero restarts, hardened settings, live timers,
controller/producer identities, 800000VMA bounds and absence of trip receipts
are required. The highest guard remains 3984782679494 bytes. The nine-epoch
fleet census must match the observer and have no other live delivery pipeline;
an extra/restarted/changed claim requires a new qualification, not a smaller
constant. Current coordinated memory/OOM/VMA evidence and actual copy guards
remain mandatory.

The refreshed protection plus the complete copy and 1 GiB requires
4095033902194 bytes. No live guard is edited, lowered, stopped or replaced.
The selected protection is retained through every copy write and requalified
before import. This source path is not deployment, fleet-monitor integration,
kernel capability proof, fresh admission, or permission to launch an
unmonitored publisher. Qualify those separately before a real canonical copy.

Capacity refresh v2 describes the ended epoch 160 replay's controller/import
handoff with three remaining growth claims. It retains the entire prior
3984782679494-byte protection, including 768 GiB of explicit 160 delivery debt;
the old 160 reserve guard is not counted as live. That admission cannot be reused
after the controller finishes and canonical verification begins.

Capacity refresh v3 instead binds `epoch160_public_delivery` to the exact sealed
canonical-import/watcher proof. It requires all eight still-claimed replay
epochs and only exact 160 full/plugin/upload owners from that proof. Missing,
changed or additional owners fail closed. No 160 live child is allowed only with
an independently reconciled `remote-ready` outcome. Readiness still does not
reduce the retained 768 GiB debt or total protection. The growth observations must
end at the publisher's current coordinated observer; all current guard, memory,
VMA, identity, copy and century-floor gates remain unchanged. V1, v2 and v3
capacity schemas reject mixed handoff/public-delivery fields. Source support
alone does not qualify a new publisher, tracker, uploader or production launch.

The intended work root is a precreated root-owned mode 0755 direct child of
`/home/sol/.jetstreamer-private` named `epoch144-publication-work-UNIQUE`.
`stage/` must be absent. A root-owned mode 0700 receipt root beneath
`/var/lib/jetstreamer/horizon-epoch144-publication-UNIQUE` must have distinct
root-owned mode 0700 `full/` and `plugin/` children. The sealed strict plan binds
the scan evidence, observer, fleet, century floor, work and receipt directories,
and grants only `artifact_publication_authorized: true`; registry, remote and R2
mutation flags must stay false.

An equivalent sandboxed `--check-only` invocation validates evidence, absence,
same statx mount ID and actual admission without writes, archive hashing or a
copy. Import additionally installs process-local Landlock ABI>=3 confinement to
only the exact work root, receipt root and public destination. It reuses the
existing epoch 213 kernel policy implementation, reporting that policy identity
without relabelling epoch 213 producer/verification evidence as epoch 144.
Do not bind work and destination as separate writable mount aliases: equal
device numbers alone do not prove rename capability.

## Disposable kernel capability proof

`--capability-probe ROOT --self-sha256 SHA` is a separate no-campaign mode.
ROOT must be an empty root-owned mode 0755 direct child of the private root named
`epoch144-publication-capability-UNIQUE`. The sealed executable creates only fake
bytes, a local destination and root-private receipt sinks beneath that root.
It exercises the real write confinement, denial of an outside write, permanent
UID1001/GID1003 drop, checksum-last absence-only transaction, retained root
receipt FD and transaction acknowledgement. It never opens the campaign source
or public directory. The resulting receipt explicitly denies campaign import,
registry promotion and R2 authority.

Mode 0755 is required on these fresh non-sensitive work roots because the
transaction writer lock opens every ancestor with O_RDONLY|O_DIRECTORY, not
O_PATH. Traverse-only0711 fails after the permanent privilege drop. Do not
relax an existing root-private evidence tree; the receipt children stay 0700.
Set copy permissions while root still owns the new copy, then hand ownership
to sol. The real publisher and capability probe share that checked helper and
do not add CAP_FOWNER.

Qualify this actual mode under the intended sandbox before any real import.
Root needs only the reviewed traversal/ownership/credential-drop capabilities
(DAC_OVERRIDE, CHOWN, SETUID and SETGID); verify effective capabilities at the
transition. Keep the common data-filesystem mount identity intact and use the
process-local narrow write policy rather than separate bind mounts that cause
EXDEV. Evidence collection, kernel capability, fresh resource admission,
production check-only, actual local import, delivery and retirement are distinct
gates. Never restart a healthy scanner or replay to obtain any of them.
