# Exact cohort-191 verifier wrapper augmentation

The existing `horizon-cohort191-delivery-tools-20261023-v1` deployment has
the qualified R2 client but lacks the separately qualified verifier wrapper.
Its original four members, including its original seal and `SHA256SUMS`, must
remain byte-for-byte and inode-for-inode unchanged. The user authorized adding
the wrapper without replacing an existing file.

`jetstreamer-append-cohort191-wrapper` implements this one fixed transition.
Its production entry points require root and its separately supplied self hash.
`--capture-plan --self-sha256 HEX` snapshots the four original files into a
native plan under the fixed external state directory. Seal that captured plan
with the normal deployment sealer before executing it. The execution command
is `PLAN --plan-sha256 HEX --self-sha256 HEX`, optionally `--check-only`.

The tool pins the existing publisher hash, wrapper source path and hash,
destination package and external state directory. It hashes stable readonly
regular files through no-follow descriptors and captures their inode, device,
mode, length, ownership, link count and timestamps. It rejects unexpected
package entries and binds the plan's complete original-member map.

The external root-only state directory holds the exclusive mutation lock,
intent, temporary copy and completion. The package directory keeps mode 0555;
the root process uses its existing DAC override capability. The wrapper is
copied and fsynced externally, its verified mode is set to 0555, and
`renameat2(RENAME_NOREPLACE)` publishes it on the same filesystem. Original
member snapshots are rechecked before and after publication. The original
deployment seal and `SHA256SUMS` are historical evidence and are not rewritten.
The separate completion authenticates the additive transition.

Interrupted copies resume only after their exact retained prefix matches the
qualified source. Intent and completion use fsynced temporary files and
no-replace publication; a partial receipt resumes only when its bytes match
the intended JSON prefix. Conflicting existing files are preserved and rejected.
Reentry after wrapper publication requires the exact original intent and
matching wrapper and can recover the missing completion without copying again.

Qualification covers original-member changes, unexplained or symlinked input,
partial-copy recovery and conflicting prefixes, no-clobber rename, interrupted
receipt publication, and root-only additive publication and reentry. Run the
bin's tests with `--include-ignored` as root, strict bin Clippy and a release
build in the serialized modern build target. Seal the qualified helper before
capturing or applying a production plan.

This transition grants no archive integrity, replay, independent verification,
publication, R2 mutation, local archive retirement or capacity credit. Those
gates remain with their existing separately qualified tools and fresh admission.
