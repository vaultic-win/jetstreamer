The epoch 209 Full v11 startup waiter passed admission, then stopped before
starting a guard, executing its child, or reading archive contents because
`archive_readonly_mount` reported `mountpoint is ambiguous`. The preserved
namespace has valid stacked mounts at `/run/user/1000` and
`/proc/sys/fs/binfmt_misc`. Neither path covers the archive or lies inside it.

The parser now retains mountpoints for ambiguity and access decisions only when
they cover the archive or lie inside it, using path components in both
directions. Every row still passes the existing bounded-input, row syntax,
numeric device/parent IDs, globally unique nonzero mount IDs, path decoding,
and access-flag checks before this scope decision. Even two read-only records
at a relevant mountpoint remain ambiguous. The most specific covering mount
and every mount inside the archive must still be read-only. Missing coverage,
writable covering/descendant mounts, and malformed unrelated rows still fail.
The returned proof schema and hash of the complete original mountinfo are
unchanged; the original namespace evidence is not filtered or rewritten.

Five new pure tests cover inherited read-only `/home` coverage with unrelated
overmounts and a writable state sibling, mount listing order, the byte-identical
captured v11 namespace, ambiguity at every ancestor/source/descendant level,
writable directory or file bind aliases at source paths, component boundaries,
and global validation of malformed or duplicate-ID unrelated rows. Existing
mount tests remain in place. The actual v11 fixture has read-only coverage from
`/` and no exact archive mountpoint; a separate synthetic case tests read-only
`/home` coverage over a writable root. Fixture provenance binds the original
6048-byte diagnostic and actual v11 startup/admission metadata. It grants no
runtime, admission, archive, release, or publication authority.

This source is based on root integration
`6a27a185b4cc2e7a68d03a368555b2ffd7d109f1`. Only formatting and whitespace
validation were run. Tests and compilation are deliberately deferred to the
root's compiler lease and qualification workflow. No archive body, current
namespace, service, guard, fleet, observer, or R2 operation was performed.
