# Epoch 205 canonical stage

The first sealed generation copied the archive but stopped before publication
because its expected SHA-256 literal had one extra character. The second
generation reached the permission step after rechecking both digests. The third
generation verified both files but the sticky destination directory blocked
rename after ownership changed. The fourth generation binds both completed
temporary files and the failed unit, intent, inode, and digests. It holds
the shared local mutation lock, checks the successful diagnostic invocations,
publishes with no clobber renames, and fsyncs a private receipt. The private
source remains intact. The receipt does not authorize verification, R2 upload,
or local retirement.

Seal the binary and exact operation plan with `jetstreamer-seal-deployment`.
Run `horizon-stage205 PLAN PLAN_SHA256 SELF_SHA256 --check-only` under the final
sandbox before running it without `--check-only`.
