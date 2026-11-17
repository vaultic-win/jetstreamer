# Epoch 205 canonical stage

This one use Rust tool stages the validated epoch 205 archive as a canonical
archive and sidecar. It holds the shared local mutation lock, checks the exact
successful diagnostic invocations, verifies both the source and copied bytes,
publishes with no clobber renames, and fsyncs a private receipt. The private
source remains intact. The receipt does not authorize verification, R2 upload,
or local retirement.

Seal the binary and exact operation plan with `jetstreamer-seal-deployment`.
Run `horizon-stage205 PLAN PLAN_SHA256 SELF_SHA256 --check-only` under the final
sandbox before running it without `--check-only`.
