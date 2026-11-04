# Bounded, receipt-gated local retirement

The Rust progressive binary has a distinct `--retirement-only` mode for one
already-published epoch. This is a bounded local-retirement helper, not a second
progressive uploader. It never calls `sync` or `public-verify`, polls for work,
uploads an archive/sidecar, or mutates R2. Keep the existing progressive delivery
owner unchanged and use the same exact private local-mutation lock.

Pass the ordinary uploader/directory/receipt arguments and full, current-plugin
and both adjacent-boundary verifier/script allowlists. This mode requires a
singleton range, `--delete-local`, a shared mutation lock directly beneath the
receipt directory, and no public-origin receipt configuration. Deferred epochs
remain blocked. The shared lock spans exact local-pair inspection, existing
authenticated R2 readback evidence, every normal publication/retirement gate and
the Rust uploader's `retire-local` child. No missing proof falls back to upload.

First use `--check-retirement-only` with the same arguments. It takes the shared
lock and checks the same local receipt gates, then exits without an uploader
child, archive hash, remote request or local removal. This is policy preflight,
not a fresh remote-pair proof; real `retire-local` must still rehash the local
archive, validate its durable R2 evidence and re-observe the authenticated remote
archive/sidecar before removing the local sidecar and archive.

Seal the exact helper and bind the actual uploader/verifier/script digests in a
reviewed deployment. Before execution prove the selected archive is not needed
by a live controller/verifier or staged import. Run under a persistent,
non-restarting bounded systemd unit with the configured credential file and
adequate Tokio task headroom. Neither this mode nor successful boundary
verification authorizes deleting any R2 object or bypassing full/plugin gates.
The source remains recoverable from its verified R2 ready pair after local
retirement; preserve all receipts and independent verification evidence.
