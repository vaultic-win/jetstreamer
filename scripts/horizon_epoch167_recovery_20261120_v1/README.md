# Epoch 167 retry8 peer evidence

The read-only Rust entry point in `prepare` emits the single epoch 166 resident-owner row for the retry8 preparation plan. The peer is the first independently admitted epoch 166 retry9 producer. The controller supplies the two actual receipts after that admission, with their paths and SHA-256 digests in a root-controlled, digest-bound plan.

```json
{
  "schema": "horizon-167-retry8-live166-receipts-v1",
  "epoch": 167,
  "attempt": "local3retry8",
  "admission": {"path": "<absolute actual admission path>", "sha256": "<receipt SHA-256>"},
  "guard_protection": {"path": "<absolute actual guard protection path>", "sha256": "<receipt SHA-256>"}
}
```

After normal build qualification, `prepare-peer --check-lineage` checks the published source's four pinned stop receipts and the root creation receipt against the current HOME-backed inodes. `prepare-peer PLAN --plan-sha256 SHA256` also reads PID1, the producer's process start time, its actual admission, original process observation, first timer-driven guard sample, protection record and guard plan. It emits the resident-owner row only when those identities agree across the capture. The module's `observe` function can also be used inside the native preparer.

For production integration, evaluate this binding during the preparer's existing opening and closing allocation checks. Compare its entire row to the owner in the fleet and booking, and re-evaluate at launch. Keep the full resident process, executable, cgroup, current guard and fleet checks. Bind the current HOME audit contract and a newly qualified epoch 167 guard for the precreated retry8 root. Publish and seal the resulting full preparer, guard and launcher before using their admission path. The emitted row carries no resource credit or replay authorization.
