# Private epoch 140 checkpoint journal observation

`jetstreamer-epoch140-checkpoint-journal` preserves the exact bounded original
producer journal response and mechanically extracts the checkpoint fields. It is
fixed to invocation `b907f4e67095443cb02e9c815ee14499` on `dev-samjohnson`,
slots 60,911,751 and 60,911,999, and the six-minute original journal window.
It never reads or changes an archive, starts a worker, creates a recovery
manifest, or accesses R2.

Seal the reviewed executable and an immutable root-owned plan using the normal
deployment sealer. Supply the executable's independently recorded SHA-256 and
the plan SHA-256 separately:

```text
jetstreamer-epoch140-checkpoint-journal PLAN --plan-sha256 HEX --self-sha256 HEX
```

The strict plan shape is:

```json
{
  "schema": "jetstreamer-epoch140-checkpoint-journal-plan-v1",
  "journalctl_sha256": "<actual lowercase SHA-256 of /usr/bin/journalctl>",
  "output_receipt": "/var/lib/jetstreamer-epoch140-checkpoint-journal-UNIQUE/observation.json"
}
```

Pre-create the canonical root-only output directory. Run as root with only
that directory writable, read-only system/home mounts, no network, bounded CPU,
memory and tasks, and a oneshot timeout exceeding the internal 30-second child
limit. Capture rejects journal warnings, missing or extra records, changed
producer/unit/boot/PID/executable identity, duplicate cursors, reordered or
out-of-window timestamps, incomplete checkpoints, unexpected fields and
noncanonical numeric/hash encodings. The same journalctl file is rehashed
before and after capture. The no-clobber receipt fsyncs its own file and parent
directory and embeds the raw JSONL response in base64 with its SHA-256.

This is a **filtered journal observation**, not a hash of the complete producer
journal and not `horizon-historical-journal-evidence-v1`. Do not relabel it to
satisfy the delayed-reaping recovery profile. The verified-accounts log at
60,911,751 does not independently prove the terminal accounts hash at
60,911,999. Both tuples remain observations of the original producer, not
proof of a canonically valid tail. Actual snapshot clock, native restore tuple,
complete prefix reread/hash, all hidden PoH boundaries and complete intended
execution-interval census remain independent qualification requirements.
No replay, import, sidecar, publication, retirement or remote mutation authority
follows from successful capture.
