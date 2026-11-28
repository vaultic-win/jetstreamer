# Optional invocation-bound progress log

Observer config and receipts remain schema v2. Journal extraction remains the
default. A replay may opt into a private append log:

```json
"append_log": {
  "path": "/absolute/private/service.log",
  "device": 64512,
  "inode": 96337932
}
```

Seal these values in a new observer deployment; never edit a running producer or
an existing sealed config. The file must be canonical, root-owned, owner-only,
singly linked, and match the live producer MainPID's stdout descriptor, including
its append flag. The observer checks that binding before and after the read,
allows append growth but not truncation or inode replacement, then rechecks the
exact zero-restart systemd invocation and main PID. Existing scratch, worker,
cadence, and resource checks are unchanged.

The reader snapshots at most the last 8 MiB. It skips an initial partial line and
an unfinished final line, requires timestamp coverage back to the observation
window, and rejects malformed or backwards progress timestamps. It uses the
legacy logger's UTC timestamps, not file mtime or observation time. A failure
rejects the sample; it never silently falls back to journald.

`useful_work.append_log_evidence` records source identity, producer PID, read
offset/length, snapshot length, and SHA-256 of the exact bytes read. For backward
compatibility, `journal_invocation_id` continues to contain the bound producer
invocation even for this source; the optional evidence explicitly identifies
non-journal provenance. These are checkpoint progress rates, not evidence that
an incomplete focused archive is publishable or has an R2 completion ETA.

Before operational deployment, run normal package tests and clippy, plus the
explicit `root_live_stdout_binding_and_file_policy` test as root. The root test
uses disposable child processes/files only and covers correct append binding,
wrong inode, non-append stdout, hard links, public permissions, and symlinks.
Seal the release binary and config normally. Admit the change only at the next
coordinated 30-minute observation; do not add a parallel polling loop.
