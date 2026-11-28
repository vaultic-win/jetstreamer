"""Run the sealed continuation, then attest its first advancing guarded transaction batch."""
import hashlib
import json
import os
from pathlib import Path
import re
import select
import stat
import sys
import time

ROOT = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch170-from-73746882-20261127-v1")
RETRY_ROOT = ROOT/"attempt-2"
FOLLOWING_ROOT = ROOT.parent/"epoch170-from-73766969-20261127-v1"
GAP_ROOT = ROOT.parent/"epoch170-from-73760367-20261128-v1"
RAM_ROOT = ROOT.parent/"epoch170-from-73760367-ram-20261128-v1"
SECOND_RAM_ROOT = ROOT.parent/"epoch170-from-73760367-ram-20261128-v2"
THIRD_RAM_ROOT = ROOT.parent/"epoch170-from-73760367-ram-20261128-v3"
for candidate in (SECOND_RAM_ROOT, THIRD_RAM_ROOT):
    if Path(__file__).resolve().parent == candidate/"operator-v1":
        RAM_ROOT = candidate
        break
RAM_OPERATOR = RAM_ROOT/"operator-v1"
RETRY = Path(__file__).resolve().parent in (RETRY_ROOT/"progress-v1", RETRY_ROOT/"progress-v2", RETRY_ROOT/"progress-v3")
if RETRY:
    ROOT = RETRY_ROOT
elif Path(__file__).resolve().parent == RAM_OPERATOR:
    ROOT = RAM_ROOT
elif Path(__file__).resolve().parent == GAP_ROOT/"progress-v1":
    ROOT = GAP_ROOT
elif Path(__file__).resolve().parent in (FOLLOWING_ROOT/"progress-v1", FOLLOWING_ROOT/"progress-v2", FOLLOWING_ROOT/"progress-v3", FOLLOWING_ROOT/"progress-v4", FOLLOWING_ROOT/"progress-v5"):
    ROOT = FOLLOWING_ROOT
WRAPPERS = {
    GAP_ROOT/"progress-v1": ("operator-v1", "7b5b4ea18425c1fc1ca510f83a3571805c52268e0e909167a6380f2ea0c53718"),
    FOLLOWING_ROOT/"progress-v5": ("operator-v5", "050361ba7d4b62135951451ec4b3d3a1960e5e3e1c04288bd64865c3775814d4"),
    FOLLOWING_ROOT/"progress-v4": ("operator-v4", "171dee2e56a5d1c3925f5c6b1fd4c4f52101f78757a9fca293afa9cfb2e47d5f"),
    FOLLOWING_ROOT/"progress-v3": ("operator-v3", "86a99a635bc917af6f8832112bcedb5bedb12a5b13b6ba7fc3176537f81dd032"),
    FOLLOWING_ROOT/"progress-v2": ("operator-v2", "09281f70df692f622c7e8ff52439bb00414ef2d58128e610cecb6d1dd3ac0351"),
    FOLLOWING_ROOT/"progress-v1": ("operator-v1", "386d55ec91710ff3ededb9d019370a68264c74fd0c739ac83ea06c523d64d9d4"),
    RETRY_ROOT/"progress-v3": ("operator-v3", "64f167d88145f2deca94f488d99fc2b0283e6264d1ba220ba702f55b6666dbfd"),
    RETRY_ROOT/"progress-v2": ("operator-v2", "6452dabfdb8ed76c67342c58cbdeca66355dbf45ba89395bf906f6468b2544a4"),
    RETRY_ROOT/"progress-v1": ("operator-v1", "0de9e1ecbd4569acb74ad6c691e953ba0dab94222c1ef617aab809d5b82d808b"),
    ROOT/"progress-with143-v1": ("operator-with143-v1", "37ef972912965856076461d7e480897b2ad2696cdfae2dbfa7215605a8bc12f3"),
    ROOT/"progress-with143-v2": ("operator-with143-v2", "bd5bcd1a55199382dde3ada2dcb3ab8426cef69f8e1057dd32a6c187a69c36fe"),
}
DISPATCH_SHA = "8d3d759e44b6ab821a8d0020e8cba1a4ef26ab91f59c9fb8cb4a84f0a66c11ff"
OPERATOR_NAME, EXPECTED_DISPATCH = WRAPPERS.get(Path(__file__).resolve().parent, ("operator", DISPATCH_SHA))
OPERATOR = ROOT/OPERATOR_NAME
PROGRESS = re.compile(rb"\] progress slot (\d+)/(\d+) .*?txs=(\d+) accounts=(\d+)")
MAX_LINE = 1 << 20


def require(value, message):
    if not value:
        raise ValueError(message)


def first_batch(log, identity, scope):
    while True:
        offset = log.tell()
        line = log.readline(MAX_LINE + 1)
        require(len(line) <= MAX_LINE, "oversized producer log record")
        if not line.endswith(b"\n"):
            log.seek(offset)
            return None
        match = PROGRESS.search(line)
        if not match:
            continue
        slot, terminal, txs, updates = map(int, match.groups())
        require(terminal == scope["last"] and slot <= terminal, "unexpected progress bounds")
        if slot > scope["first_new_slot"] and txs:
            return dict(slot=slot, last_requested_slot=terminal, transactions=txs, account_updates=updates,
                        first_log_byte=offset, last_log_byte=log.tell()-1, line=line[:-1].decode(),
                        log_device=identity.st_dev, log_inode=identity.st_ino)


def worker_sample(dispatch, scope, actor, release):
    guard_dir = Path(scope["guard_receipts"])
    require(not (guard_dir/"stop-intent.json").exists(), "successor guard tripped")
    sample, ref = dispatch.q.read(max(guard_dir.glob("sample-*.json"), key=lambda path: path.stat().st_mtime_ns))
    iid = actor["producer_invocation_id"]
    require(sample["producer_invocation_id"] == sample["producer"]["invocation_id"] == iid
            and sample["producer"]["pid"] == actor["producer_pid"] and sample["producer_stop_enabled"]
            and sample["plan_sha256"] == release["guard_plan"]["sha256"] and sample["trip_reason"] is None
            and sample["worker_observation_error"] is sample["root_physical_observation_error"] is None
            and not sample["root_physical_observation"]["exceeds_budget"]
            and sample["available_bytes"] >= sample["minimum_free_bytes"], "invalid protective sample")
    if not sample["workers"] or time.time() - sample["recorded_unix_seconds"] > 75:
        return None
    require(sample["recorded_unix_seconds"] <= time.time(), "future protective sample")
    (pid, _vmas), = sample["workers"]
    proc = Path("/proc")/str(pid)
    def ticks():
        return int((proc/"stat").read_text().rsplit(") ", 1)[1].split()[19])
    start = ticks()
    timer = dispatch.q.state(scope["expected_guard_timer"], "ActiveState,Id,InvocationID,Job,Triggers")
    require(timer["ActiveState"] == "active" and not timer["Job"] and timer["Triggers"] == scope["expected_guard_unit"]
            and timer["InvocationID"] == release["guard_timer_invocation_id"], "different protective timer")
    if ROOT == RAM_ROOT:
        matched = dispatch.operator.workspace.worker(pid, actor["producer_pid"], Path(scope["run"])/"scratch",
                                                    scope["profile"]["worker"],"/system.slice/"+actor["unit"])
        require(dispatch.operator.actor(False)==actor and ticks()==start, "private worker or actor changed")
        return ref, dict(matched, exe=matched["path"])
    exe = (proc/"exe").resolve(strict=True)
    require(exe.is_relative_to(Path(scope["run"])/"scratch") and exe.name == "historical-worker"
            and dispatch.operator.digest(proc/"exe") == scope["profile"]["worker"]
            and (proc/"cgroup").read_text().strip() == "0::/system.slice/"+actor["unit"]
            and set((Path("/sys/fs/cgroup/system.slice")/actor["unit"]/"cgroup.procs").read_text().split())
                == {str(pid), str(actor["producer_pid"])}
            and dispatch.operator.actor(False) == actor and (proc/"exe").samefile(exe) and ticks() == start,
            "different node, worker or guard")
    return ref, dict(pid=pid, exe=str(exe), start_ticks=start, sha256=scope["profile"]["worker"])


def follow(dispatch):
    q = dispatch.q
    scope, scope_ref = q.scope()
    actor, actor_ref = q.read(ROOT/"SUCCESSOR_ACTOR.json")
    release, release_ref = q.read(ROOT/"SUCCESSOR_RELEASE.json")
    iid = actor["producer_invocation_id"]
    require(release["actor"] == actor_ref and release["interface"] == scope_ref
            and release["producer_invocation_id"] == iid and Path(scope["barrier"]).read_text() == iid
            and not release["archive_publication_authorized"], "unconfirmed successor release")
    if ROOT in (GAP_ROOT,RAM_ROOT):
        require(release["independent_checkpoint"] == q.compare_predecessor(), "different independent gap checkpoint")
    dest = ROOT/"FIRST_PROTECTED_PROGRESS.json"
    if dest.exists():
        existing, ref = q.read(dest)
        require(existing["release"] == release_ref and existing["actor"] == actor_ref
                and existing["scope"] == scope_ref, "existing proof names another release")
        return ref
    proc = Path("/proc")/str(actor["producer_pid"])
    log_path = Path(scope["log"])
    changes = dispatch.Changes()
    try:
        changes.watch(Path(scope["guard_receipts"]))
        pidfd = os.pidfd_open(actor["producer_pid"])
        try:
            # Wake only on guard output or node exit; each wake consumes newly completed log lines.
            with log_path.open("rb") as log:
                identity = os.fstat(log.fileno())
                require(stat.S_ISREG(identity.st_mode) and identity.st_nlink == 1 and identity.st_uid == 0
                        and (proc/"fd/1").samefile(log_path) and (proc/"fd/2").samefile(log_path)
                        and os.path.samestat(log_path.lstat(), identity), "unbound producer log")
                deadline = time.monotonic() + 75*60
                batch = None
                while True:
                    batch = batch or first_batch(log, identity, scope)
                    evidence = batch and worker_sample(dispatch, scope, actor, release)
                    if evidence:
                        guard, worker = evidence
                        require((proc/"fd/1").samefile(log_path) and os.path.samestat(log_path.lstat(), identity)
                                and not select.select([pidfd], [], [], 0)[0], "producer changed during observation")
                        return dispatch.operator.save(dest.name, dict(
                            schema="horizon-epoch170-bounded-successor-first-protected-progress-v1",
                            recorded_unix=time.time(), actor=actor_ref, release=release_ref,
                            producer_invocation_id=iid, producer_pid=actor["producer_pid"], worker=worker,
                            native_guard=guard, guard_timer_invocation_id=release["guard_timer_invocation_id"],
                            scope=scope_ref, progress=batch, resource_credit_bytes=0, canonical_publication_authorized=False))
                    left = deadline - time.monotonic()
                    require(left > 0, "startup observation expired")
                    ready, _, _ = select.select([changes.fd, pidfd], [], [], left)
                    require(ready and pidfd not in ready, "node exited or startup observation expired")
                    changes.events(0)
        finally:
            os.close(pidfd)
    finally:
        changes.close()


def main():
    observe = ROOT in (GAP_ROOT,RAM_ROOT) and sys.argv[1:] == ["observe"]
    require(observe or sys.argv[1:] in (["check"], ["advance"]), "unknown progress command")
    directory = RAM_OPERATOR if ROOT == RAM_ROOT else OPERATOR
    original = directory/"continuation_dispatch.py"
    expected = EXPECTED_DISPATCH
    if ROOT == RAM_ROOT:
        require(observe, "use the registered RAM retry dispatcher to advance")
        seal = json.loads((directory/"deployment-seal-receipt.json").read_bytes())
        require(seal["destination"]==str(directory), "different RAM retry operator")
        member, = [m for m in seal["members"] if m["name"]==original.name]
        expected = member["sha256"]
    require(hashlib.sha256(original.read_bytes()).hexdigest() == expected, "dispatcher changed")
    sys.path.insert(0, str(directory))
    import continuation_dispatch as dispatch
    if sys.argv[1] == "check":
        print(json.dumps(dispatch.dispatch("check")), flush=True)
        return
    if not observe:
        dispatch.main()
    print(json.dumps(follow(dispatch)), flush=True)


if __name__ == "__main__":
    main()
