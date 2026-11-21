"""Read the normal 168 admission and worker evidence for the sole cadence publisher."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time

ROOT = Path("/var/lib/jetstreamer/horizon_runtime_data")
D = ROOT / "epoch168-full-metered-20261121-v1"
TREE = Path("/home/sol/.jetstreamer-private/epoch168-standard-lane-20261109-v1")
RUN = TREE / "full-metered-20261121-v1"
LOG = RUN / "producer.log"
U = "horizon-qualify-168-full-metered-20261121-v1.service"
GUARD = "horizon-guard-168-full-metered-20261121-v1"
T = GUARD + ".timer"
TRACE = ROOT / "epoch168-terminal-trace-20261121-v1/TERMINAL.json"
PREPARED = "27e3588b8c8a13c8eb4f1dd83133c17a777abbf7d8e8c32960600ac6e0af20d0"
CLOSED = "29672efbaff97d23a9a9d45a824840cb2d4cf43c6f5e8427ed3b532b41a38de2"
CONTROLLER = "b8e8093a3719e99e3cd920fd6cafd742b2be5c408029bf469c66f33b2cb0a95e"
INPUT = "e00db5e753a2cc37af403933f54bcb3216594d1fac3d91cc8984623999295a93"
GIMAGE = "b2271db6f25696612c388297db3a10852f7911560887f67dcb404392d91f7016"
WORKER = "b0219574172b54b251b4f2feda6285ca3b6bee5f2830a0d46e69ee8ea2275541"
OLD = "c081016844dd40c5a78b594bf7ede73a"
PROPERTIES = ("Id,LoadState,ActiveState,SubState,InvocationID,Description,MainPID,StartLimitAction,"
              "ControlPID,ControlGroup,Job,NRestarts,Triggers,TriggeredBy,Result,ExecMainStatus,"
              "MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec")


def need(value, message):
    if not value:
        raise ValueError(message)


def ref(path, sha):
    return {"path": str(path), "sha256": sha}


def read(path, sha=None):
    need(path.is_absolute() and path.resolve(strict=True) == path, f"indirect original {path}")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as f:
        m = os.fstat(f.fileno())
        need(stat.S_ISREG(m.st_mode) and m.st_uid == 0 and not m.st_mode & 0o022
             and m.st_nlink == 1 and 0 < m.st_size <= 64 << 20, f"untrusted original {path}")
        raw = f.read(m.st_size + 1)
        need(len(raw) == m.st_size and os.path.samestat(m, path.stat()) and
             os.fstat(f.fileno()).st_ctime_ns == m.st_ctime_ns, f"replaced original {path}")
    digest = hashlib.sha256(raw).hexdigest()
    need(sha is None or digest == sha, f"different content {path}")
    return json.loads(raw), ref(path, digest)


def bound(reference, path):
    need(reference["path"] == str(path), f"wrong evidence path {path}")
    return read(path, reference["sha256"])[0]


def show(unit):
    raw = subprocess.check_output(["/usr/bin/systemctl", "show", "-p", PROPERTIES, unit],
                                  timeout=10, text=True)
    return dict(line.split("=", 1) for line in raw.splitlines())


def iid(s):
    return isinstance(s, str) and re.fullmatch("[a-f0-9]{32}", s) and int(s, 16)


def process(pid):
    proc = Path("/proc") / str(pid)
    fields = (proc / "stat").read_text().rsplit(")", 1)[1].split()
    return int(fields[1]), int(fields[19]), (proc / "cgroup").read_text().strip()


def same_file(a, b):
    return os.path.samestat(a.stat(), b.stat())


def native_actor(intent, node=False):
    actor = show(U)
    ident = actor["InvocationID"]
    need(actor["Id"] == U and iid(ident) and ident != OLD and actor["ActiveState"] == "active"
         and actor["SubState"] == "running" and actor["Description"] == "guarded-full168-metered-" + intent["token"]
         and actor["ControlGroup"] == "/system.slice/" + U and actor["ControlPID"] == "0"
         and actor["Job"] == "" and actor["NRestarts"] == "0" and actor["CPUQuotaPerSecUSec"] == "9s"
         and actor["MemoryMax"] == str(68 << 30) and actor["MemorySwapMax"] == "0", "different 168 actor")
    pid = int(actor["MainPID"])
    need(pid > 1, "missing normal actor")
    proc = Path("/proc") / str(pid)
    _, ticks, group = process(pid)
    argv = (proc / "cmdline").read_bytes().split(b"\0")[:-1]
    payload = read(D / "inputs-v1/payload.json",
                   "6c56c0cad87c9d22ca72ad8e2cf97cb0cc0c5e1b4d1d01e4f051dfc01875b240")[0]
    normal = [os.fsencode(v) for v in payload["regular_node_argv"]]
    if node:
        need(argv == normal and same_file(proc / "exe", Path(payload["members"]["jetstreamer-node"][0])),
             "normal node has not execed")
    else:
        need(argv == [b"/usr/bin/python3", b"-IB", b"/run/horizon-full168-metered/gate.py", *normal]
             and same_file(proc / "exe", Path("/usr/bin/python3"))
             and same_file(proc / "root/run/horizon-full168-metered/gate.py", D / "controller/gate.py"),
             "different gate image or argv")
    need(group == "0::/system.slice/" + U and same_file(proc / "fd/1", LOG)
         and same_file(proc / "fd/2", LOG) and show(U) == actor and process(pid)[1] == ticks,
         "normal process or append FD changed")
    return actor, dict(producer_unit=U, producer_pid=pid, producer_invocation_id=ident, start_ticks=ticks)


def receipt(actor, planref, worker):
    plan = bound(planref, D / "ACTUAL_GUARD_PLAN.json")
    generation = actor["producer_invocation_id"]
    pid = actor["producer_pid"]
    need(plan["invocation_id"] == generation and plan["unit"] == U and plan["worker_root"] == str(TREE)
         and plan["maximum_root_physical_bytes"] == 288 << 30 and plan["minimum_free_bytes"] >= 8297502499408
         and plan["receipt_directory"] == str(D / "guard-receipts"), "guard bounds differ")
    t, g = show(T), show(GUARD + ".service")
    need(t["Id"] == T and t["ActiveState"] == "active" and t["SubState"] in ("waiting", "running")
         and iid(t["InvocationID"]) and not t["Job"] and t["Triggers"] == GUARD + ".service"
         and g["TriggeredBy"] == T and g["CPUQuotaPerSecUSec"] == "250ms" and g["MemoryMax"] == str(1 << 30)
         and g["MemorySwapMax"] == "0", "different timer or guard budget")
    directory = D / "guard-receipts"
    need(not any(directory.glob("stop-*.json")), "168 guard stopped actor")
    with (D / "guard.stdout").open("rb") as f:
        f.seek(max(0, os.fstat(f.fileno()).st_size - 65536))
        last = next(json.loads(l) for l in reversed(f.read().splitlines()) if l.startswith(b"{"))
    gid = last["guard_invocation_id"]
    need(iid(gid), "bad guard identity")
    sample, original = read(directory / ("sample-" + gid + ".json"))
    p = sample["producer"]
    need(sample == last and sample["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
         and sample["guard_sha256"] == GIMAGE and sample["plan_sha256"] == planref["sha256"]
         and sample["producer_invocation_id"] == p["invocation_id"] == generation and p["pid"] == pid
         and p["cgroup"] == "/system.slice/" + U and p["restarts"] == 0 and p["active"] == "active"
         and p["sub"] == "running" and sample["producer_stop_enabled"] is True and sample["trip_reason"] is None
         and sample["worker_observation_error"] is None and sample["root_physical_observation_error"] is None
         and sample["root_physical_observation"]["exceeds_budget"] is False
         and 0 <= time.time() - sample["recorded_unix_seconds"] <= 90, "wrong or stale 168 guard")
    if worker:
        need(len(sample["workers"]) == 1 and 0 < sample["workers"][0][1] < 3500000, "worker lacks guard")
    events = subprocess.check_output(["/usr/bin/journalctl", "--no-pager", "-ojson",
              "--output-fields=_PID,INVOCATION_ID,UNIT,JOB_RESULT", "_PID=1", "UNIT=" + GUARD + ".service",
              "INVOCATION_ID=" + gid, "-n12"], timeout=10, text=True)
    need(any(json.loads(line).get("JOB_RESULT") == "done" for line in events.splitlines()), "incomplete PID1 guard")
    return dict(receipt=original, timer=t, guard_invocation=gid), sample


def worker_record(actor, planref):
    proof, s = receipt(actor, planref, True)
    pid = s["workers"][0][0]
    owner = actor["producer_pid"]
    parent, ticks, group = process(pid)
    proc = Path("/proc") / str(pid)
    image = (proc / "exe").readlink()
    need(parent == owner and group == "0::/system.slice/" + U and image.name == "historical-worker"
         and image.is_relative_to(RUN / "private") and "scratch" in image.relative_to(RUN / "private").parts
         and same_file(proc / "exe", image), "unexpected normal worker")
    with (proc / "exe").open("rb") as f:
        need(hashlib.file_digest(f, "sha256").hexdigest() == WORKER, "changed historical worker")
    scratch = next(p for p in image.parents if p.name == "scratch")
    log = LOG.stat()
    generation = actor["producer_invocation_id"]
    row = dict(range="168", controller_unit=U, producer_unit=U, scratch_path=str(scratch),
               expected_controller_invocation_id=generation, expected_producer_invocation_id=generation,
               worker_executable_basename="historical-worker",
               append_log=dict(device=log.st_dev, inode=log.st_ino, path=str(LOG)))
    need(process(pid) == (parent, ticks, group) and same_file(Path(f"/proc/{owner}/fd/1"), LOG)
         and show(U)["InvocationID"] == generation, "worker changed during capture")
    return dict(observer_row=row, worker_guard=proof, worker_pid=pid, worker_start_ticks=ticks,
                worker_sha256=WORKER, **actor)


def identity(original, expected):
    need(all(original.get(k) == v for k, v in expected.items()), "different recorded 168 generation")


def classify(intent, actor, admission, promoted):
    """Only a bound normal worker can supply an ordinary replay sampler row."""
    need(intent["prior_trace_terminal"] == ref(TRACE, CLOSED) and intent["prepared"] == ref(D/"PREPARED.json", PREPARED)
         and intent["producer_unit"] == U and intent["timer_unit"] == T and iid(intent["token"]),
         "foreign normal 168 intent")
    if actor is not None:
        need(iid(actor["producer_invocation_id"]) and actor["producer_invocation_id"] != OLD
             and actor["producer_unit"] == U and actor["producer_pid"] > 1 and actor["start_ticks"] > 0,
             "foreign normal 168 process")
    if admission is not None:
        need(actor is not None and admission["bootstrap_only"] is True and admission["transaction_replay_claimed"] is False
             and admission["prior_trace_terminal"] == ref(TRACE, CLOSED) and admission["epoch"] == 168,
             "foreign normal bootstrap")
        identity(admission, actor)
    if promoted is not None:
        need(admission is not None and promoted["worker_sha256"] == WORKER, "orphan 168 worker")
        identity(promoted, actor)
        row = promoted["observer_row"]
        need(row["range"] == "168" and row["producer_unit"] == row["controller_unit"] == U
             and row["expected_producer_invocation_id"] == row["expected_controller_invocation_id"] == actor["producer_invocation_id"]
             and promoted["worker_pid"] != actor["producer_pid"] and promoted["worker_start_ticks"] > 0,
             "different worker observation")
    stage = "protected-worker" if promoted else "protected-bootstrap" if admission else "gated" if actor else "intent"
    return dict(stage=stage, epoch=168, ordinary_canonical=admission is not None,
                actual_active_bootstrap=admission is not None and promoted is None,
                private_diagnostic=False, transaction_replay_claimed=False, resource_credit_bytes=0,
                actor=actor, observer_row=promoted["observer_row"] if promoted else None)


def inspect():
    """Return None before intent. Fail closed on a foreign unit or an expired pending transaction."""
    if not (D / "START_INTENT.json").exists():
        need(show(U)["LoadState"] == "not-found" and not (D / "ACTUAL_ADMISSION_AND_PROTECTION.json").exists(),
             "unregistered normal 168")
        return None
    intent, intentref = read(D / "START_INTENT.json")
    read(TRACE, CLOSED)
    read(D / "PREPARED.json", PREPARED)
    read(D / "controller/deployment-seal-receipt.json", CONTROLLER)
    normal_path = D / "ACTUAL_ADMISSION_AND_PROTECTION.json"
    if not normal_path.exists():
        need(0 <= time.time()-intent["recorded_unix_seconds"] <= 180, "expired 168 start intent")
        if show(U)["LoadState"] == "not-found":
            result = classify(intent, None, None, None)
        else:
            permitted = (D/"barrier/allow").exists()
            # A released gate can be between its last read and exec. Both identities
            # are authenticated and the bounded interval still claims no bootstrap.
            try:
                _, actor = native_actor(intent)
            except ValueError:
                need(permitted, "gate was replaced before permit")
                _, actor = native_actor(intent, node=True)
            if permitted:
                identity(read(D / "AUTHORIZED_GATED_PAYLOAD.json")[0], actor)
                need((D/"barrier/allow").read_bytes() == actor["producer_invocation_id"].encode(), "different permit")
            if (D / "NATIVE_GATED.json").exists():
                gated = read(D / "NATIVE_GATED.json")[0]
                identity(gated, {**actor, "intent": intentref})
            result = classify(intent, actor, None, None)
    else:
        _, actor = native_actor(intent, node=True)
        ad, adref = read(normal_path)
        identity(ad, actor)
        proof, _ = receipt(actor, ad["actual_guard_plan"], False)
        need(ad["timer_invocation_id"] == proof["timer"]["InvocationID"] and ad["timer_unit"] == T
             and ad["input_seal"] == ref(D / "inputs-v1/deployment-seal-receipt.json", INPUT), "wrong bootstrap timer or inputs")
        first = bound(ad["first_guard"], D/"FIRST_GUARD.json")
        need(first["genuine_first_timer_driven_success"] is True and first["producer"]["InvocationID"] == actor["producer_invocation_id"]
             and first["timer"]["InvocationID"] == ad["timer_invocation_id"], "different first guard")
        bound(ad["post_guard_capacity"], D/"POST_GUARD_CAPACITY.json")
        promoted = None
        if (D / "FIRST_PROTECTED_WORKER.json").exists():
            promoted, pref = read(D / "FIRST_PROTECTED_WORKER.json")
            need(promoted["admission"] == adref, "different first worker admission")
            now = worker_record(actor, ad["actual_guard_plan"])
            identity(promoted, {k: v for k, v in now.items() if k != "worker_guard"})
            first_worker = promoted["worker_guard"]
            sid = first_worker["guard_invocation"]
            need(iid(sid), "wrong first worker guard")
            historic = bound(first_worker["receipt"], D/"guard-receipts"/("sample-"+sid+".json"))
            need(historic["guard_invocation_id"] == sid and historic["plan_sha256"] == ad["actual_guard_plan"]["sha256"]
                 and historic["producer_invocation_id"] == actor["producer_invocation_id"]
                 and historic["workers"][0][0] == promoted["worker_pid"], "different first worker guard receipt")
        result = classify(intent, actor, ad, promoted)
        result.update(admission=adref, current_guard=proof, first_worker=pref if promoted else None)
    return dict(result, intent=intentref, prior_trace_terminal=ref(TRACE, CLOSED))
