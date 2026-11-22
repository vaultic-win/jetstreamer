"""Continue the ready-range audit with the original 0–100 inventory after its funded handoff."""
import argparse
import contextlib
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

DATA = Path("/var/lib/jetstreamer/horizon_runtime_data/ready-range-audit-20261121-v1")
HOME = Path("/home/sol/.jetstreamer-private")
OLD = HOME / "public-0-100-tps-20261120/run-global-slot-partitions-compact-v3"
SCOPE = HOME / "reconcile-0-100-20261122/live-r2.json"
INVENTORY = OLD / "inventory.json"
REFERENCE = OLD / "evidence/comparison.json"
CG = Path("/sys/fs/cgroup/horizonaudit.slice")
UNIT = "horizon-public-0-100-current-20261122-v1.service"
OLD_UNITS = ("horizon-r2-fast-ranges-256-20261121-v1.service",
             "horizon-r2-ready-ranges-101-300-20261121-v1.service",
             "horizon-r2-ready-parallel-regions-20261121-v1.service")
FORMER_SCOPE = "5be8c088182bcff1fc1e39a09000060e88da4c825537c9d9d934283719545d43"
DIGESTS = {DATA / "ready-controller.py": "5a218dae2974b73e0b792ab33e992ba77d6249bd8b2168ca153f89ee0b676f4b",
           DATA / "qualify-ready.py": "3d40989043f264d62d949c63f22e8b9f2f930ebbd30e645a9b6b1953282cf489",
           SCOPE: "bfb489d9a1eecae1013a3ecec6a568417401f6e9dc994ea02f5f045d51e2fa82",
           INVENTORY: "733a88ba5c153259035e199df7107ce5ec1816b212e35fd0dacdb8be5681528d",
           REFERENCE: "642d0f5496b2d0480a0ac646fde0acca5b34107d50fc1b5af356f20abbc6ce1f",
           DATA / "scope.json": FORMER_SCOPE}
STATE = DATA / "attempts" / "history-0-100"
FINAL = STATE / "accepted.json"


def require(ok, message):
    if not ok:
        raise ValueError(message)


def tools():
    for path, digest in DIGESTS.items():
        require(path.resolve(strict=True) == path, f"noncanonical evidence path {path}")
        with path.open("rb") as file:
            require(hashlib.file_digest(file, "sha256").hexdigest() == digest, f"changed {path}")
    spec = importlib.util.spec_from_file_location("ready", DATA / "ready-controller.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def identities(a):
    scope = a.read(SCOPE)
    rows = {r["epoch"]: r for r in scope["objects"]}
    inventory = a.read(INVENTORY)
    require(scope["eligible_ranges"] == [[0, 100]] and scope["scope"] == [0, 100]
            and len(scope["objects"]) == 101 and not scope["staged"]
            and scope["inventory_sha256"] == DIGESTS[INVENTORY], "wrong history scope")
    require([rows[n]["object"] for n in range(101)] == inventory["objects"]
            and all(rows[n]["ready"] for n in range(101)), "wrong history identities")
    return scope, rows


def outstanding(a):
    prior = a.read(DATA / "scope.json")
    ranges = prior["eligible_ranges"]
    require(sum(hi-lo+1 for lo, hi in ranges) == 104 and len(ranges) == 12, "wrong predecessor")
    remaining = []
    for lo, hi in ranges:
        path = DATA / "accepted" / f"{lo}-{hi}.json"
        if not path.exists():
            remaining.append([lo, hi])
            continue
        result = a.read(path)
        require(result["schema"] == "horizon-ready-range-verified-v1"
                and result["range"] == [lo, hi] and result["scope"] == a.ref(DATA / "scope.json")
                and result["exit"]["success"] and result["method"] == "strict-public-slot-ranges"
                and [row["epoch"] for row in result["epochs"]] == list(range(lo, hi+1)),
                f"invalid predecessor {path}")
    return remaining


def compare(rows):
    reference = json.loads(REFERENCE.read_bytes())["epochs"]
    require(len(rows) == len(reference) == 101, "incomplete independent comparison")
    for i, (row, old) in enumerate(zip(rows, reference, strict=True)):
        counts = row["counters"]
        require(row["epoch"] == old["epoch"] == i and bytes(counts["stream_digest"]).hex() == old["stream_digest"]
                and all(counts[k] == v for k, v in old["counters"].items()), f"historical transcript differs at {i}")


def command(a, cfg, reports):
    args = a.child_argv(cfg, 0, 100, reports, 4)
    index = args.index("--archive-inventory") + 1
    args[index] = str(INVENTORY)
    require(cfg["partitions"] == 256 and cfg["max_active"] == 4
            and args[1:3] == ["0:100", a.SOURCE], "wrong consumer or partition envelope")
    return args


def other_readers():
    conflicts = []
    for proc in Path("/proc").iterdir():
        if not proc.name.isdecimal():
            continue
        try:
            if (proc / "exe").readlink().name != "horizon_pipeline":
                continue
            args = (proc / "cmdline").read_bytes().split(b"\0")
        except (FileNotFoundError, ProcessLookupError):
            continue
        require(len(args) > 2, "unclassified Horizon reader")
        match = re.fullmatch(rb"(\d+)(?::(\d+))?", args[1])
        require(match is not None, "unclassified Horizon range")
        if int(match[1]) <= 100:
            conflicts.append([int(proc.name), os.fsdecode(args[1])])
    return conflicts


def donor_groups():
    active = []
    for unit in OLD_UNITS:
        path = CG / unit / "cgroup.procs"
        if path.exists() and path.read_text().strip():
            active.append(unit)
    return active


def envelope():
    group = CG / UNIT
    require(Path("/proc/self/cgroup").read_text().strip() == f"0::/horizonaudit.slice/{UNIT}", "unregistered cgroup")
    for path, cpu, high, maximum, tasks in [(group, 4, 14, 16, 448), (CG, 12, 20, 24, 512)]:
        quota, period = map(int, (path / "cpu.max").read_text().split())
        require(quota == cpu * period and int((path / "memory.high").read_text()) == high << 30
                and int((path / "memory.max").read_text()) == maximum << 30
                and int((path / "pids.max").read_text()) == tasks
                and (path / "memory.swap.max").read_text().strip() == "0", "cgroup envelope changed")


def verify_prior_trace(a, rows):
    saved = a.read(OLD / "evidence/reader.json")
    argv = saved["reader_argv"]
    results = a.native(rows, 0, 100, argv, OLD / "reports", OLD / "playback.log", 256)
    compare(results)
    return len(results), sum(r["counters"]["slots"] for r in results)


@contextlib.contextmanager
def monitor(a, attempt):
    """Start the existing passive probe after its v2 owner releases the original scopes."""
    script = Path(__file__).resolve().with_name("passive_http.py")
    require(a.sha(script) == "526c597cde655e542da103c331f4045ffe459d718c504a6c1e4dd92e79715826",
            "history HTTP observer source changed")
    invocation = os.environ["INVOCATION_ID"]
    require(re.fullmatch(r"[0-9a-f]{32}", invocation) is not None, "missing systemd invocation")
    root = DATA / "http-observability-v2" / "history-0-100"
    started = root / ("monitor-" + invocation)
    with (attempt / "http-observer.log").open("xb") as log:
        proc = subprocess.Popen(["/usr/bin/python3", "-IB", str(script)], stdout=log, stderr=log)
    try:
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            require(proc.poll() is None, "HTTP observer startup failed")
            if (started / "handover.json").exists() and (started / "attached.json").exists():
                attached = a.read(started / "attached.json")
                require(attached["scope"] == [UNIT] and attached["program_sha256"] == a.sha(script),
                        "HTTP observer has a different scope")
                break
            time.sleep(1)
        else:
            raise ValueError("HTTP observer awaits its predecessor")
        yield proc
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=12)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        final = started / "final.json"
        if final.exists():
            a.save(attempt / "http.json", dict(monitor=invocation, final=a.ref(final)))


def play(a, scope, rows, cfg):
    envelope()
    require(not outstanding(a), "ready 101–300 receipts still pending")
    # The last accepted receipt precedes normal service and monitor exit by a few seconds.
    while donor_groups() or not a.read(DATA / "http-observability-v2/latest.json").get("queue_complete"):
        time.sleep(5)
    require(not other_readers(), "historical range already owned")
    STATE.mkdir(exist_ok=True, mode=0o700)
    with contextlib.ExitStack() as locks:
        # Hold the original managers' nonblocking locks throughout the handoff.
        for path in (*[DATA / name for name in ("controller.lock", "pool/coordinator.lock")], STATE / "lease"):
            fd = locks.enter_context(path.open("a"))
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if FINAL.exists():
            prior = a.read(FINAL)
            require(prior["schema"] == "horizon-history-reverification-v1" and prior["range"] == [0, 100]
                    and prior["inventory"] == a.ref(INVENTORY)
                    and prior["reader"]["binary"] == cfg["elf"] and prior["scope"] == a.ref(SCOPE)
                    and len(prior["epochs"]) == 101, "previous history receipt differs")
            return a.ref(FINAL)
        require(not other_readers(), "another historical reader owns this range")
        start = a.current_branch(cfg)
        a.confirm_r2(scope, rows, 0, 100)
        name = "history-0-100-" + str(time.time_ns())
        attempt = STATE / name
        attempt.mkdir(mode=0o700)
        reports = a.OUT / "scoped-reports" / name
        a.public_run(["/bin/mkdir", str(reports)])
        argv = command(a, cfg, reports)
        log = attempt / "playback.log"
        env = dict(HOME="/home/sol", PATH="/usr/bin:/bin", TMPDIR=str(reports), TOKIO_WORKER_THREADS="2",
                   RAYON_NUM_THREADS="1", RUST_LOG="info,jetstreamer_horizon_range=debug", MALLOC_ARENA_MAX="2",
                   MALLOC_CONF="narenas:2,dirty_decay_ms:0,muzzy_decay_ms:0,background_thread:true,tcache_max:8192")
        with monitor(a, attempt) as observer, log.open("xb") as file:
            proc = subprocess.Popen(argv, stdout=file, stderr=file, user=a.ACCOUNT.pw_uid,
                                    group=a.ACCOUNT.pw_gid, extra_groups=[], env=env)
            reason = None
            try:
                a.save(attempt / "start.json", dict(at=a.now(), pid=proc.pid, argv=argv, reader=start,
                                                     scope=a.ref(SCOPE), inventory=a.ref(INVENTORY)))
                while proc.poll() is None:
                    if observer.poll() is not None:
                        reason = "http-observer-exited"
                        break
                    if int((CG / "memory.current").read_text()) >= 18 << 30 or int((CG / UNIT / "memory.current").read_text()) >= 16 << 30:
                        reason = "memory-guard"
                        break
                    time.sleep(2)
            finally:
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=8)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait()
            a.save(attempt / "exit.json", dict(at=a.now(), code=proc.returncode, reason=reason, log=a.ref(log)))
        if proc.returncode and reason is None:
            with log.open("rb") as file:
                file.seek(0, 2)
                file.seek(max(0, file.tell() - 65536))
                tail = file.read().decode(errors="replace").lower()
            if any(marker in tail for marker in ("connection reset", "unexpected eof", "error sending request",
                                                  "http 429", "http 503", "timed out", "body error")):
                raise SystemExit(75)
        require(proc.returncode == 0 and reason is None, f"unsuccessful playback; retained evidence {attempt}")
        results = a.native(rows, 0, 100, argv, reports, log, 256)
        compare(results)
        a.confirm_r2(scope, rows, 0, 100)
        end = a.current_branch(cfg)
        monitor_receipt = a.read(attempt / "http.json")
        observed = a.read(a.checked_ref(monitor_receipt["final"]))
        own = [r for r in observed["readers"].values() if r["range"] == "0:100" and r["pid"] == proc.pid]
        require(len(own) == 1 and own[0]["binary_sha256"] == cfg["elf"]["sha256"] and own[0]["responses"] > 0,
                "missing passive reader enrollment")
        a.save(FINAL, dict(schema="horizon-history-reverification-v1", range=[0, 100], at=a.now(),
                           scope=a.ref(SCOPE), inventory=a.ref(INVENTORY), reader=end, predecessor=a.ref(DATA/"scope.json"),
                           epochs=results, invocation=argv, log=a.ref(log), historical_comparison=a.ref(REFERENCE),
                           http_monitor=a.ref(attempt/"http.json"), start=a.ref(attempt/"start.json"), exit=a.ref(attempt/"exit.json"), throughput=a.observed_peak(log)))
        return a.ref(FINAL)


def ready(a):
    return not FINAL.exists() and not outstanding(a)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("qualify", "ready", "play"))
    args = parser.parse_args()
    os.umask(0o077)
    a = tools()
    if args.action == "ready":
        sys.exit(0 if ready(a) else 1)
    scope, rows = identities(a)
    cfg = a.config()
    if args.action == "play":
        print(json.dumps(play(a, scope, rows, cfg)))
        return
    branch = a.current_branch(cfg)
    historical, slots = verify_prior_trace(a, rows)
    print(json.dumps(dict(at=a.now(), branch=branch, historical_reports=historical, historical_slots=slots,
                          current_image_history_reports=0 if not FINAL.exists() else len(a.read(FINAL)["epochs"]),
                          remaining_predecessor_ranges=outstanding(a), predecessor_groups=donor_groups(),
                          historical_live_readers=other_readers(), scope=a.ref(SCOPE), inventory=a.ref(INVENTORY),
                          invocation_example=command(a, cfg, a.OUT/"scoped-reports/ATTEMPT"),
                          accepted_path=str(FINAL), public_object_requests_during_qualification=0), indent=2))


if __name__ == "__main__":
    main()
