"""Verify newly ready ranges inside the existing idle-only audit slice."""

import fcntl
import hashlib
import importlib.util
import json
from pathlib import Path
import os
import re
import stat
import subprocess
import sys
import time


BASE = Path("/var/lib/jetstreamer/horizon_runtime_data/ready-range-audit-20261121-v1")
REPORT_ROOT = Path("/home/sol/horizon-audit-reports/bucket-slot-ranges-256-20261121-v1/scoped-reports")
PREFLIGHT = "/usr/local/lib/jetstreamer/horizon-ready-output-budget-20261121-v1/prestart.py"
UNIT = "horizon-r2-ready-inventory-extension.service"
INCUMBENTS = {
    "horizon-r2-ready-ranges-101-300-20261121-v1.service": "400000 100000",
    "horizon-r2-ready-parallel-regions-20261121-v1.service": "700000 100000",
}
CONTROLLER_HASH = "5a218dae2974b73e0b792ab33e992ba77d6249bd8b2168ca153f89ee0b676f4b"
INVENTORY_CODE_HASH = "3d40989043f264d62d949c63f22e8b9f2f930ebbd30e645a9b6b1953282cf489"


STANDALONE_GUARD = "jetstreamer-utils/src/horizon_standalone_guard_bin.rs"


def load_audit():
    controller = BASE / "ready-controller.py"
    for path, expected in ((controller, CONTROLLER_HASH), (BASE / "qualify-ready.py", INVENTORY_CODE_HASH)):
        meta = path.lstat()
        if meta.st_uid != 0 or meta.st_mode & 0o022 or path.resolve(strict=True) != path:
            raise ValueError(f"Untrusted audit code {path}")
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError(f"Unqualified audit code {path}")
    spec = importlib.util.spec_from_file_location("ready_audit", controller)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sealed_ref(audit, path):
    md = path.lstat()
    audit.check(path.resolve(strict=True) == path and stat.S_ISREG(md.st_mode)
                and md.st_uid == 0 and not md.st_mode & 0o222,
                f"Unsealed audit evidence {path}")
    return audit.ref(path)


def qualify(audit, cfg):
    try:
        return audit.current_branch(cfg)
    except audit.ReaderChanged as error:
        tip, changed = error.args
        audit.check(re.fullmatch(r"[0-9a-f]{40}", tip) and changed == [STANDALONE_GUARD],
                    f"Current branch has unqualified reader changes: {changed}")
    evidence = sealed_ref(audit, BASE / f"COMPILED_INPUT_COMPARISON_{tip[:12]}.json")
    comparison = audit.read(audit.checked_ref(evidence))
    proof = audit.read(audit.checked_ref(cfg["proof"]))
    sources = audit.read(audit.checked_ref(cfg["sources"]))["members"]
    audit.check(comparison["schema"] == "horizon-live-audit-compiled-input-comparison-v1"
                and comparison["fetched_account_updates"] == tip
                and comparison["compiled_from"] == proof["source_commit"] == cfg["built_from"]
                and comparison["source_manifest"] == cfg["sources"]
                and comparison["manifest_members"] == len(sources)
                and comparison["matching_members"] == len(sources) - 1
                and STANDALONE_GUARD in sources
                and comparison["only_changed_path"] == STANDALONE_GUARD
                and comparison["changed_path_present_in_native_depinfo"] is False
                and comparison["pipeline"] == cfg["elf"]
                and comparison["original_cargo_artifacts"] == proof["compiler_artifacts"],
                "Compiled input comparison does not qualify this reader and branch")
    audit.checked_ref(comparison["original_cargo_artifacts"])
    depinfo = audit.checked_ref(comparison["depinfo"])
    audit.check(STANDALONE_GUARD.encode() not in depinfo.read_bytes(),
                "Standalone guard was a compiled reader input")
    return dict(branch_commit=tip, build_commit=cfg["built_from"], build=cfg["proof"],
                binary=cfg["elf"], seal=cfg["seal"], observed=audit.now(),
                source_fingerprint=proof.get("source_fingerprint"), compiled_input_comparison=evidence)


def inputs(audit, delta):
    audit.check(delta.parent == REPORT_ROOT and delta.resolve(strict=True) == delta,
                "Extension is outside the bounded reports mount")
    inventory = delta / "inventory.json"
    scope_file = delta / "AUTHENTICATED_RECHECK.json"
    initial = audit.read(BASE / delta.name / "scope.json")
    original = audit.read(audit.checked_ref(initial["original"]))
    scope = audit.read(scope_file)
    rows = {row["epoch"]: row for row in scope["objects"]}
    audit.check(initial["schema"] == "horizon-ready-delta-audit-scope-v1"
                and scope["schema"] == "horizon-ready-strict-audit-scope-v1"
                and scope["scope"] == original["scope"] == [101, 300]
                and scope["bucket"] == initial["bucket"] == original["bucket"]
                and audit.sha(inventory) == initial["inventory"]["sha256"] == scope["inventory_sha256"]
                and scope["objects"] == initial["objects"]
                and len(rows) == len(scope["objects"])
                and all(row["ready"] for row in rows.values())
                and scope["eligible_ranges"] == initial["eligible_ranges"] == audit.READY.ranges(rows)
                and set(rows).isdisjoint(row["epoch"] for row in original["objects"] if row["ready"]),
                "Extension scope or pinned archive identity differs")
    return scope, rows, audit.ref(scope_file), audit.ref(inventory)


def limits(audit, require_own_group):
    group = audit.CG
    expected = {"cpu.max": "1200000 100000", "cpu.idle": "1", "memory.high": str(20 << 30),
                "memory.max": str(24 << 30), "memory.swap.max": "0", "pids.max": "512"}
    audit.check(all((group / name).read_text().strip() == value for name, value in expected.items()),
                "Shared audit limits changed")
    units = {path.name for path in group.iterdir() if path.is_dir()}
    audit.check(units <= INCUMBENTS.keys() | {UNIT}, "Unpriced audit actor in the shared slice")
    for unit in units & INCUMBENTS.keys():
        audit.check((group / unit / "cpu.max").read_text().strip() == INCUMBENTS[unit],
                    f"Incumbent CPU quota changed for {unit}")
    if require_own_group:
        audit.check(Path("/proc/self/cgroup").read_text().strip() == f"0::/{group.name}/{UNIT}",
                    "Extension is outside its systemd allocation")
        expected = {"cpu.max": "100000 100000", "memory.max": str(2 << 30),
                    "memory.swap.max": "0", "pids.max": "32"}
        audit.check(all((group / UNIT / name).read_text().strip() == value for name, value in expected.items()),
                    "Extension limits changed")
    return int((group / "memory.current").read_text())


def extension_argv(audit, cfg, bounds, reports, inventory_ref):
    audit.check(cfg["partitions"] == 256 and cfg["limit_arg"] == "--max-active-partitions",
                "Extension needs the qualified 256-partition reader")
    args = audit.child_argv(cfg, *bounds, reports, 1)
    args[args.index("--archive-inventory") + 1] = inventory_ref["path"]
    return args


def accept(audit, cfg, scope, rows, scope_ref, inventory_ref, bounds, attempt, destination):
    first, last = bounds
    start_ref = sealed_ref(audit, attempt / "start.json")
    exit_ref = sealed_ref(audit, attempt / "exit.json")
    start = audit.read(audit.checked_ref(start_ref))
    terminal = audit.read(audit.checked_ref(exit_ref))
    reports = attempt / "reports"
    log = attempt / "playback.log"
    log_ref = audit.ref(log)
    args = extension_argv(audit, cfg, bounds, reports, inventory_ref)
    audit.check(start["argv"] == args and start["scope"] == scope_ref and start["range"] == bounds
                and start["inventory"] == inventory_ref and start["at"] <= terminal["at"]
                and start["reader"]["build_commit"] == cfg["built_from"]
                and start["reader"]["binary"] == cfg["elf"] and start["reader"]["seal"] == cfg["seal"]
                and start["reader"]["build"] == cfg["proof"] and terminal["code"] == 0
                and terminal["reason"] is None and terminal["log"] == log_ref
                and not audit.canonical(first, last), "Incomplete or foreign extension playback")
    values = audit.native(rows, first, last, args, reports, log, cfg["partitions"])
    fresh = audit.confirm_r2(scope, rows, first, last)
    current = qualify(audit, cfg)
    for bound in (scope_ref, inventory_ref, start_ref, exit_ref, log_ref, *(v["report"] for v in values)):
        audit.checked_ref(bound)
    audit.save(destination, dict(schema="horizon-ready-range-verified-v1", range=bounds,
               at=audit.now(), scope=scope_ref, inventory=inventory_ref, method="strict-public-slot-ranges",
               exit=dict(success=True, receipt=exit_ref), reader=current, starting_reader=start["reader"],
               start=start_ref, invocation=args, log=log_ref, epochs=values, readiness=fresh,
               throughput=audit.observed_peak(log)))
    return audit.ref(destination)


def recover(audit, delta, scope, rows, scope_ref, inventory_ref, name):
    match = re.fullmatch(r"run-([0-9]+)-([0-9]+)-[0-9]+", name)
    audit.check(match is not None, "Expected an exact extension attempt name")
    bounds = list(map(int, match.groups()))
    audit.check(bounds in scope["eligible_ranges"], "Attempt is outside the extension scope")
    label = f"{bounds[0]}-{bounds[1]}"
    destination = delta / f"verified-{label}.json"
    with (delta / f"{label}.lock").open("rb") as lease:
        try:
            fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SystemExit(f"Extension attempt is still leased: {name}") from None
        if destination.exists():
            prior = audit.read(destination)
            audit.check(prior["schema"] == "horizon-ready-range-verified-v1"
                        and prior["range"] == bounds and prior["scope"] == scope_ref
                        and prior["inventory"] == inventory_ref, "Foreign existing extension acceptance")
            return audit.ref(destination)
        return accept(audit, audit.config(), scope, rows, scope_ref, inventory_ref,
                      bounds, delta / name, destination)


def verify(audit, delta, scope, rows, scope_ref, inventory_ref, bounds):
    first, last = bounds
    lease_name = f"{first}-{last}"
    with (delta / f"{lease_name}.lock").open("a") as lease:
        fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        destination = delta / f"verified-{lease_name}.json"
        if destination.exists():
            prior = audit.read(destination)
            audit.check(prior["range"] == bounds and prior["scope"] == scope_ref
                        and prior["inventory"] == inventory_ref, "Foreign existing acceptance")
            return
        cfg = audit.config()
        reader = qualify(audit, cfg)
        audit.confirm_r2(scope, rows, first, last)
        audit.check(limits(audit, True) < 15 << 30 and not audit.canonical(first, last),
                    "Extension needs free decoder memory and a disjoint range")
        attempt = delta / f"run-{lease_name}-{time.time_ns()}"
        attempt.mkdir()
        attempt.chmod(0o755)
        reports = attempt / "reports"
        reports.mkdir(mode=0o700)
        os.chown(reports, audit.ACCOUNT.pw_uid, audit.ACCOUNT.pw_gid)
        args = extension_argv(audit, cfg, bounds, reports, inventory_ref)
        env = {"HOME": "/home/sol", "PATH": "/usr/bin:/bin", "TMPDIR": str(reports),
               "TOKIO_WORKER_THREADS": "2", "RAYON_NUM_THREADS": "1",
               "RUST_LOG": "info,jetstreamer_horizon_range=debug",
               "RUST_MIN_STACK": "67108864", "MALLOC_ARENA_MAX": "2",
               "MALLOC_CONF": "narenas:2,dirty_decay_ms:0,muzzy_decay_ms:0,background_thread:true,tcache_max:8192"}
        log = attempt / "playback.log"
        reason = None
        with log.open("xb") as output:
            process = subprocess.Popen(args, stdout=output, stderr=output, env=env,
                                       user=audit.ACCOUNT.pw_uid, group=audit.ACCOUNT.pw_gid, extra_groups=[])
            try:
                audit.save(attempt / "start.json", dict(at=audit.now(), range=bounds, pid=process.pid,
                           reader=reader, argv=args, scope=scope_ref, inventory=inventory_ref))
                audit.save(delta / "status.json", dict(phase="streaming", range=bounds, pid=process.pid,
                           at=audit.now(), log=str(log), active_partitions=1, partitions=256))
                while process.poll() is None:
                    if limits(audit, True) >= 16 << 30 or audit.canonical(first, last):
                        reason = "audit_guard"
                        break
                    time.sleep(5)
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
        exit_file = attempt / "exit.json"
        audit.save(exit_file, dict(at=audit.now(), code=process.returncode, reason=reason,
                   log=audit.ref(log), throughput=audit.observed_peak(log)))
        audit.check(process.returncode == 0 and reason is None,
                    f"Playback interrupted; integrity unconfirmed; see {exit_file}")
        accept(audit, cfg, scope, rows, scope_ref, inventory_ref, bounds, attempt, destination)


def main():
    os.umask(0o077)
    action, path, *attempt = sys.argv[1:]
    if action not in ("check", "run", "recover") or len(attempt) != int(action == "recover"):
        raise ValueError("Expected check PATH, run PATH, or recover PATH ATTEMPT")
    delta = Path(path)
    audit = load_audit()
    scope, rows, scope_ref, inventory_ref = inputs(audit, delta)
    if action == "recover":
        print(json.dumps(recover(audit, delta, scope, rows, scope_ref, inventory_ref, attempt[0]), sort_keys=True))
        return
    subprocess.run(["/usr/bin/python3", "-IB", PREFLIGHT], check=True, timeout=15)
    usage = limits(audit, action == "run")
    audit.check(usage < 15 << 30, "Shared decoder memory unavailable")
    if action == "check":
        print(dict(reader=qualify(audit, audit.config())["branch_commit"],
                   ranges=scope["eligible_ranges"], shared_memory_bytes=usage))
        return
    failures = []
    for bounds in scope["eligible_ranges"]:
        try:
            verify(audit, delta, scope, rows, scope_ref, inventory_ref, bounds)
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            failures.append(dict(range=bounds, detail=str(error)))
    audit.save(delta / "status.json", dict(phase="incomplete" if failures else "complete",
               at=audit.now(), failures=failures))
    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
