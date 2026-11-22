"""Prove the canonical source of the ready-range audit workers for cold epoch 130."""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

BASE = Path("/var/lib/jetstreamer/horizon_runtime_data")
TOOLS = BASE / "ready-idle-cpu-20261121-v1/cadence-tools"
READY = BASE / "ready-range-audit-20261121-v1"
REPORTS = Path("/home/sol/horizon-audit-reports/bucket-slot-ranges-256-20261121-v1")
ORIGIN = "https://pub-e7795f13d2d04a5f829e49e8f3ef3011.r2.dev"
CANONICAL = {"epoch": 130, "key": "epoch-130.jet", "bytes": 83405061082,
             "etag": '"73d501e604900b1c9a079d9453459a52-1243"'}
CANONICAL_SHA = "8cb4493da4e67528aea3038915be428b1039218a1dbdaa6a6544a743894475ff"
PROFILES = {
    "active-reader.json": "412f73becbfe6cf40d53724aec951df0ecc013248eb061936a9bdb76b4a2dd31",
    "legacy-reader.json": "600f1332b0449adf5edc146049ff5c4b1dd18893cab15f763a6554af8ac109f6",
}
MODULES = {"ready_audit_jobs.py": "58f441f4cc1f2ead90f926026e813e0737b962353ef91af8445524da29f7699d",
           "evidence.py": "64cf122f5ef5651da18b66a2d6a262201f0ea60fba5bf1b1b80b657d3d528912"}


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def read(path, digest):
    p = Path(path)
    before = p.lstat()
    require(p.resolve(strict=True) == p and stat.S_ISREG(before.st_mode) and
            before.st_uid == 0 and before.st_nlink == 1 and not before.st_mode & 0o022 and
            before.st_size < 64 << 20, "invalid metadata custody: " + str(p))
    data = p.read_bytes()
    after = p.lstat()
    require(hashlib.sha256(data).hexdigest() == digest and before.st_ino == after.st_ino and
            before.st_dev == after.st_dev and before.st_ctime_ns == after.st_ctime_ns,
            "metadata changed or digest differs: " + str(p))
    return data


def document(ref):
    return json.loads(read(ref["path"], ref["sha256"]))


def check_args(row, argv, profile):
    first, last = row["range"]
    threads = profile["partitions"]
    expected = [profile["elf"]["path"], f"{first}:{last}", ORIGIN, "--verify-only",
                "--slot-ranges", "--threads", str(threads)]
    limit = profile["limit_arg"]
    active = row["max_active_partitions"]
    if limit:
        require(type(active) is int and 1 <= active <= profile["max_active"], "invalid active partition cap")
        expected.extend([limit, str(active)])
    expected.extend(["--archive-inventory", str(REPORTS / "inventory.json"), "--verification-report-dir"])
    require(argv[:-1] == expected and row["reader"] == argv[0] and row["partitions"] == threads and
            (bool(limit) or active is None),
            "unrecognized reader mode, source or inventory")
    output = Path(argv[-1])
    require(output.is_relative_to(REPORTS) and ".." not in output.parts and output != REPORTS,
            "unrecognized output root")


def accepted_regions(audit, scope_ref, inventory_ref):
    regions = []
    for ref in audit["summary"]["accepted_ranges"]:
        receipt = document(ref)
        lo, hi = receipt["range"]
        require(type(lo) is int and type(hi) is int and 101 <= lo <= hi <= 300 and
                ref["path"] == str(READY / "accepted" / f"{lo}-{hi}.json") and
                receipt["schema"] == "horizon-ready-range-verified-v1" and
                receipt["method"] == "strict-public-slot-ranges" and receipt["scope"] == scope_ref and
                receipt["inventory"] == inventory_ref and
                [row["epoch"] for row in receipt["epochs"]] == list(range(lo, hi+1)),
                "foreign completed ready region")
        if lo <= 130 <= hi:
            require(receipt["epochs"][130-lo]["object"] == CANONICAL,
                    "completed reader used another epoch 130 source")
        regions.append([lo, hi])
    return regions


def complete_population(active, completed, scope, summary):
    passed = sum(hi-lo+1 for lo, hi in completed)
    count = sum(hi-lo+1 for lo, hi in scope["eligible_ranges"])
    require(sorted(active + completed) == sorted(scope["eligible_ranges"]) and
            len({tuple(region) for region in active + completed}) == len(scope["eligible_ranges"]) and
            summary["passed"] == passed and summary["archives"] == count and
            summary["pending"] == count - passed and summary["failed"] == 0 and
            summary["complete"] is (count == passed), "incomplete ready reader population")


def main(fleet_path, fleet_sha):
    for name, digest in MODULES.items():
        read(TOOLS / name, digest)
    sys.path.insert(0, str(TOOLS))
    from ready_audit_jobs import native_jobs

    fleet_ref = {"path": fleet_path, "sha256": fleet_sha}
    fleet = document(fleet_ref)
    current = fleet["current_audit_child"]["observation"]
    audit = document(current)
    ready = fleet["active_ready_range_audit_obligation"]
    require(ready["current_observation"] == current and audit["child"] is None and
            audit["chronological_retirement"] == ready["chronological_retirement"], "different audit generation")
    retirement = document(audit["chronological_retirement"])
    scope_ref = audit["inventory"]
    require(retirement["scope"] == scope_ref and retirement["schema"] == "horizon-chronological-retirement-to-ready-range-v1" and
            retirement["legacy"]["ActiveState"] == "inactive" and retirement["legacy"]["MainPID"] == "0" and
            scope_ref["path"] == str(READY / "scope.json"), "unproven prior audit stop or scope")
    scope = document(scope_ref)
    require(scope["schema"] == "horizon-ready-strict-audit-scope-v1" and
            scope["bucket"] == "solana-archive-with-accounts-data", "foreign scope")
    matches = [r for r in scope["objects"] if r["epoch"] == 130]
    require(len(matches) == 1 and matches[0]["ready"] is True and matches[0]["object"] == CANONICAL and
            matches[0]["archive_sha256"] == CANONICAL_SHA, "foreign scoped epoch 130")
    inventory = REPORTS / "inventory.json"
    public = json.loads(read(inventory, scope["inventory_sha256"]))
    require(public["bucket"] == scope["bucket"] and [r for r in public["objects"] if r["epoch"] == 130] == [CANONICAL],
            "canonical public inventory differs")
    profiles = [json.loads(read(READY / name, digest)) for name, digest in PROFILES.items()]
    by_exe = {v["elf"]["path"]: v for v in profiles}
    jobs = native_jobs(scope_ref)
    require(jobs == audit["active_ready_workers"] and len({r["pid"] for r in jobs}) == len(jobs),
            "native ready reader identities differ from the accepted fleet")
    inventory_ref = {"path": str(inventory), "sha256": scope["inventory_sha256"]}
    completed = accepted_regions(audit, scope_ref, inventory_ref)
    complete_population([j["range"] for j in jobs], completed, scope, audit["summary"])
    worker_proofs = []
    for row in jobs:
        proc = Path("/proc") / str(row["pid"])
        stat_text = (proc / "stat").read_text().rsplit(")", 1)[1].split()
        require(int(stat_text[19]) == row["start_ticks"], "worker PID reused")
        command = (proc / "cmdline").read_bytes()
        argv = command.split(b"\0")
        require(argv.pop() == b"", "unterminated argv")
        argv = [os.fsdecode(arg) for arg in argv]
        check_args(row, argv, by_exe[row["reader"]])
        exe = Path(row["reader"])
        require(exe.resolve(strict=True) == exe and exe.stat().st_uid == 0 and not exe.stat().st_mode & 0o022 and
                os.path.samefile(proc / "exe", exe) and os.path.samefile(proc / "root" / inventory.relative_to("/"), inventory),
                "worker binary or mount-namespace inventory differs")
        require((proc / "cmdline").read_bytes() == command, "worker arguments changed across closure")
        worker_proofs.append(dict(row, image_inode=exe.stat().st_ino, inventory_inode=inventory.stat().st_ino,
                                  argv_sha256=hashlib.sha256(command).hexdigest()))
    require(native_jobs(scope_ref) == jobs, "ready workers changed across closure")
    return {"schema": "cold130-ready-audit-reader-proof-v1", "fleet": fleet_ref, "audit": current,
            "retirement": audit["chronological_retirement"], "scope": scope_ref,
            "inventory": inventory_ref, "accepted_ranges": audit["summary"]["accepted_ranges"],
            "readers": worker_proofs, "canonical_object": CANONICAL, "source_body_bytes_read": 0,
            "resource_credit_bytes": 0, "retirement_authorized": False}


if __name__ == "__main__":
    require(len(sys.argv) == 3 and sys.flags.isolated and sys.dont_write_bytecode, "run python3 -IB with fleet and digest")
    print(json.dumps(main(*sys.argv[1:]), sort_keys=True))
