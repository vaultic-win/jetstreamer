"""Accept a completed pinned pool playback after an unrelated branch change."""

import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from extend_ready_pool import BASE, REPORT_ROOT, load_audit


STANDALONE_GUARD = "jetstreamer-utils/src/horizon_standalone_guard_bin.rs"


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


def recover(audit, cfg, attempt_name):
    match = re.fullmatch(r"([0-9]+)-([0-9]+)-([0-9]+)", attempt_name)
    audit.check(match is not None, "Expected an exact ready-pool attempt name")
    first, last = map(int, match.group(1, 2))
    bounds = [first, last]
    scope_path = BASE / "scope.json"
    scope = audit.read(scope_path)
    handoff = audit.read(BASE / "reader.json")
    audit.check(bounds in handoff["pool_ranges"] and bounds in scope["eligible_ranges"],
                "Attempt is outside the delegated ready pool")
    inventory = audit.ref(REPORT_ROOT.parent / "inventory.json")
    audit.check(inventory["sha256"] == scope["inventory_sha256"], "Frozen inventory changed")
    rows = {r["epoch"]: r for r in scope["objects"]}
    label = f"{first}-{last}"
    destination = BASE / "accepted" / f"{label}.json"
    with (BASE / "pool" / label / "lease").open("rb") as lease:
        try:
            fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SystemExit(f"Ready pool attempt is still leased: {attempt_name}") from None
        if destination.exists():
            prior = audit.read(destination)
            audit.check(prior["schema"] == "horizon-ready-range-verified-v1"
                        and prior["range"] == bounds and prior["scope"] == audit.ref(scope_path)
                        and prior["inventory"] == inventory,
                        "Foreign accepted range")
            return audit.ref(destination)
        attempt = BASE / "attempts" / attempt_name
        reports = REPORT_ROOT / attempt_name
        scope_ref = audit.ref(scope_path)
        start_ref = sealed_ref(audit, attempt / "start.json")
        exit_ref = sealed_ref(audit, attempt / "exit.json")
        start = audit.read(audit.checked_ref(start_ref))
        terminal = audit.read(audit.checked_ref(exit_ref))
        argv = audit.child_argv(cfg, first, last, reports, start["active_cap"])
        log = attempt / "playback.log"
        log_ref = audit.ref(log)
        audit.check(start["argv"] == argv and start["scope"] == scope_ref
                    and start["threads"] == cfg["partitions"]
                    and 1 <= start["active_cap"] <= cfg["max_active"]
                    and start["reader"]["build_commit"] == cfg["built_from"]
                    and start["reader"]["binary"] == cfg["elf"] and start["reader"]["seal"] == cfg["seal"]
                    and start["reader"]["build"] == cfg["proof"] and start["at"] <= terminal["at"]
                    and terminal["code"] == 0 and terminal["reason"] is None and terminal["log"] == log_ref
                    and not audit.canonical(first, last), "Incomplete or foreign pinned playback")
        values = audit.native(rows, first, last, argv, reports, log, cfg["partitions"])
        readiness = audit.confirm_r2(scope, rows, first, last)
        reader = qualify(audit, cfg)
        for bound in (scope_ref, inventory, start_ref, exit_ref, log_ref, *(v["report"] for v in values)):
            audit.checked_ref(bound)
        audit.save(destination, dict(schema="horizon-ready-range-verified-v1", range=bounds,
                   at=audit.now(), scope=scope_ref, inventory=inventory, attempt=attempt_name,
                   method="strict-public-slot-ranges", exit=dict(success=True, receipt=exit_ref),
                   reader=reader, starting_reader=start["reader"], recovered_start=start_ref,
                   invocation=argv, log=log_ref, epochs=values, readiness=readiness,
                   throughput=audit.observed_peak(log)))
        return audit.ref(destination)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("attempt", nargs="?", help="exact finalized pool attempt; omit to check reader equivalence only")
    args = parser.parse_args()
    os.umask(0o077)
    audit = load_audit()
    cfg = audit.config()
    result = recover(audit, cfg, args.attempt) if args.attempt else qualify(audit, cfg)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
