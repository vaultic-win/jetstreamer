"""Accept a completed pinned pool playback after an unrelated branch change."""

import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from extend_ready_pool import BASE, REPORT_ROOT, load_audit, qualify, sealed_ref


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
