"""Exercise every local-completion report location against a real 19-epoch report."""
import json
from itertools import combinations
from pathlib import Path
import sys

import terminal_event as event


def write(path, value):
    path.write_text(json.dumps(value))
    path.chmod(0o600)
    return event.document(path, 0o600)[1]


def qualify(source, scratch):
    fleet, _ = event.document(source, 0o600)
    report, original = event.document(Path(fleet["authenticated_status_audit"]["path"]), 0o600)
    assert original == fleet["authenticated_status_audit"]
    runtime = scratch / "runtime"
    reports = scratch / "reports"
    cycle = runtime / source.parent.name
    base = reports / Path(original["path"]).parent.name
    cycle.mkdir(parents=True)
    base.mkdir(parents=True)
    labels = event.report_labels()
    fields = {n: label + "_local_commit" for n, label in labels.items()}
    terminal = {e: {"test_epoch": e} for e in fields}
    candidate = dict(fleet, **{fields[e]: terminal[e] for e in fields})
    clock = fleet["recorded_unix_seconds"]
    accepted = denied = 0
    watch = event.Changes()
    try:
        for size in range(len(fields) + 1):
            for subset in combinations(fields, size):
                directory = event.completion_report_dir(base, subset)
                directory.mkdir(exist_ok=True)
                ref = write(directory / "COMPLETED.json", report)
                current = dict(candidate, authenticated_status_audit=ref)
                registered = write(cycle / event.FLEET_NAME, current)
                for e, field in fields.items():
                    assert event.accepted(runtime, reports, terminal[e], watch, lambda r: r, clock, field) == {
                        "fleet": registered, "report": ref}
                    accepted += 1
                for e in subset:
                    missing = dict(current)
                    del missing[fields[e]]
                    try:
                        event.registered_report(base, missing, fields[e])
                    except event.Rejected:
                        denied += 1
                    else:
                        raise AssertionError(f"accepted {directory.name} without epoch {e}")
        for name in ("after-170-166", "after-166-166", "after-indexed167/../after-166-170",
                     "after-166-168/after-recovered170", "after-999"):
            invalid = dict(candidate, authenticated_status_audit={"path": str(base / name / "COMPLETED.json")})
            try:
                event.registered_report(base, invalid, fields[166])
            except event.Rejected:
                denied += 1
            else:
                raise AssertionError(f"accepted invalid directory {name}")
    finally:
        watch.close()
    assert accepted == len(fields) * 2 ** len(fields) and denied == len(fields) * 2 ** (len(fields)-1) + 5
    sample, ref = event.document(Path(fleet["observer"]["path"]), 0o644)
    assert ref == fleet["observer"]
    scheduled = sample["cadence"]["configured_not_before_utc"]
    drift_checks = []
    if scheduled != fleet["sampled_at_utc"]:
        assert event.sample_time(fleet, cycle, scheduled) == report["sampled_at_utc"]
        for label, changed, due in (
            ("foreign-observer", dict(fleet, observer=original), scheduled),
            ("foreign-time", dict(fleet, sampled_at_utc=sample["completed_at_utc"] + "x"), scheduled),
            ("foreign-schedule", fleet, "2000-01-01T00:00:00Z"),
        ):
            try:
                event.sample_time(changed, cycle, due)
            except event.Rejected:
                drift_checks.append(label)
            else:
                raise AssertionError(label)
    return dict(accepted=accepted, denied=denied, original_report=original, native_report_count=len(report["receipts"]),
                scheduled=scheduled, sampled=fleet["sampled_at_utc"], rejected_clock_changes=drift_checks)


if __name__ == "__main__":
    print(json.dumps(qualify(*map(Path, sys.argv[1:])), sort_keys=True))
