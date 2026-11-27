"""Record the exact first-hourly booking after a complete current fit."""

import argparse
import fcntl
import json
from pathlib import Path
import sys
import time

BASE = Path("/var/lib/jetstreamer/horizon_runtime_data")
WRITER_ROOT = BASE / "survivor172-cadence-20261122-v1"
PACKAGE = WRITER_ROOT / "tools-cold168-retry5-failed166-v44-entry146"
ACTIVE = WRITER_ROOT / "FAILED166_CADENCE_V44_ACTIVE.json"
ACTIVE_SHA = "fa89af4b94631111c9998170d86758d11db8728dbdc3fe7648df48eef4bba9eb"
SEAL_SHA = "ffbcf9381420fe08966f35d24e4b7fada4e3e8684339c92600a4a1169fb1629b"
LOCK = Path("/run/horizon-epoch171-to136-g1.operation.lock")
CPU_QUOTA = 3_000_000
HOME_BYTES = (44 << 30) + (64 << 20)
RAM_BYTES = 31 << 30


def book(price, quote, operator, runtime, refused=None, dispatch_log=None):
    sys.path.insert(0, str(PACKAGE))
    import status_cycle as cycle
    from cutover41 import private_write
    from evidence import bound, checked, digest, json_bytes, need, raw, utc
    from first_hourly143 import EPOCH141 as profile, EPOCH143, process_ids, props
    from transition import clock

    need(cycle.FAILED166_VERSION == 44 and cycle.entry()["sha256"] == SEAL_SHA,
         "different first-hourly writer package")
    active = bound(ACTIVE)
    need(active["sha256"] == ACTIVE_SHA, "different live first-hourly writer")
    writer = checked(active)["new"]
    writer_state = props(writer["unit"], "MainPID,InvocationID,ActiveState,ExecStart,Job")
    fd = Path(f"/proc/{writer['pid']}/fd/{writer['lock']['fd']}").stat()
    need(writer_state["ActiveState"] == "active" and writer_state["Job"] == ""
         and writer_state["InvocationID"] == writer["invocation_id"]
         and writer_state["MainPID"] == str(writer["pid"]) and writer["program"] in writer_state["ExecStart"]
         and (fd.st_dev, fd.st_ino) == (writer["lock"]["device"], writer["lock"]["inode"]),
         "first-hourly writer lost its active lock")
    for route in (profile, EPOCH143):
        state = props(route.unit, "ActiveState,MainPID,ControlPID,Job")
        need(state["ActiveState"] == "inactive" and state["MainPID"] == state["ControlPID"] == "0"
             and state["Job"] == "" and not process_ids(route),
             f"the shared first-hourly envelope is occupied by epoch {route.epoch}")
    fit = checked(quote)
    head = fit["fleet"]
    current = max(BASE.glob("root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json"),
                  key=lambda path: path.stat().st_mtime_ns)
    fleet = checked(head)
    now = int(time.time())
    need(head["path"] == str(current) and fleet["owner"] == "/root"
         and 0 <= now - fit["recorded_unix_seconds"] <= 90
         and fit["candidate_home_bytes"] == HOME_BYTES and fit["candidate_ram_bytes"] == RAM_BYTES
         and fit["candidate_cpu_quota_micros"] == CPU_QUOTA and fit["resource_credit_bytes"] == 0
         and fit["disk_fits"] is fit["memory_fits"] is True
         and fit["available_home_bytes"] >= fit["retained_required_home_bytes"] + HOME_BYTES
         and fit["available_ram_bytes"] >= fit["retained_required_ram_bytes"] + RAM_BYTES,
         "epoch 141 complete fit is stale, nonpositive or covers another envelope")
    loan = fleet["current_private140_suffix_recording"]
    need(loan["phase"] == "terminal" and loan["loan_return"]
         and checked(loan["loan_return"])["producer_and_guard_drained"] is True
         and not Path("/run/horizon-epoch140-epoch170-cpu-loan.active").exists(),
         "epoch 140 has not returned the three-core envelope")
    reference = fleet["sole_next_observer"]
    timer = fleet["sole_next_timer"]
    config = cycle.sealed(reference)
    need(clock(vars(cycle), fleet, config, timer, reference) is None,
         "the next fleet observer is already complete")
    observer = props(timer, "InvocationID,ActiveState,SubState")
    due = int(utc(config["not_before_utc"]).timestamp())
    latest = min(now + 90, due - 180)
    need(now < latest and observer["ActiveState"] == "active" and observer["SubState"] == "waiting",
         "the observer is too close to begin the held replay")
    checked(profile.contract)
    need(bound(Path(price["path"])) == price and bound(Path(operator["path"])) == operator,
         "first-hourly price or operator seal changed")
    need(runtime > 0, "positive runtime bound required")
    booking = dict(schema="horizon-epoch141-first-hourly-booking-v1", unit=profile.unit,
                   contract=profile.contract, fleet=head, writer=writer, writer_active=active,
                   sole_next_timer=dict(unit=timer, invocation_id=observer["InvocationID"]),
                   sealed_price=price, sealed_operator=operator,
                   sealed_reader=bound(PACKAGE / "first_hourly143.py"), price=quote,
                   HOME_bytes=HOME_BYTES, RAM_bytes=RAM_BYTES, cpu_quota_micros=CPU_QUOTA,
                   runtime_max_seconds=runtime, latest_start_unix_seconds=latest,
                   must_drain_by_unix_seconds=latest + runtime, recorded_unix_seconds=now,
                   native_census_enrolled=True, recording_authorized=True,
                   archive_publication_authorized=False, resource_credit_bytes=0)
    path = profile.base / "WRITER_BOOKING_FIRST_HOURLY.json"
    if refused:
        old = checked(refused)
        log = raw(dispatch_log["path"])
        guard = props(profile.guard_timer, "ActiveState,InvocationID,Job")
        untouched = ("PRESTART_SCREEN.json", "ACTUAL_GUARD_PLAN.json", "HELD_OWNER.json", "barrier/allow")
        predecessor = max(profile.base.glob("WRITER_BOOKING_FIRST_HOURLY*.json"),
                          key=lambda candidate: candidate.stat().st_mtime_ns)
        need(refused == bound(predecessor) and old["unit"] == profile.unit
             and old["contract"] == profile.contract and old["writer_active"] == active
             and old["latest_start_unix_seconds"] < now
             and old["price"] != quote and old["sealed_price"] != price
             and Path(dispatch_log["path"]).parent == profile.base
             and digest(log) == dispatch_log["sha256"]
             and b"' returned non-zero exit status 1." in log
             and b"old_lower, old_upper = tree_bytes()" in log
             and b"/usr/bin/du: cannot access " in log and log.rstrip().endswith(b"+ quote=")
             and guard == {"ActiveState": "inactive", "InvocationID": "", "Job": ""}
             and all(not (profile.base / item).exists() for item in untouched),
             "the original booking is still live or did not fail before producer creation")
        booking.update(replaces_expired_booking=refused, failed_prestart_dispatch=dispatch_log)
        path = profile.base / f"WRITER_BOOKING_FIRST_HOURLY_{now}.json"
    private_write(path, json_bytes(booking), 0o400)
    return bound(path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    for option in ("price", "quote", "operator", "refused", "dispatch-log"):
        parser.add_argument(f"--{option}", nargs=2, metavar=("PATH", "SHA256"),
                            required=option in ("price", "quote", "operator"))
    parser.add_argument("--runtime-max-seconds", type=int, required=True)
    args = parser.parse_args()
    if bool(args.refused) != bool(args.dispatch_log):
        parser.error("--refused and --dispatch-log must be supplied together")
    refs = [dict(zip(("path", "sha256"), getattr(args, name))) for name in ("price", "quote", "operator")]
    refs += [dict(zip(("path", "sha256"), values)) if values else None
             for values in (args.refused, args.dispatch_log)]
    with LOCK.open("rb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        print(json.dumps(book(*refs[:3], args.runtime_max_seconds, *refs[3:])))
