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


def book(price, quote, operator, runtime, refused=None, dispatch_log=None, *, epoch=141, v46=None):
    replacement = epoch == 143
    version = 45 if replacement else 44
    package = PACKAGE.with_name("tools-cold168-retry5-failed166-v45-entry146") if replacement else PACKAGE
    active_path = WRITER_ROOT/"FAILED166_CADENCE_V45_ACTIVE.json" if replacement else ACTIVE
    active_sha = "a95b8ea8c0fc8692b5b534bb1afe33800476e48156a362c8f59dff75d12ae202" if replacement else ACTIVE_SHA
    seal_sha = "237ff74a47d9d3fce22399ea81ff268aa50b6ed09daa3a03bf102a228f09e0bb" if replacement else SEAL_SHA
    if v46 is not None:
        if not replacement:
            raise ValueError("V46 booking is scoped to epoch 143")
        version = 46
        package = WRITER_ROOT / "tools-cold168-retry5-failed166-v46-entry146-r2"
        active_path = WRITER_ROOT / "FAILED166_CADENCE_V46_ACTIVE.json"
        active_sha, seal_sha = v46
    home_bytes = (64 << 30)+(64 << 20) if replacement else HOME_BYTES
    ram_bytes = 41 << 30 if replacement else RAM_BYTES
    sys.path.insert(0, str(package))
    import status_cycle as cycle
    from cutover41 import private_write
    from evidence import bound, checked, digest, json_bytes, need, raw, utc
    from first_hourly143 import EPOCH141, EPOCH143, process_ids, props
    profile = EPOCH143 if replacement else EPOCH141
    from transition import clock

    need(cycle.FAILED166_VERSION == version and cycle.entry()["sha256"] == seal_sha,
         "different first-hourly writer package")
    active = bound(active_path)
    need(active["sha256"] == active_sha, "different live first-hourly writer")
    active_record = checked(active)
    writer = active_record["new"]
    if v46 is not None:
        ready = checked(active_record["ready"])
        need(ready["package"] == cycle.entry() and ready["hourly_reader"] == bound(package / "first_hourly143.py")
             and writer["program"] == str(package / "status_cycle.py"),
             "V46 adoption does not bind the epoch 143 reader")
    writer_state = props(writer["unit"], "MainPID,InvocationID,ActiveState,ExecStart,Job")
    fd = Path(f"/proc/{writer['pid']}/fd/{writer['lock']['fd']}").stat()
    need(writer_state["ActiveState"] == "active" and writer_state["Job"] == ""
         and writer_state["InvocationID"] == writer["invocation_id"]
         and writer_state["MainPID"] == str(writer["pid"]) and writer["program"] in writer_state["ExecStart"]
         and (fd.st_dev, fd.st_ino) == (writer["lock"]["device"], writer["lock"]["inode"]),
         "first-hourly writer lost its active lock")
    for route in (EPOCH141, EPOCH143):
        state = props(route.unit, "ActiveState,MainPID,ControlPID,Job")
        need(state["ActiveState"] == "inactive" and state["MainPID"] == state["ControlPID"] == "0"
             and state["Job"] == "" and not process_ids(route),
             f"the shared first-hourly envelope is occupied by epoch {route.epoch}")
    fit = checked(quote)
    if replacement:
        module = Path(price["path"])
        need(module.name == "price_hourly143.py" and module.parent.parent == profile.base
             and module.parent.name in ({"booking-price-v4", "booking-price-v5"} if v46 is not None else {"booking-price-v2", "booking-price-v3"})
             and Path(operator["path"]) == module.with_name("launch-first-hourly143.sh"),
             "foreign epoch 143 operator or price")
        sys.path.insert(0,str(module.parent))
        import rollover143, continuation_price
        closed = rollover143.first_closed(continuation_price.prior)
        need(fit["schema"]=="horizon-epoch143-first-hourly-replacement-fit-v1" and fit["contract"]==profile.contract
             and fit["closed141"]==closed and not fit["projection_only"] and fit["held_invocation"] is None,
             "143 needs a real closed 141 and prestart fit")
    head = fit["fleet"]
    current = max(BASE.glob("root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json"),
                  key=lambda path: path.stat().st_mtime_ns)
    fleet = checked(head)
    now = int(time.time())
    need(head["path"] == str(current) and fleet["owner"] == "/root"
         and 0 <= now - fit["recorded_unix_seconds"] <= 90
         and fit["candidate_home_bytes"] == home_bytes and fit["candidate_ram_bytes"] == ram_bytes
         and fit["candidate_cpu_quota_micros"] == CPU_QUOTA and fit["resource_credit_bytes"] == 0
         and fit["disk_fits"] is fit["memory_fits"] is True
         and fit["available_home_bytes"] >= fit["retained_required_home_bytes"] + home_bytes
         and fit["available_ram_bytes"] >= fit["retained_required_ram_bytes"] + ram_bytes,
         f"epoch {epoch} complete fit is stale, nonpositive or covers another envelope")
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
    booking = dict(schema=f"horizon-epoch{epoch}-first-hourly-booking-v1", unit=profile.unit,
                   contract=profile.contract, fleet=head, writer=writer, writer_active=active,
                   sole_next_timer=dict(unit=timer, invocation_id=observer["InvocationID"]),
                   sealed_price=price, sealed_operator=operator,
                   sealed_reader=bound(package / "first_hourly143.py"), price=quote,
                   HOME_bytes=home_bytes, RAM_bytes=ram_bytes, cpu_quota_micros=CPU_QUOTA,
                   runtime_max_seconds=runtime, latest_start_unix_seconds=latest,
                   must_drain_by_unix_seconds=latest + runtime + (20 if replacement else 0), recorded_unix_seconds=now,
                   native_census_enrolled=True, recording_authorized=True,
                   archive_publication_authorized=False, resource_credit_bytes=0)
    path = profile.base / "WRITER_BOOKING_FIRST_HOURLY.json"
    if replacement:
        need(not refused and not dispatch_log, "143 replacement takes its prior booking from its own directory")
        booking.update(closed_141=closed,native_stop_grace_seconds=20)
        prior = list(profile.base.glob("WRITER_BOOKING_FIRST_HOURLY*.json"))
        if prior:
            old_ref = bound(max(prior,key=lambda p:p.stat().st_mtime_ns))
            old = checked(old_ref)
            need(old["unit"]==profile.unit and old["contract"]==profile.contract and old["latest_start_unix_seconds"]<now
                 and all(not (profile.base/item).exists() for item in ("PRESTART_SCREEN.json","HELD_OWNER.json","barrier/allow","ACTUAL_GUARD_PLAN.json")),
                 "a previous 143 booking is still live or its evidence requires reconciliation")
            booking.update(replaces_expired_booking=old_ref)
            path = profile.base/f"WRITER_BOOKING_FIRST_HOURLY_{time.time_ns()}.json"
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
    parser.add_argument("--epoch",type=int,choices=[141,143],default=141)
    args = parser.parse_args()
    if bool(args.refused) != bool(args.dispatch_log):
        parser.error("--refused and --dispatch-log must be supplied together")
    refs = [dict(zip(("path", "sha256"), getattr(args, name))) for name in ("price", "quote", "operator")]
    refs += [dict(zip(("path", "sha256"), values)) if values else None
             for values in (args.refused, args.dispatch_log)]
    with LOCK.open("rb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        print(json.dumps(book(*refs[:3], args.runtime_max_seconds, *refs[3:], epoch=args.epoch)))
