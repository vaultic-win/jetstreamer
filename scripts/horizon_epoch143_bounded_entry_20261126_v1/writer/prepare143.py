"""Under the host lock, record a positive current 143 quote and V45 booking."""
import argparse
import fcntl
import json
from pathlib import Path
import sys
import time

PACKAGE = Path(__file__).resolve().parent
sys.path.insert(0, str(PACKAGE))
import book141
import price_hourly143 as funding


def prepare(runtime):
    core = funding.core
    core.need(PACKAGE.parent == funding.roll.ROOT and PACKAGE.name in {"booking-price-v2", "booking-price-v3"}
              and runtime > 0, "invalid 143 booking interface")
    if PACKAGE.name == "booking-price-v3":
        assembly = "horizon-assemble-168-private-20261127-v1.service"
        state = core.state(assembly, "Id,ActiveState,MainPID,ControlPID,Job")
        core.need(state["ActiveState"] == "inactive" and state["MainPID"] == state["ControlPID"] == "0"
                  and not state["Job"] and not (Path("/sys/fs/cgroup/system.slice")/assembly).exists(),
                  "epoch 168 assembly already owns or is claiming the joint window")
        reconciled, _ = core.read(funding.roll.ROOT/"failed-fa915d8326a34b589238d55833b3e846/RECONCILED.json")
        core.need(reconciled["failed_invocation"] == "fa915d8326a34b589238d55833b3e846"
                  and reconciled["release_absent"] and reconciled["resource_credit_bytes"] == 0,
                  "failed 143 gate evidence not reconciled")
    writer = book141.PACKAGE.with_name("tools-cold168-retry5-failed166-v45-entry146")
    sys.path.insert(0, str(writer))
    import status_cycle
    from cutover41 import private_write
    from evidence import bound, json_bytes

    core.need(status_cycle.FAILED166_VERSION == 45, "different booking writer")
    _, fleet = core.current_fleet()
    fit = funding.price(fleet["path"], fleet["sha256"])
    core.need(fit["disk_fits"] and fit["memory_fits"],
              f'143 fit failed: HOME {fit["home_margin_bytes"]} bytes, RAM {fit["ram_margin_bytes"]} bytes')
    quote = funding.roll.ROOT/f"BOOKING_PRICE_{time.time_ns()}.json"
    private_write(quote, json_bytes(fit), 0o400)
    return book141.book(bound(PACKAGE/"price_hourly143.py"), bound(quote),
                        bound(PACKAGE/"launch-first-hourly143.sh"), runtime, epoch=143)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-max-seconds", required=True, type=int)
    args = parser.parse_args()
    with book141.LOCK.open("rb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        print(json.dumps(prepare(args.runtime_max_seconds)))
