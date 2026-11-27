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
    core.need(PACKAGE == funding.roll.ROOT/"booking-price-v1" and runtime > 0, "invalid 143 booking interface")
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
