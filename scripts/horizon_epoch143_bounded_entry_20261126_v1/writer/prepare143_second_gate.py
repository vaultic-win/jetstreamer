"""Native pre-start barrier for the paid epoch 143 preparation allocations."""

import json
import os
from pathlib import Path
import re
import stat
import sys
import time

PERMITS = Path("/run/horizon143-preparation-permits")
ACTIONS = {"copy","build","fixture"}


def read_gate(path, invocation, unit):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as source:
        st = os.fstat(source.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_uid or stat.S_IMODE(st.st_mode) != 0o444 or st.st_nlink != 1 or st.st_size > 8192:
            raise ValueError("different guarded preparation token metadata")
        row = json.loads(source.read())
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    if (row["schema"] != "horizon-143-preparation-permit-v1" or row["unit"] != unit
        or row["boot_id"] != boot or row["invocation"] != invocation
        or not row["first_guard_success"] or row["replay_authorized"] or row["resource_credit_bytes"]):
        raise ValueError("token belongs to another native preparation invocation")
    return row


def wait_for_token(action):
    invocation = os.environ.get("INVOCATION_ID","")
    if action not in ACTIONS or not re.fullmatch("[0-9a-f]{32}", invocation):
        raise ValueError("expected exact systemd preparation invocation")
    unit = f"horizon-prepare-143-hourly-{action}-20261128-v1.service"
    if Path("/proc/self/cgroup").read_text().strip() != f"0::/system.slice/{unit}":
        raise ValueError("preparation gate is outside its native service")
    path = PERMITS / f"{action}-{invocation}.json"
    deadline = time.monotonic() + 70
    while time.monotonic() < deadline:
        token = read_gate(path, invocation, unit)
        if token is not None:
            return token
        time.sleep(0.15)
    raise ValueError("no guard proof for this preparation invocation")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise ValueError("expected one preparation action")
    wait_for_token(sys.argv[1])
