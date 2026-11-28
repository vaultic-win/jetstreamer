"""Register the sealed 157 retire/restore operator on the already-paid serial holding slot."""
from hashlib import file_digest
import json
from pathlib import Path
import re
import stat

BASE = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch157-lanej-rotation-20261128-v1")
DIRECTORY = BASE / "turnover-tools-v2"
IMAGE = DIRECTORY / "rotation"
SEAL = dict(path=str(DIRECTORY / "deployment-seal-receipt.json"),
            sha256="c064fe08ebf6af969217c231085d76ebadaa74958103632c120e904e7ad17a50")
DIGEST = "aac4dd93041aa325792c8f082c657a760417319929fbb41639105b9ce317649a"
PATTERN = re.compile(r"horizon-closed157-(retire|restore)-lanej-([0-9]+)\.service")


def registered(core):
    sealed = core.bound(SEAL)
    row, = (m for m in sealed["members"] if m["name"] == IMAGE.name)
    info = IMAGE.lstat()
    core.need(sealed["destination"] == str(DIRECTORY) and row["sha256"] == DIGEST
              and IMAGE.resolve(strict=True) == IMAGE and stat.S_ISREG(info.st_mode)
              and info.st_uid == 0 and info.st_nlink == 1 and not info.st_mode & 0o222
              and info.st_size == row["bytes"], "foreign lane-j holding image")
    with IMAGE.open("rb") as handle:
        core.need(file_digest(handle,"sha256").hexdigest() == DIGEST, "changed lane-j holding image")
    return SEAL


def holder(core, units):
    core.need(len(units) == 1, "several native owners claim the paid holding slot")
    unit = next(iter(units))
    match = PATTERN.fullmatch(unit)
    core.need(match is not None, "unrecognized 157 rotation service")
    registered(core)
    row = json.loads(core.cmd(str(IMAGE),"live-holder",unit))
    core.need(row["phase"] == match[1] and row["native"]["Id"] == unit and not row["resource_credit_bytes"],
              "unexpected native lane-j confirmation")
    return row


def account(whole, core):
    core.need("epoch157_lanej_rotation" not in whole and not whole["resource_credit_bytes"], "duplicate lane-j charge")
    paid = whole["base_169"]["accounting"]
    core.need(paid["serial"]["repeated_serial_bytes"] == 2 << 30, "serial memory reservation changed")
    current = paid["holding"]
    lane = current if current and PATTERN.fullmatch(current.get("native",{}).get("Id","")) else None
    whole["epoch157_lanej_rotation"] = dict(operator_seal=registered(core),holder=lane,
                                           serial_slot_bytes=123_350_028_052,resource_credit_bytes=0)
    return whole
