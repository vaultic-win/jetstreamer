"""Match the paid lane-j reservation to the native operator named by its admission."""
from hashlib import file_digest
import json
from pathlib import Path
import re
import stat

BASE = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch157-lanej-rotation-20261128-v1")
PRIOR = dict(path=str(BASE / "turnover-tools-v2/deployment-seal-receipt.json"),
             sha256="c064fe08ebf6af969217c231085d76ebadaa74958103632c120e904e7ad17a50")
CURRENT = dict(path=str(BASE / "turnover-tools-v4/deployment-seal-receipt.json"),
               sha256="65a6e06cfeae073952d6f3c87e16c8a939d8f23879b8f91b04536323ca53c28d")
IMAGES = {
    PRIOR["sha256"]: "aac4dd93041aa325792c8f082c657a760417319929fbb41639105b9ce317649a",
    CURRENT["sha256"]: "b578de72ff7b1a5fb67d71a9d5c03f2fe9399d4e8bc63e7644418cb406a4c8e2",
}
PATTERN = re.compile(r"horizon-closed157-(retire|restore)-lanej-([0-9]+)\.service")


def registered(core, seal):
    core.need(seal in (PRIOR, CURRENT), "unregistered lane-j holding operator")
    directory = Path(seal["path"]).parent
    image = directory / "rotation"
    digest = IMAGES[seal["sha256"]]
    sealed = core.bound(seal)
    row, = (m for m in sealed["members"] if m["name"] == image.name)
    info = image.lstat()
    core.need(sealed["destination"] == str(directory) and row["sha256"] == digest
              and image.resolve(strict=True) == image and stat.S_ISREG(info.st_mode)
              and info.st_uid == 0 and info.st_nlink == 1 and not info.st_mode & 0o222
              and info.st_size == row["bytes"], "foreign lane-j holding image")
    with image.open("rb") as handle:
        core.need(file_digest(handle, "sha256").hexdigest() == digest, "changed lane-j holding image")
    return image


def holder(core, units):
    core.need(len(units) == 1, "several native owners claim the paid holding slot")
    unit = next(iter(units))
    match = PATTERN.fullmatch(unit)
    core.need(match is not None, "unrecognized 157 rotation service")
    phase, stamp = match.groups()
    admission, ref = core.read(BASE / f"{phase.upper()}_ADMISSION_{stamp}.json")
    core.need(admission["unit"] == unit and admission["phase"] == phase, "different native lane-j admission")
    image = registered(core, admission["operator_seal"])
    row = json.loads(core.cmd(str(image), "live-holder", unit))
    core.need(row["phase"] == phase and row["native"]["Id"] == unit
              and row["admission"] == ref and not row["resource_credit_bytes"],
              "unexpected native lane-j confirmation")
    return row


def account(whole, core):
    core.need("epoch157_lanej_rotation" not in whole and not whole["resource_credit_bytes"], "duplicate lane-j charge")
    paid = whole["base_169"]["accounting"]
    core.need(paid["serial"]["repeated_serial_bytes"] == 2 << 30, "serial memory reservation changed")
    current = paid["holding"]
    lane = current if current and PATTERN.fullmatch(current.get("native", {}).get("Id", "")) else None
    registered(core, CURRENT)
    whole["epoch157_lanej_rotation"] = dict(operator_seal=CURRENT, previous_operator_seal=PRIOR, holder=lane,
                                           serial_slot_bytes=123_350_028_052, resource_credit_bytes=0)
    return whole
