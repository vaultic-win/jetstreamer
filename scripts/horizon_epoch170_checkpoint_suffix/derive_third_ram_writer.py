"""Register the third RAM-backed 170 receiver while keeping both earlier recordings visible."""
import ast
from hashlib import sha256
import json
from pathlib import Path

from derive_ram170_writer import once

HERE = Path(__file__).resolve().parent
ROOT = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch170-from-73760367-ram-20261128-v3")
PREVIOUS = ROOT.with_name(ROOT.name.replace("-v3", "-v2")) / "observer-modules-v1"
PREVIOUS_SEAL = "5c8d82782a94087bb5622ee35a0daa5b71a3904973308647833750528e062f25"
READY_KEY = "third_ram_gap170_interface"
ENROLL_OPTION = "--enroll-third-ram-gap-170"


def members(scope):
    if scope["path"] != str(ROOT / "RAM_GAP170_WRITER_INTERFACE.json") or len(scope["sha256"]) != 64:
        raise ValueError("unregistered third 170 interface")
    receipt = (PREVIOUS / "deployment-seal-receipt.json").read_bytes()
    if sha256(receipt).hexdigest() != PREVIOUS_SEAL:
        raise ValueError("different second 170 observer")
    seal = json.loads(receipt)
    expected = {"ram170_second_" + n + ".py" for n in ("native", "status", "contract", "workspace")}
    if seal["destination"] != str(PREVIOUS) or {m["name"] for m in seal["members"]} != expected:
        raise ValueError("incorrect predecessor receiver members")
    files = {}
    for member in seal["members"]:
        name = member["name"]
        original = (PREVIOUS / name).read_bytes()
        if sha256(original).hexdigest() != member["sha256"]:
            raise ValueError("changed second 170 receiver " + name)
        if name == "ram170_second_contract.py":
            source = (HERE / "ram170_third_contract.py").read_text()
            source = once(source, "INTERFACE_DIGEST = None", "INTERFACE_DIGEST = " + repr(scope["sha256"]))
        else:
            source = original.decode().replace("ram170_second_", "ram170_third_")
            source = source.replace("from-73760367-ram-20261128-v2", "from-73760367-ram-20261128-v3")
            source = source.replace("second_ram_gap", "third_ram_gap").replace("second RAM-backed", "third RAM-backed")
        name = name.replace("_second_", "_third_")
        ast.parse(source, filename=name)
        files[name] = source.encode()
    return files
