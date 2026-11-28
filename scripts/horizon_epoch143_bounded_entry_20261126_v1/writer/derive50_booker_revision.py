"""Derive the 143 booking correction from the exact V50 booking seal."""

import ast
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch143-first-hourly-20261127-v1")
OLD = ROOT / "booking-price-v50"
NEW = ROOT / "booking-price-v50-r2"
OLD_SEAL = "d4e681eb2ba2cd43c961730b4420debd2b1bae314f35b54cb96f1d11f8af2365"
OLD_143 = 'RT/"epoch143-first-hourly-20261127-v1/booking-price-v48",'
NEW_143 = 'RT/"epoch143-first-hourly-20261127-v1/booking-price-v50-r2",'


def successor(data):
    text = data.decode()
    start = text.index('    if native162 is not None and native162["phase"] != "terminal":')
    stop = text.index('    need(units == expected', start)
    clause = text[start:stop]
    if clause.count(OLD_143) != 1:
        raise ValueError("missing V48 split-162 caller")
    return (text[:start] + clause.replace(OLD_143, OLD_143 + "\n                 " + NEW_143) + text[stop:]).encode()


def stage(work, revision):
    raw = (OLD / "deployment-seal-receipt.json").read_bytes()
    if hashlib.sha256(raw).hexdigest() != OLD_SEAL:
        raise ValueError("foreign V50 booking seal")
    seal = json.loads(raw)
    if seal["destination"] != str(OLD):
        raise ValueError("foreign V50 booking destination")
    work.mkdir(mode=0o700)
    members = []

    def add(name, data, mode):
        if name.endswith(".py"):
            ast.parse(data, filename=name)
        path = work / name
        path.write_bytes(data)
        path.chmod(mode)
        members.append(dict(name=name, source=str(path), mode=mode,
                            sha256=hashlib.sha256(data).hexdigest()))

    for member in seal["members"]:
        name = member["name"]
        path = OLD / name
        data = path.read_bytes()
        if path.resolve(strict=True) != path or hashlib.sha256(data).hexdigest() != member["sha256"]:
            raise ValueError("foreign V50 member " + name)
        mode = int(member["mode"], 8)
        if name in {"book141.py", "prepare143.py"}:
            data = data.replace(b"booking-price-v50", b"booking-price-v50-r2")
        if name == "successor_price.py":
            data = successor(data)
        if name == "price_hourly143.py":
            mode = 0o555
        add(name, data, mode)
    provenance = dict(branch="account-updates", revision=revision,
                      predecessor=dict(path=str(OLD / "deployment-seal-receipt.json"), sha256=OLD_SEAL),
                      corrected_receivers=["book141.py", "prepare143.py", "successor_price.py"],
                      executable_price="price_hourly143.py")
    add("DERIVATION.json", (json.dumps(provenance, indent=2) + "\n").encode(), 0o444)
    return dict(schema="jetstreamer-sealed-deployment-plan-v1", destination=str(NEW), members=members)


if __name__ == "__main__":
    print(json.dumps(stage(Path(sys.argv[1]), sys.argv[2]), indent=2))
