"""Bind the existing 143 entry and stopped-roster price to the V51 writer."""

import ast
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch143-first-hourly-20261127-v1")
OLD = ROOT / "booking-price-v50-r3"
NEW = ROOT / "booking-price-v51"
OLD_SEAL = "2699371befa215330f263466452d6970be5b954b4b4727b706067283fa8ba723"


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError("unexpected V50-R3 source")
    return text.replace(old, new)


def bind_version(data):
    return (data.decode().replace("booking-price-v50-r3", "booking-price-v51")
            .replace("v50", "v51").replace("V50", "V51")
            .replace("version = 50", "version = 51"))


def booker(data):
    text = bind_version(data)
    start = text.index('        if v51 is not None:\n            need(ready["old_owner"]')
    end = text.index('        need(module.name', start)
    text = text[:start] + '''        if v51 is not None:
            prior_ref = bound(WRITER_ROOT / "FAILED166_CADENCE_V50_ACTIVE.json")
            prior = checked(prior_ref)
            prior_ready = checked(prior["ready"])
            need(prior_ref["sha256"] == "1a97e2971f8222d98412392054d540fda66efa609721b1d7caa28f402125eb22"
                 and ready["old_owner"] == prior_ref and active_record["old"] == prior["new"]
                 and all(writer["lock"][k] == prior["new"]["lock"][k] for k in ("path", "device", "inode"))
                 and ready["retained_143_phase"] == prior_ready["retained_143_phase"]
                 and fit["whole_roster"]["writer"] == active
                 and not active_record["producer_mutations"],
                 "V51 lost the V50 phase, consumer lock or fresh 143 quote")
''' + text[end:]
    return text.encode()


def price(data):
    text = data.decode()
    point = '''                  "143 stopped-roster quote lost the exact held guard")'''
    return replace_once(text, point, point + '''
        booking = core.bound(replacement["booking"])
        core.need(whole["writer"] == booking["writer_active"],
                  "held 143 quote changed its V51 writer binding")''').encode()


def stage(work, revision):
    raw = (OLD / "deployment-seal-receipt.json").read_bytes()
    if hashlib.sha256(raw).hexdigest() != OLD_SEAL:
        raise ValueError("foreign V50-R3 booker seal")
    seal = json.loads(raw)
    if seal["destination"] != str(OLD):
        raise ValueError("foreign V50-R3 booker destination")
    work.mkdir(mode=0o700)
    members = []
    transforms = {"prepare143.py": lambda data: bind_version(data).encode(),
                  "book141.py": booker, "price_hourly143.py": price}

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
            raise ValueError("foreign V50-R3 member " + name)
        if name == "DERIVATION.json":
            continue
        if name in transforms:
            data = transforms[name](data)
        add(name, data, int(member["mode"], 8))
    source = dict(branch="account-updates", revision=revision,
                  predecessor=dict(path=str(OLD / "deployment-seal-receipt.json"), sha256=OLD_SEAL),
                  changes=list(transforms))
    add("DERIVATION.json", (json.dumps(source, indent=2) + "\n").encode(), 0o444)
    return dict(schema="jetstreamer-sealed-deployment-plan-v1", destination=str(NEW), members=members)


if __name__ == "__main__":
    print(json.dumps(stage(Path(sys.argv[1]), sys.argv[2]), indent=2))
