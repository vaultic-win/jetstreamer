"""Derive the full epoch 143 entry on the current stopped-roster accounting."""

import ast
import hashlib
import json
from pathlib import Path
import sys

from derive50_booker_revision import OLD, OLD_SEAL

ROOT = OLD.parent
NEW = ROOT / "booking-price-v50-r3"
HERE = Path(__file__).resolve().parent


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError("different V50 launch shell")
    return text.replace(old,new)


def launcher(data):
    source = data.decode()
    start = source.index("floor=$(jq -er '")
    end = source.index('test "$floor" -ge', start)
    source = source[:start] + """floor=$(jq -er '.guard_floor_bytes' "$a/PRESTART_SCREEN.json")
""" + source[end:]
    source = replace_once(source, '''    .retained_required_home_bytes<=$floor
    and .available_home_bytes>=($floor+.candidate_home_bytes)''',
        '''    .guard_floor_bytes<=$floor
    and .available_home_bytes>=(([$floor,.retained_required_home_bytes]|max)+.candidate_home_bytes)''')
    return source.encode()


def stage(work, revision):
    raw = (OLD/"deployment-seal-receipt.json").read_bytes()
    if hashlib.sha256(raw).hexdigest() != OLD_SEAL:
        raise ValueError("different V50 booker seal")
    seal = json.loads(raw)
    if seal["destination"] != str(OLD):
        raise ValueError("different V50 booker destination")
    work.mkdir(mode=0o700)
    members = []

    def add(name, data, mode):
        if name.endswith(".py"):
            ast.parse(data, filename=name)
        path = work/name
        path.write_bytes(data)
        path.chmod(mode)
        members.append(dict(name=name, source=str(path), mode=mode,
                            sha256=hashlib.sha256(data).hexdigest()))

    for member in seal["members"]:
        name = member["name"]
        path = OLD/name
        data = path.read_bytes()
        if path.resolve(strict=True) != path or hashlib.sha256(data).hexdigest() != member["sha256"]:
            raise ValueError("foreign V50 member " + name)
        mode = int(member["mode"], 8)
        if name in {"book141.py", "prepare143.py"}:
            data = data.replace(b"booking-price-v50", b"booking-price-v50-r3")
        if name == "launch-first-hourly143.sh":
            data = launcher(data)
        if name == "price_hourly143.py":
            data = (HERE/"price143_stopped_roster.py").read_bytes()
            mode = 0o555
        add(name,data,mode)
    evidence = dict(branch="account-updates", revision=revision,
                    predecessor=dict(path=str(OLD/"deployment-seal-receipt.json"),sha256=OLD_SEAL),
                    price_source="price143_stopped_roster.py")
    add("DERIVATION.json",(json.dumps(evidence,indent=2)+"\n").encode(),0o444)
    return dict(schema="jetstreamer-sealed-deployment-plan-v1",destination=str(NEW),members=members)


if __name__ == "__main__":
    print(json.dumps(stage(Path(sys.argv[1]),sys.argv[2]),indent=2))
