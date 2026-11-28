"""Derive 143's corrected bootstrap entry from the sealed booking and roster provider."""

import ast
import hashlib
import json
from pathlib import Path
import sys

BASE = Path("/var/lib/jetstreamer/horizon_runtime_data")
ROOT = BASE / "epoch143-first-hourly-20261127-v1"
OLD_PRICE = BASE / "epoch162-first-hourly-completion-20261127-v2/issued-price-v5"
NEW_PRICE = OLD_PRICE.with_name("issued-price-v6")
OLD_BOOK = ROOT / "booking-price-v51"
NEW_BOOK = ROOT / "booking-price-v52"
OLD_PRICE_SEAL = "6bff49a31525ee2e1cdd5861a9d1d30e43686ddc79e5932bf7a85f5a3df35a96"
OLD_BOOK_SEAL = "d1801ac0ac8e47cdc4cb39271d3c7ec3588181428c0db8f2c06f820bafbcf534"
GATE_SHA = "c5656f1867ede9b8b33e12e890eae3ba97c572bcaf76d9b45b86aafd0b5cde63"
OLD_GATE = "5c5f37185fcf617a01e3a323632847f34c70f3e513b0fece4ccb49e7c98d033c"
NATIVE_FAILED = "03ba8900c208428e81f98314e72f6685"
OLD_ACTIVE = "7353e093feb5763907b9e76ac58fa35d8cf869af686dae85a0b91e58c8857c62"


def change(data, old, new):
    if data.count(old) != 1:
        raise ValueError("unexpected predecessor text: " + old)
    return data.replace(old, new)


def read_package(directory, digest):
    path = directory / "deployment-seal-receipt.json"
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError("different predecessor package")
    seal = json.loads(raw)
    if seal["destination"] != str(directory):
        raise ValueError("foreign predecessor directory")
    result = {}
    for row in seal["members"]:
        member = directory / row["name"]
        data = member.read_bytes()
        if member.resolve(strict=True) != member or hashlib.sha256(data).hexdigest() != row["sha256"]:
            raise ValueError("different predecessor member " + row["name"])
        result[row["name"]] = (data, int(row["mode"], 8))
    return result


def plan(files, work, target, revision, previous, digest):
    work.mkdir(mode=0o700)
    source_name = "DERIVATION.json" if target == NEW_BOOK else "SOURCE.json"
    source = dict(branch="account-updates", revision=revision,
                  predecessor=dict(path=str(previous / "deployment-seal-receipt.json"), sha256=digest))
    files[source_name] = ((json.dumps(source, indent=2) + "\n").encode(), 0o444)
    members = []
    for name, (data, mode) in files.items():
        if name.endswith(".py"):
            ast.parse(data, filename=name)
        path = work / name
        path.write_bytes(data)
        path.chmod(mode)
        members.append(dict(name=name, source=str(path), sha256=hashlib.sha256(data).hexdigest(), mode=mode))
    return dict(schema="jetstreamer-sealed-deployment-plan-v1", destination=str(target), members=members)


def price(work, revision):
    files = read_package(OLD_PRICE, OLD_PRICE_SEAL)

    def set_text(name, transform):
        data, mode = files[name]
        files[name] = (transform(data.decode()).encode(), mode)

    set_text("capacity.py", lambda data: change(
        change(data, "STOPPED = ROOT / 'issued-price-v5/capacity.py'",
                 """STOPPED_V5 = ROOT / 'issued-price-v5/capacity.py'
STOPPED = ROOT / 'issued-price-v6/capacity.py'"""),
        "{'path':str(HANDOFF), 'sha256':HANDOFF_DIGEST})),",
        """{'path':str(HANDOFF), 'sha256':HANDOFF_DIGEST},
                                                 {'path':str(STOPPED_V5), 'sha256':'091c06051762b277db141d19ebed0fec815fdd22804e7ff81fe7f296de0a1804'})),"""))
    set_text("continuation_price.py", lambda data: change(
        data, 'STOPPED162_PRICE = SPLIT162_PRICE.with_name("issued-price-v5")',
        'STOPPED162_PRICE = SPLIT162_PRICE.with_name("issued-price-v6")'))
    set_text("successor_price.py", lambda data: change(
        data, 'RT/"epoch162-first-hourly-completion-20261127-v2/issued-price-v5",',
        'RT/"epoch162-first-hourly-completion-20261127-v2/issued-price-v6",'))
    set_text("rollover143.py", lambda data: change(
        data, 'ROOT/"tools-v1/hold-143"', 'ROOT/"tools-bootstrap-v2/hold-143"'))
    return plan(files, work, NEW_PRICE, revision, OLD_PRICE, OLD_PRICE_SEAL)


def launch(data):
    data = change(data, OLD_GATE, GATE_SHA)
    data = change(data, 'gate="$a/tools-v1/hold-$epoch"', '''gate="$a/tools-v1/hold-$epoch"
if [[ $epoch == 143 ]]; then gate="$a/tools-bootstrap-v2/hold-143"; fi''')
    data = change(data, '''        if [[ $destination == "$view"/* ]]; then
            sourcepath=''',
        '''        if [[ $destination == "$view/hold-143" ]]; then
            test "$(sha "$gate")" = "$gate_sha"
            checked=$((checked+1))
            continue
        fi
        if [[ $destination == "$view"/* ]]; then
            sourcepath=''')
    return change(data, '''mapfile -t bindings < <(jq -r '.read_only_bind_map|to_entries[]|.key+":"+ .value' "$contract")'''
                  .replace('":"+ .value','":"+ .value'.replace(' ','')),
                  '''mapfile -t bindings < <(jq -r --arg gate "$gate" --arg destination "$view/hold-$epoch" '
    .read_only_bind_map|to_entries[]|(if .value==$destination then $gate else .key end)+":"+ .value' "$contract")''')


def book(work, revision, provider_seal):
    files = read_package(OLD_BOOK, OLD_BOOK_SEAL)

    def set_text(name, transform):
        data, mode = files[name]
        files[name] = (transform(data.decode()).encode(), mode)

    def version(data):
        return data.replace("v51", "v52").replace("V51", "V52").replace("version = 51", "version = 52")

    def booker(data):
        data = version(data)
        data = change(data, "FAILED166_CADENCE_V50_ACTIVE.json", "FAILED166_CADENCE_V51_ACTIVE.json")
        return change(data, "1a97e2971f8222d98412392054d540fda66efa609721b1d7caa28f402125eb22", OLD_ACTIVE)

    def preparer(data):
        data = version(data)
        marker = '    version = 52 if v52 is not None'
        return change(data, marker, f'''    if v52 is not None:
        repaired, _ = core.read(funding.roll.ROOT / "failed-{NATIVE_FAILED}/RECONCILED.json")
        core.need(repaired["failed_invocation"] == "{NATIVE_FAILED}"
                  and repaired["released_gate_drained"] and repaired["resource_credit_bytes"] == 0,
                  "released 143 attempt still needs reconciliation")
''' + marker)

    set_text("book141.py", booker)
    set_text("prepare143.py", preparer)
    set_text("launch-first-hourly143.sh", launch)
    set_text("price_hourly143.py", lambda data: change(change(data,
        "epoch162-first-hourly-completion-20261127-v2/issued-price-v5",
        "epoch162-first-hourly-completion-20261127-v2/issued-price-v6"),
        OLD_PRICE_SEAL, provider_seal))
    return plan(files, work, NEW_BOOK, revision, OLD_BOOK, OLD_BOOK_SEAL)


if __name__ == "__main__":
    kind, root, revision, *args = sys.argv[1:]
    selected = {"price": price, "book": book}[kind]
    print(json.dumps(selected(Path(root), revision, *args), indent=2))
