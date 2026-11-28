"""Enroll the pre-funded 162 gate on the V15 roster while preserving all other reservations."""
import ast
from pathlib import Path

import following_prepare as f
from derive_closed167_price import DEST as PREVIOUS
from derive_gap_price import one

DEST = PREVIOUS.with_name("issued-price-v16")
SEAL = "a45a40a3a5e4e16754a63c9ed2a61d1768416fab11e1a0f06aaa8107ca24b120"
SOURCE = Path(__file__).resolve().parent.parent / "horizon_epoch162_split_scratch/second_reserved_peer.py"


def members(staging, revision):
    ref = dict(path=str(PREVIOUS / "deployment-seal-receipt.json"),sha256=SEAL)
    seal = f.read(ref)
    f.need(Path(seal["destination"]) == PREVIOUS, "foreign V15 roster")
    staging.mkdir(mode=0o700)
    members = {}
    for entry in seal["members"]:
        name = entry["name"]
        old = PREVIOUS/name
        f.need(old.parent == PREVIOUS and f.reference(old)["sha256"] == entry["sha256"], "changed V15 member")
        if name == "SOURCE.json":
            continue
        if name == "second162_peer.py":
            ast.parse(SOURCE.read_text())
            members[name] = (SOURCE,0o444)
            continue
        s = old.read_text()
        count = s.count(str(PREVIOUS))
        expected = 3 if name == "successor_price.py" else int(name in ("continuation_price.py","capacity.py"))
        f.need(count == expected, "unexpected self scope in " + name)
        s = s.replace(str(PREVIOUS),str(DEST))
        if name == "successor_price.py":
            s = one(s, 'native162["unit"]["Id"] == "horizon-qualify-162-second-replay-20261128-v2.service"',
                    'native162["unit"]["Id"] == "horizon-qualify-162-second-replay-20261128-v3.service"')
        if not expected:
            members[name] = (old,0o444)
        else:
            ast.parse(s,filename=name)
            out = staging/name
            out.write_text(s)
            members[name] = (out,0o444)
    source = staging/"SOURCE.json"
    history = f.read(f.reference(PREVIOUS/"SOURCE.json"))
    f.save(source,dict(history,revision=revision,previous_162_postguard_price=ref,second_162_reserved_peer=f.reference(SOURCE)["sha256"]))
    members[source.name] = (source,0o444)
    return members
