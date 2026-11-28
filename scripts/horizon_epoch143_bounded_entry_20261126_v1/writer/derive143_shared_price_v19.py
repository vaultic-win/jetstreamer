"""Carry the exact 157 serial holding recognition into the epoch 143-aware roster."""

import json
from pathlib import Path
import subprocess
import sys

from derive143_bootstrap_retry import ROOT, read_package
from derive143_v53 import member_plan

OLD = ROOT.parent / "epoch162-first-hourly-completion-20261127-v2/issued-price-v18"
NEW = OLD.with_name("issued-price-v19")
SEAL = "8c326db152e86c7723771501a225607de66012c6cc6f619e9da452335c627e4a"
SOURCE = "b450bab2ddd6672c9077931bbeda6d3174c8a0c6"
PATH = "scripts/horizon_epoch170_checkpoint_suffix/following_peers.py"


def span(source):
    return source.index("def holding("),source.index("def m12_owner(")


def derive(stage, revision):
    files = read_package(OLD, SEAL)
    for name, count in (("capacity.py",1),("continuation_price.py",1),("successor_price.py",3)):
        raw, mode = files[name]
        source = raw.decode()
        if source.count(str(OLD)) != count:
            raise ValueError("unexpected sealed V18 self references for " + name)
        files[name] = (source.replace(str(OLD),str(NEW)).encode(),mode)
    current, mode = files["following_peers.py"]
    incoming = subprocess.check_output(["git","show",SOURCE+":"+PATH],text=True)
    old_s = current.decode()
    a,b = span(old_s)
    n,m = span(incoming)
    files["following_peers.py"] = ((old_s[:a] + incoming[n:m] + old_s[b:]).encode(),mode)
    source = json.loads(files["SOURCE.json"][0])
    source.update(revision=revision, prior_shared_price=dict(
        path=str(OLD/"deployment-seal-receipt.json"),sha256=SEAL),holding157_revision=SOURCE)
    files["SOURCE.json"] = ((json.dumps(source,indent=2)+"\n").encode(),0o444)
    return member_plan(files,stage,NEW)


if __name__ == "__main__":
    print(json.dumps(derive(Path(sys.argv[1]),sys.argv[2]),indent=2))
