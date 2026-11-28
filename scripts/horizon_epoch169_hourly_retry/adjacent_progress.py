"""Capture the first guarded native block or transaction advance from this exact 169 producer."""
import argparse
from hashlib import sha256
import json
from pathlib import Path

BASE=Path("/var/lib/jetstreamer/horizon_runtime_data/epoch169-from-73245218-20261128-v1")
ORIGINAL=Path(__file__).resolve().parents[1]/"horizon_epoch162_split_scratch/third162_first_progress.py"
PIN="99003e3cf8b83948832bbf960697293ae4c65800c332fbbb236226df292151c7"


def first(iid,transactions=False):
    body=ORIGINAL.read_bytes()
    if sha256(body).hexdigest()!=PIN:
        raise ValueError("different journal and guard reader")
    source=body.decode().replace("epoch162-third-replay-20261128-v1",BASE.name)
    source=source.replace("0489c223b03c5bbc889a1cd28b4907fa237c11dd05e10c52bee3ba78615afdb3",
                          "9bd834876a560f4e90dc9623d019acfbf49d1cdaf3edba09fb6da69784152226")
    source=source.replace("69_998_120 <= slot <= 70_004_937","73_245_219 <= slot <= 73_252_243")
    source=source.replace("THIRD162_","ADJACENT169_").replace("private-162-third","private-169-adjacent")
    source=source.replace("status162.py","status169.py").replace("third 162","adjacent 169")
    # Preserve the worker's path in the receipt. The inherited first-event code
    # reuses 'name' for the output filename after the executable check.
    original="worker_start_ticks=ticks,worker_executable=str(name)"
    if source.count(original)!=1:
        raise ValueError("different worker identity check")
    source=source.replace(original,"worker_start_ticks=ticks,worker_executable=str(exe.readlink())")
    ns={"__name__":"adjacent169_progress_event","__file__":str(__file__)}
    exec(compile(source,str(ORIGINAL),"exec"),ns)
    return ns["first"](iid,transactions)


if __name__=="__main__":
    cli=argparse.ArgumentParser(description=__doc__)
    cli.add_argument("iid")
    cli.add_argument("--transactions",action="store_true")
    arg=cli.parse_args()
    print(json.dumps(first(arg.iid,arg.transactions),sort_keys=True),flush=True)
