"""Bind the first private block and transaction advance to the next guarded 169 invocation."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import adjacent_progress as prior
import derive_next169_price as price


def first(iid, transactions=False):
    source = prior.ORIGINAL.read_bytes()
    if hashlib.sha256(source).hexdigest()!=prior.PIN:
        raise ValueError("different original progress reader")
    text = source.decode()
    bindings = (("epoch162-third-replay-20261128-v1",price.operator.BASE.name),
                ("0489c223b03c5bbc889a1cd28b4907fa237c11dd05e10c52bee3ba78615afdb3",price.INTERFACE["sha256"]),
                ("69_998_120 <= slot <= 70_004_937","73_252_244 <= slot <= 73_259_077"),
                ("THIRD162_","NEXT169_"),("private-162-third","private-169-next"),
                ("INTERFACE.json","INTERFACE_48.json"),("SCOPE.json","SCOPE_48.json"),
                ("operator-v1/status162.py","operator-48-v1/status169.py"),("third-162","next-169"),
                ("worker_start_ticks=ticks,worker_executable=str(name)","worker_start_ticks=ticks,worker_executable=str(exe.readlink())"))
    for old,new in bindings:
        if old not in text:
            raise ValueError("changed progress binding "+old)
        text = text.replace(old,new)
    api = {"__name__":"next169_progress_event","__file__":str(__file__)}
    exec(compile(text,str(prior.ORIGINAL),"exec"),api)
    return api["first"](iid,transactions)


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("iid")
    parser.add_argument("--transactions",action="store_true")
    args=parser.parse_args()
    print(json.dumps(first(args.iid,args.transactions),sort_keys=True),flush=True)
