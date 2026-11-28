"""Observe native block and transaction events on the registered 48 GiB 169 worker."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import adjacent_progress as original
import compact_adjacent_writer as writer


def event_reader():
    # All IPC, matching, protection and receipt handling use the qualified same-unit
    # reader. Only the sealed scope, provider and interface references change.
    refs=writer.bindings()
    raw=original.ORIGINAL.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=original.PIN:
        raise ValueError("changed native event reader")
    text=raw.decode()
    for a,b in (("epoch162-third-replay-20261128-v1",original.BASE.name),
                ("0489c223b03c5bbc889a1cd28b4907fa237c11dd05e10c52bee3ba78615afdb3",refs["INTERFACE"]["sha256"]),
                ("69_998_120 <= slot <= 70_004_937","73_245_219 <= slot <= 73_252_243"),
                ("THIRD162_","ADJACENT169_"),("private-162-third","private-169-adjacent"),
                ("INTERFACE.json","INTERFACE_48.json"),("SCOPE.json","SCOPE_48.json"),
                ("operator-v1/status162.py","operator-48-v1/status169.py"),("third-162","adjacent-169"),
                ("worker_start_ticks=ticks,worker_executable=str(name)","worker_start_ticks=ticks,worker_executable=str(exe.readlink())")):
        if a not in text:
            raise ValueError("different native progress binding "+a)
        text=text.replace(a,b)
    ns={"__name__":"compact_169_progress","__file__":str(__file__)}
    exec(compile(text,str(original.ORIGINAL),"exec"),ns)
    return ns["first"]


def first(iid, transactions=False):
    return event_reader()(iid, transactions)


if __name__=="__main__":
    cli=argparse.ArgumentParser(description=__doc__)
    cli.add_argument("iid")
    cli.add_argument("--transactions",action="store_true")
    arg=cli.parse_args()
    print(json.dumps(first(arg.iid,arg.transactions),sort_keys=True),flush=True)
