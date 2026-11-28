"""Read the first guarded fourth-interval block, or its first positive transaction advance."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from fourth162_price import INTERFACE_SHA
from fourth_interval import BASE, OLD, OLD_INTERFACE_SHA, need

SOURCE = HERE/"third162_first_progress.py"
SOURCE_SHA = "99003e3cf8b83948832bbf960697293ae4c65800c332fbbb236226df292151c7"


def event_reader():
    raw = SOURCE.read_bytes()
    need(sha256(raw).hexdigest()==SOURCE_SHA,"previous event reader changed")
    text = raw.decode()
    for old,new in ((str(OLD),str(BASE)),(OLD_INTERFACE_SHA,INTERFACE_SHA),
                    ("69_998_120 <= slot <= 70_004_937","70_004_938 <= slot <= 70_011_988"),
                    ("THIRD162_","FOURTH162_"),("private-162-third","private-162-fourth"),
                    ("third","fourth"),("worker_executable=str(name)","worker_executable=str(exe.readlink())")):
        need(old in text,"missing source binding "+old)
        text=text.replace(old,new)
    module = {"__name__":"fourth162_event_reader","__file__":str(__file__)}
    exec(compile(text,str(SOURCE),"exec"),module)
    need(module["ROOT"]==BASE and module["PIN"]==INTERFACE_SHA and "FOURTH162_" in module["NAME"],"foreign event receiver")
    return module["first"]


if __name__ == "__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("invocation")
    p.add_argument("--transactions",action="store_true")
    args=p.parse_args()
    print(json.dumps(event_reader()(args.invocation,args.transactions),sort_keys=True),flush=True)
