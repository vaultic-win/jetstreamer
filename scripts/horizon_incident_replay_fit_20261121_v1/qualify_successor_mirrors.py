import hashlib
import json
from pathlib import Path
import runpy
import sys
from unittest.mock import patch


def verify(entry, worker, digest):
    q = runpy.run_path(str(entry))
    fleet = q["original"]["head_reader"]()()
    ref = dict(path=str(worker),sha256=digest)
    ctx = q["price_context"](fleet,ref)
    q["checked_owners"](ctx)
    negative = []

    def rejected(name, function, *args):
        try:
            function(*args)
        except (ValueError, FileNotFoundError):
            negative.append(name)
        else:
            raise AssertionError("accepted " + name)

    rejected("previous registration",q["price_context"],fleet,dict(path=str(worker.parent/"V5F_ACTUAL_ADVANCING_WORKER.json"),sha256=digest))
    rejected("other receipt digest",q["price_context"],fleet,dict(ref,sha256="0"*64))
    for field in ("iid","parent_pid","child_pid","parent_ticks","child_ticks"):
        bad = dict(ctx)
        bad[field] = "0"*32 if field == "iid" else 1
        rejected(field,q["checked_owners"],bad)
    for field in ("old","failure","provider","semantic_provider","verifier","fleet"):
        fn = q["price_context"]
        read = q["read"]
        def crossed(bound,path,mode):
            item = read(bound,path,mode)
            if str(path) == ctx["intent"]["path"]:
                if field == "old":item[field] = "0"*32
                else:item[field] = dict(item[field],sha256="0"*64)
            return item
        with patch.dict(fn.__globals__,read=crossed):
            rejected(field,fn,fleet,ref)
    native, adapter = str(q["NATIVE"]), str(q["IMAGE"].parent/"incident-phase.py")
    err = f'  File "{native}", line 400, in phase145\n  File "{adapter}", line 155, in inspect\nValueError: foreign 145 descendants\n'.encode()
    seen = (99,100,7)
    check = q["accepted_overlap"]
    assert check(1,b"",err,seen)
    for label, args in (("partial",(1,b"{}",err,seen)), ("no probe",(1,b"",err,None)),("other status",(2,b"",err,seen)),
                        ("different traceback",(1,b"",err.replace(b"in inspect",b"in other"),seen)),
                        ("foreign qualifier",(1,b"",err.replace(b"145 descendants",b"qualifier unit"),seen))):
        assert not check(*args)
        negative.append(label)
    return dict(accepted_native_owner=ctx,rejected=negative,
                scope="read-only active PID1 and immutable original receipts",new_fixture_units=0)


if __name__ == "__main__":
    print(json.dumps(verify(Path(sys.argv[1]),Path(sys.argv[2]),sys.argv[3]),sort_keys=True))
