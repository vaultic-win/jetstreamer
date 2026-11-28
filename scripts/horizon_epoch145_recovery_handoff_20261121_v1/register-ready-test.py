"""Exercise the registrar on HOME fixtures; none of the paths are live registrations."""
from contextlib import contextmanager
from pathlib import Path
import fcntl
import json
import os
import runpy
import sys
import subprocess
import tempfile

REG = runpy.run_path(str(Path(__file__).with_name("register-ready.py")))
FIXTURE = len(sys.argv) == 3 and sys.argv[2] == "--fixture"
RETRY = len(sys.argv) == 5 and sys.argv[2] == "--retry1"
assert len(sys.argv) == 2 or FIXTURE or RETRY
FAMILY = runpy.run_path(str(Path(__file__).with_name("register-fixture-ready.py"))) if FIXTURE else REG
if RETRY:
    retry = runpy.run_path(str(Path(__file__).with_name("register-retry-ready.py")))
    # Resolve the compiled inputs while the sealed selector is still visible in this namespace.
    bindings = retry["compiled_refs"](sys.argv[3])
    handoff = retry["inputs"](bindings, sys.argv[4])
    FAMILY = dict(DIRECTORY=retry["directory"], SEMANTIC=retry["iid"], handoff_inputs=lambda: handoff)
ROOT = Path(sys.argv[1]).resolve(strict=True)
assert ROOT.is_relative_to("/home/sol/.jetstreamer-private") and os.geteuid() == 0 and sys.flags.isolated


class Crash(Exception):
    pass


def exercise(base, fail_after=None, change_owner=False, native=False):
    directory=base/"dispatch"
    writer=base/"writer"
    for p in (directory, directory/"state", writer):
        p.mkdir(mode=0o700)
    if (FIXTURE or RETRY) and native:
        # The native parent authenticates the canonical READY path before it exists.
        # Expose this empty test directory there only in a private mount namespace.
        target=FAMILY["DIRECTORY"]
        assert not Path("/proc/self/ns/mnt").samefile("/proc/1/ns/mnt")
        mode=subprocess.check_output(["findmnt","-n","-o","PROPAGATION","-T",str(target)],text=True)
        assert mode.strip()=="private" and not directory.samefile(target)
        subprocess.run(["mount","--bind",directory,target],check=True)
        mounted=subprocess.check_output(["findmnt","-n","-o","TARGET","--mountpoint",str(target)],text=True)
        assert mounted.strip()==str(target) and directory.samefile(target)
        directory=target
    op=base/"original-operation.lock"
    op.touch(mode=0o600)
    identity=REG["lock_identity"](op)
    flags={"held":False,"owner":41,"published":False,"crashed":False}
    semantic=FAMILY["SEMANTIC"]
    events=[]

    def ready():
        return dict(schema="horizon-145-136-prestart-selector-ready-v1",original_semantic_invocation=semantic,
                    operation_lock=identity,dispatcher={"pid":flags["owner"]})
    @contextmanager
    def take(expected):
        assert expected==identity
        with op.open("r+b") as f:
            fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
            REG["holder"](identity,os.getpid())
            flags["held"]=True
            try:yield
            finally:flags["held"]=False

    def free(expected):
        assert expected==identity and not flags["held"] and not REG["locks"](identity)
        with op.open("r+b") as f:
            fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)

    def store(p,data):
        if p.name=="READY.json":
            free(identity)
            assert (directory/"OFFER.json").is_file() and (directory/"state"/REG["INSPECTION"]).is_file()
        else:
            assert flags["held"] and not (directory/"READY.json").exists()
        r=REG["publish"](p,data)
        events.append(p.name)
        if not flags["crashed"] and p.name==fail_after:
            flags["crashed"]=True
            raise Crash()
        if change_owner and p.name=="OFFER.json":
            flags["owner"]+=1
        return r

    if native:
        inputs=FAMILY["handoff_inputs"]
    else:
        def inputs():
            return {"original":"fixture"}, {"parent":{"path":"fixture-parent","sha256":"0"*64}}

    def inspect(plan,parent):
        assert flags["held"] and not (directory/"READY.json").exists()
        assert REG["read_ref"](plan)["holding145_prestart_ready"]==REG["binding"](directory/"READY.json",REG["encoded"](ready()))
        events.append("inspect")
        if native:
            return REG["inspect_plan"](plan,parent)
        return dict(writer_plan=plan,**{k:False for k in REG["NO_ACTION"]})

    def run():
        return REG["registration"](directory,writer,ready,lambda:None,take,free,inputs,inspect,store)

    if change_owner:
        try:run()
        except ValueError as e:assert "dispatcher changed before READY" in str(e)
        else:raise AssertionError("foreign owner committed READY")
        assert not (directory/"READY.json").exists()
        return {"changed_owner":"rejected","marker":False}

    if fail_after is not None:
        try:run()
        except Crash:pass
        else:raise AssertionError("missing crash injection")
        assert (directory/"READY.json").exists() == (fail_after=="READY.json")
    retained={p:p.stat().st_ino for p in [writer/"registered-production-plan.json",directory/"OFFER.json",directory/"state"/REG["INSPECTION"]] if p.exists()}
    result=run()
    assert all(p.stat().st_ino==inode for p,inode in retained.items())
    check=REG["read_ref"](result["offer"])
    assert check["selector"]==result["ready"]==REG["read_ref"](result["writer_plan"])["holding145_prestart_ready"]
    previous=events.copy()
    assert run()==result and previous==events
    if native:
        assert events==["registered-production-plan.json","inspect",REG["INSPECTION"],"OFFER.json","READY.json"]
    return {"events":events,"same_owner_noop":True,"prior_inodes_preserved":True,"native_parent":native}


def main():
    result={}
    with tempfile.TemporaryDirectory(dir=ROOT) as temp:
        staging=Path(temp)
        for case in ("registered-production-plan.json",REG["INSPECTION"],"OFFER.json","READY.json"):
            p=staging/case
            p.mkdir()
            result[case]=exercise(p,case)
        p=staging/"crossed"
        p.mkdir()
        result["changed_owner"]=exercise(p,change_owner=True)
        p=staging/"real-parent"
        p.mkdir()
        result["real_parent"]=exercise(p,native=True)
    print(json.dumps(result,sort_keys=True))


if __name__=="__main__":
    main()
