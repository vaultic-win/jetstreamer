"""Identity and live witness for the single privately leased epoch 169 diagnostic."""
import hashlib
import os
import re
import runpy
import stat
from pathlib import Path

R = Path("/var/lib/jetstreamer/horizon_runtime_data")
T = R / "epoch169-focused-terminal-20261121-v1"
A = R / "epoch169-focused-admission-20261120-v4"
P = R / "epoch169-focused-replay-20261120-g1/inputs-v1"
SAMPLE = R / "root154959-live166167170-20261121-v1/FOCUSED169_OBSERVATION.json"
ROOT = Path("/home/sol/.jetstreamer-private/epoch169-focused-diagnostic-20261117-v1")
V = ROOT / "v158"
ATT = ROOT / "attempt-g4"
LOCKROOT = ATT / "private/destination-3fe3d8794185d5eb0c7ff8c5bf4d9593ad5dcb3b5a6d72b0127e59f799c5d78d"
LOG = ATT / "producer.log"
LOCK = LOCKROOT / "locks/epoch-169.lock"
OUT = V / "epoch-169-through-73245218.jet"
MANIFEST = OUT.with_suffix(".jet.segment.json")
UNIT = "horizon-qualify-169-focused-20261120-v4.service"
IID = "0dfa0d36fbc246c28443a1c90a82c9cb"
TIMER = "horizon-guard-169-focused-20261120-v4.timer"
GUARD = TIMER.removesuffix(".timer") + ".service"
TIMER_IID = "bca3b97b4b5c45e2a63496975378be20"
WORKER = "44f39109586d7e2cabdb03e3b781949d64ed0c2a3591067b382a6eb590f77cf4"
PID, WPID = 3031007, 3031352
CAP = 96 << 30
SIG = "267mkJuiWWjRVYmTUjAEcLu9K3BmLos5h7tBkpXkYTyyJffVJ6Wn89cFrQvuEYXU8vASqvWkF1Mni7RSi1gGTG5c"
HASH = "5aXCD1ZXBe3fPYtrxvFkDvSvz8x68XiRmWfoEnLVLPif"
shared_path = R / "epoch172-current-delivery-20261121-v1/closure-tools/closure.py"
assert hashlib.sha256(shared_path.read_bytes()).hexdigest() == "1eda4eb778e73a8ab670df50980cad9208215f8d4854432d94f83f4054e92541"
shared = runpy.run_path(str(shared_path))
need, document, once = (shared[k] for k in ("need", "document", "once"))
boot = lambda: Path("/proc/sys/kernel/random/boot_id").read_text().strip()

def original():
    ad, ar = document(A/"ACTUAL_ADMISSION_AND_PROTECTION.json", 0o400, "2995f88a93200210cb376ea7be9437c4eee7b4783c6cc62e6805bbbb858d50b0")
    first, fr = document(A/"FIRST_GUARD.json", 0o400, "2171e599a25a23ae85a9a7ab1173fc5cfb88b2c64f1803f81213cd9b36975a90")
    plan, pr = document(A/"ACTUAL_GUARD_PLAN.json", 0o400, "3ddbafe25e1b5df2498d86b629ce6411e47c116b4377035f3a6690a504e1aa58")
    stage, sr = document(A/"VERIFIED_STAGING.json", 0o400, ad["snapshot_staging"]["sha256"])
    observation, obs = document(SAMPLE, 0o600, "c9bd3b5a4877857242c11e43c8f22d2ebd6e684c114577defc17b6b80728686d")
    need(observation["admission"] == ar and observation["first_guard"] == ad["first_guard"] == fr and sr == ad["snapshot_staging"]
         and ad["producer_pid"] == PID and plan["invocation_id"] == ad["producer_invocation_id"] == IID
         and plan["unit"] == ad["producer_unit"] == UNIT and plan["worker_root"] == str(ROOT) and plan["maximum_root_physical_bytes"] == CAP
         and first["timer"]["Id"] == TIMER and first["timer"]["InvocationID"] == TIMER_IID and first["timer"]["Triggers"] == GUARD
         and stage["native_preworker_log"] == observation["native_preworker_log"], "foreign 169 admission")
    proof, seal = document(P/"deployment-seal-receipt.json", 0o444, "2fe7d2fb8ca707b4b122662622587a1d00bf6981781609a2989a7ac7f6f42e69")
    members = {r["name"]: r for r in proof["members"]}
    inputs, ip = document(P/"input-proof.json", 0o444, members["input-proof.json"]["sha256"])
    need(inputs["verified_ed25519_signatures"][0] == SIG and inputs["canonical_error"] == {"InstructionError":[2,"ProgramFailedToComplete"]}
         and inputs["worker_sha256"] == WORKER and inputs["terminal_slot"] == 73245218 and inputs["canonical_log_lines"] == 50
         and inputs["canonical_logs_match_prior"] and inputs["signed_transaction_message_sha256"] == "5afa6b1fb68043e3dc4342e6bc12d9b195b7bc3afe5700620122555a8758a22b", "wrong finalized source")
    return dict(admission=ar, first_guard=fr, actual_guard_plan=pr, stage=sr, observation=obs, input_proof=ip, input_seal=seal), observation

def identity(path, directory=False):
    m = path.lstat()
    need(path.resolve(strict=True) == path and (m.st_dev,m.st_uid,m.st_gid) == (Path("/home/sol").stat().st_dev,1001,1003)
         and (stat.S_ISDIR(m.st_mode) and stat.S_IMODE(m.st_mode)==0o700 if directory else
              stat.S_ISREG(m.st_mode) and m.st_nlink==1 and stat.S_IMODE(m.st_mode)==0o600), "unsafe private member "+str(path))
    return dict(path=str(path),device=m.st_dev,inode=m.st_ino)

def layout():
    directories = [ROOT,V,ATT,LOCKROOT,LOCK.parent,LOCKROOT/"evidence/archive-batches"]
    return dict(booked_tree=identity(ROOT,True),directories=[identity(p,True) for p in directories],
                log=identity(LOG),lease=identity(LOCK),archive=identity(OUT))

def ticks(pid):
    return int(Path(f"/proc/{pid}/stat").read_text().rsplit(")",1)[1].split()[19])

def owner():
    refs, row = original()
    current = shared["manager"](UNIT)
    timer = shared["manager"](TIMER)
    need(current["InvocationID"]==IID and current["ActiveState"]=="active" and current["MainPID"]==str(PID)
         and not current["Job"] and timer["InvocationID"]==TIMER_IID and timer["ActiveState"]=="active" and timer["Triggers"]==GUARD, "original producer or timer unavailable")
    files = layout()
    worker = row["native_worker_at_consumption"]
    for pid,start,inode in ((PID,row["native_start_ticks"],101008876),(WPID,worker["start_ticks"],worker["inode"])):
        p = Path(f"/proc/{pid}")
        need(ticks(pid)==start and (p/"exe").stat().st_ino==inode and (p/"exe").stat().st_dev==files["log"]["device"]
             and (p/"cgroup").read_text().strip()=="0::/system.slice/"+UNIT, "different original native process")
    need(worker["pid"]==WPID and worker["sha256"]==WORKER and row["service_owned_stdout"]==files["log"]
         and set(map(int,(Path("/sys/fs/cgroup/system.slice")/UNIT/"cgroup.procs").read_text().split()))=={PID,WPID}, "unexpected focused worker")
    for pid,fd,member in ((PID,1,LOG),(PID,2,LOG),(WPID,2,LOG),(PID,10,LOCK),(PID,14,OUT),(PID,9,V),(PID,11,V)):
        p=Path(f"/proc/{pid}/fd/{fd}")
        need(p.samefile(member) and p.readlink()==member, "different original fd "+str(p))
        if member==LOG:
            flags=int(re.search(r"(?m)^flags:\s+([0-7]+)$",Path(f"/proc/{pid}/fdinfo/{fd}").read_text())[1],8)
            need(flags & os.O_APPEND and flags & os.O_ACCMODE == os.O_WRONLY,"non-append log")
    lock_info=Path(f"/proc/{PID}/fdinfo/10").read_text()
    need(re.search(rf"(?m)^lock:\s+\d+: FLOCK +ADVISORY +WRITE {PID} [0-9a-f]+:[0-9a-f]+:{files['lease']['inode']} 0 EOF$",lock_info), "original lease not held")
    worker_stdin=Path(f"/proc/{WPID}/fd/0").readlink()
    need(worker_stdin==Path(f"/proc/{PID}/fd/12").readlink() and Path(f"/proc/{WPID}/fd/1").readlink()==Path(f"/proc/{PID}/fd/13").readlink(), "different worker pipes")
    need(layout()==files and shared["manager"](UNIT)==current and ticks(PID)==row["native_start_ticks"] and ticks(WPID)==worker["start_ticks"],"owner changed")
    return dict(schema="focused169-original-owner-v1",boot_id=boot(),producer_unit=UNIT,producer_invocation_id=IID,timer_unit=TIMER,timer_invocation_id=TIMER_IID,
                original=refs,**files,producer_start_ticks=row["native_start_ticks"],worker=worker,prefix=row["native_preworker_log"],resource_credit_bytes=0)

if __name__ == "__main__":
    import sys
    import json
    need(sys.argv[1:]==["witness"] and os.geteuid()==0 and sys.flags.isolated and __debug__,"invalid witness call")
    print(json.dumps(once(T/"LIVE.json",owner())))
