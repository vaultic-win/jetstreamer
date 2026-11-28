"""Prepare or release the private 169 bootstrap with its exact held start and live floor."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import runpy
import stat
import subprocess
import time

HERE = Path(__file__).resolve().parent
base = runpy.run_path(str(HERE / "bindings.py"))
capacity = runpy.run_path(str(HERE / "split_capacity.py"))
a, h, gate = (base[k] for k in ("a", "h", "g"))
scope = runpy.run_path(str(HERE / "scratch_mount.py"))
prep = runpy.run_path(str(HERE / "prepare.py"))
C, UNIT, need = base["C"], base["UNIT"], h["need"]
DEP = C / "issued-split-v1"
WROOT = C.parent / "survivor172-cadence-20261122-v1"
ACTIVE = WROOT / "FAILED166_CADENCE_V48_ACTIVE.json"
IMAGE = WROOT / "tools-cold168-retry5-failed166-v48-entry146"
LOCK = Path("/run/horizon-epoch171-to136-g1.operation.lock")
NEW_SOURCE = "epoch169-hourly-tmpfs-first-guard-intent-v1"
M = 1 << 20


def put(path, data, mode=0o400):
    """Publish a complete, durable and immutable receipt exactly once."""
    if not isinstance(data, bytes):
        data = (json.dumps(data, sort_keys=True, indent=2) + "\n").encode()
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{time.time_ns()}")
    fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fchmod(f.fileno(), mode)
            os.fsync(f.fileno())
        try:
            os.link(tmp, path, follow_symlinks=False)
        except FileExistsError:
            st = path.lstat()
            need(path.resolve(strict=True) == path and stat.S_ISREG(st.st_mode) and st.st_uid == 0
                 and st.st_nlink == 1 and stat.S_IMODE(st.st_mode) == mode and path.read_bytes() == data,
                 "foreign existing " + str(path))
        tmp.unlink()
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(parent)
        finally: os.close(parent)
    finally:
        tmp.unlink(missing_ok=True)
    return base["ref"](path)


def setup():
    need(capacity["seal"]() and not any((C / name).exists() for name in
         ("START_INTENT.json", "GRANT.json", "HELD_GATE.json", "results/TERMINAL.json")),
         "previous 169 attempt is already recorded")
    lane, run, dest, bind = (h[k] for k in ("LANE", "RUN", "DEST", "BIND"))
    def directory(p, uid, gid, mode):
        if not p.exists():
            p.mkdir(mode=mode)
            os.chown(p, uid, gid)
            p.chmod(mode)
        st = p.lstat()
        need(p.resolve(strict=True) == p and stat.S_ISDIR(st.st_mode) and
             (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) == (uid, gid, mode), "foreign path " + str(p))
    for p in (dest, dest/"compact-indexes", dest/"compact-indexes/168", dest/"compact-indexes/169", scope["SCRATCH"],
              run, run/"tmp", run/"private"):
        directory(p,1001,1003,0o700)
    for p in (C/"results",C/"guard-plan",lane/"hourly-guard-receipts"):
        directory(p,0,0,0o700)
    directory(bind,0,0,0o755)
    for p in (scope["SCRATCH"], run/"tmp", run/"private", lane/"hourly-guard-receipts",
              dest/"compact-indexes/168", dest/"compact-indexes/169"):
        need(not any(p.iterdir()), "occupied prestart directory " + str(p))
    recipe = h["launch_recipe"]()
    put(dest/"epoch-hashes-169-focused.txt", recipe["source_hash_manifest"].encode(), 0o444)
    need(h["sha"](dest/"epoch-hashes-169-focused.txt") == recipe["source_hash_manifest_sha256"], "changed checkpoints")
    need(not os.path.lexists(bind/"allow.json") and not os.path.lexists(recipe["output"])
         and not os.path.lexists(recipe["output"]+".segment.json"), "existing 169 output or grant")
    watcher = C/"sealed"/base["WATCH"]
    service = h["producer_service"](split_scratch=True).encode()
    for suffix,data in ((UNIT,service), (base["WATCH"],watcher.read_bytes())):
        put(Path("/run/systemd/system")/suffix, data, 0o644)
    subprocess.run(["/usr/bin/systemctl", "daemon-reload"],check=True)
    base["verified_watcher"]()
    need(a["props"](UNIT, ["FragmentPath"])["FragmentPath"] == "/run/systemd/system/"+UNIT,
         "systemd did not select the split-scratch service")
    return dict(service=base["ref"](Path("/run/systemd/system")/UNIT), watcher=base["verified_watcher"]())


def writer():
    active, ref = base["locked"](ACTIVE)
    ready = a["pinned"](active["ready"])
    old = a["pinned"](ready["old_owner"])
    owner = active["new"]
    need(ready["old_owner"]["sha256"] == "def64d8842984dee1835c05aefa8b5f344c52f9b97e8691db123b1cce2daca86"
         and old["new"] == active["old"] and owner["lock"] == old["new"]["lock"]
         and owner["unit"] == old["new"]["unit"] and owner["program"] == str(IMAGE/"status_cycle.py")
         and ready["split169_provider"] == capacity["seal"]()
         and ready["split169_reader"] == base["ref"](IMAGE/"split_status169.py") and
         ready["package"] == base["ref"](IMAGE/"deployment-seal-receipt.json"), "V48 did not enroll this exact 169 provider")
    props = a["props"](owner["unit"], ["Id", "MainPID", "InvocationID", "ActiveState", "ExecStart", "Job"])
    proc = Path("/proc") / str(owner["pid"])
    lock = (proc/"fd"/str(owner["lock"]["fd"])).stat()
    need(props["ActiveState"] == "active" and not props["Job"] and props["InvocationID"] == owner["invocation_id"]
         and props["MainPID"] == str(owner["pid"]) and owner["program"] in props["ExecStart"]
         and os.fsencode(owner["program"]) in (proc/"cmdline").read_bytes().split(b"\0")
         and int((proc/"stat").read_text().rsplit(") ",1)[1].split()[19]) == owner["start_ticks"]
         and (lock.st_dev,lock.st_ino) == (owner["lock"]["device"],owner["lock"]["inode"]), "different active cadence writer")
    return dict(active=ref, package=ready["package"], reader=ready["split169_reader"])


def price(*, separate_162=False):
    # Both new package trees and their deployment metadata are charged against
    # the historical limit even after the current statvfs has seen their bytes.
    total = 0
    for directory in (IMAGE, C.parent/"epoch143-first-hourly-20261127-v1/booking-price-v48", DEP):
        for p in directory.iterdir():
            st = p.lstat()
            need(p.resolve() == p and stat.S_ISREG(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o222,
                 "unexpected deployed package member")
            total += max(st.st_blocks*512, (st.st_size+4095)//4096*4096)
    return capacity["quote"](include_writer_overhead=total, separate_162=separate_162)


def prestart():
    current_writer = writer()
    source = h["sources"]()
    bank = Path(h["bound"]({"path":source["169"]["receipt"],"sha256":source["169"]["sha256"]})["destination"])
    st = h["same_file"](bank,source["169"]["file"])
    release = h["pin"](h["RELEASE"],h["RELEASE_SHA"])
    for key in ("node","worker"):
        file = Path(release[key]["path"])
        meta = file.lstat()
        need(file.resolve() == file and meta.st_uid == 0 and not meta.st_mode & 0o222
             and h["sha"](file) == release[key]["sha256"], "changed sealed " + key)
    indexes = prep["indexes"]()
    q = price()
    need(q["actor"] is None and q["fits"] and q["phase"] == "prestart" and writer() == current_writer
         and h["same_file"](bank,source["169"]["file"]).st_ctime_ns == source["169"]["verified_ctime_ns"],
         "prestart lacks a current four-owner fit")
    return dict(schema="horizon-169-split-prestart-v1", fleet=q["fleet"], boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                sources=source, source_indexes=indexes, verified_release=release, price=q, writer=current_writer,
                bank=str(bank), snapshot_identity=[st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns],
                initial_physical=st.st_blocks*512, canonical_publication_authorized=False)


def basis():
    pre, ref = base["locked"](C/"PRESTART.json")
    st = h["same_file"](Path(pre["bank"]), pre["sources"]["169"]["file"])
    need(pre["schema"] == "horizon-169-split-prestart-v1" and pre["price"]["fits"] and
         pre["price"]["provider"] == capacity["seal"]() and pre["writer"] == writer() and
         pre["snapshot_identity"] == [st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns] and
         st.st_blocks*512 == pre["initial_physical"], "different held prestart or input custody")
    return pre, ref


def first(sample_path):
    pre, pre_ref = basis()
    manager, ticks = base["owner"]()
    iid, pid = manager["InvocationID"], int(manager["MainPID"])
    held, held_ref = base["locked"](C/"HELD_GATE.json")
    plan, plan_ref = base["locked"](C/"guard-plan/guard-plan.json")
    expected = h["guard_plan"](iid, pre["price"]["guard_floor"], pre["initial_physical"] + scope["OUTPUT_ALLOWANCE"])
    mount = scope["native"](pid)
    need(held["invocation_id"] == iid and held["pid"] == pid and held["start_ticks"] == ticks
         and held["private_scratch_mount"] == mount and plan == expected, "unbound held scratch or guard")
    sample, sr = base["locked"](sample_path)
    timer = a["props"](h["GUARD_UNIT"]+".timer", ["Id","ActiveState","Job","Triggers","InvocationID"])
    guard = a["props"](h["GUARD_UNIT"]+".service", ["Id","InvocationID","Result","ExecMainStatus","Job","TriggeredBy"])
    need(sample_path == Path(plan["receipt_directory"])/("sample-"+sample["guard_invocation_id"]+".json") and
         sample["plan"] == plan_ref["path"] and 0 <= time.time()-sample["recorded_unix_seconds"] <= 45,
         "different first guard sample")
    h["first_guard"](sample,plan,plan_ref["sha256"],manager,timer,guard)
    return dict(schema=NEW_SOURCE, unit=UNIT, pid=pid, producer_invocation_id=iid, start_ticks=ticks, boot_id=pre["boot_id"],
                held_gate=held_ref, previous_producer_iid="0dfa0d36fbc246c28443a1c90a82c9cb",
                previous_terminal=a["pinned"](pre["fleet"])["focused169_terminal"], timer_iid=timer["InvocationID"],
                sealed_node=pre["verified_release"]["node"], guard_plan=plan_ref, first_guard=sr, timer=timer, guard=guard,
                watcher=base["verified_watcher"](), original_prestart=pre_ref, prestart_physical_bytes=pre["initial_physical"],
                actor_memory_bytes=68<<30, guard_memory_bytes=1<<30, actor_cpu_micros=3_000_000,
                guard_cpu_micros=1_000_000, fixed_control_allowance=scope["CONTROL_ALLOWANCE"],
                charged_worker_growth=scope["OUTPUT_ALLOWANCE"], private_scratch_mount=mount, canonical_publication_authorized=False)


def grant():
    pre, pre_ref = basis()
    intent, ir = base["locked"](C/"START_INTENT.json")
    post, pr = base["locked"](C/"POST_GUARD_CAPACITY.json")
    manager,ticks = base["owner"]()
    held = a["before"](a["pinned"](pre["fleet"]), split_scratch=True)
    pid,iid = int(manager["MainPID"]),manager["InvocationID"]
    need(post["fits"] and post["phase"] == "postguard" and post["actor"]["phase"] == "held"
         and post["provider"] == pre["price"]["provider"] and post["fleet"] == pre["fleet"]
         and post["actor"]["binding"] == held and held["held"] and intent["original_prestart"] == pre_ref
         and post["actor"]["hourly169_start_intent"] == ir and 0 <= time.time()-post["recorded_unix_seconds"] <= 90
         and base["verified_watcher"]() == intent["watcher"] and held["producer_iid"] == iid, "fifth actor postguard price changed")
    sample,_ = a["newest_guard"](held)
    capacity["actor"]["price_guard"](held, sample, time.time())
    log = h["RUN"] / "producer.log"; st=log.lstat()
    need(log.resolve() == log and st.st_nlink == 1 and st.st_size == 0 and (Path("/proc")/str(pid)/"fd/1").samefile(log),
         "foreign pre-payload log")
    doc = dict(schema="epoch169-hourly-private-postguard-release-v1",unit=UNIT,invocation_id=iid,
              pid=pid,start_ticks=ticks,boot_id=intent["boot_id"],issued_unix_seconds=int(time.time()),
              first_guard_sha256=intent["first_guard"]["sha256"],native_post_guard_price_sha256=pr["sha256"],
              registered_watcher_sha256=hashlib.sha256(json.dumps(intent["watcher"],sort_keys=True).encode()).hexdigest(),
              verified_source_receipt_sha256=pre["sources"]["169"]["sha256"],guard_plan_sha256=intent["guard_plan"]["sha256"],
              snapshot_sha256=pre["sources"]["169"]["file"]["sha256"],snapshot_identity=pre["snapshot_identity"],
              producer_cpu_micros=3000000,guard_cpu_micros=1000000,memory_max=68<<30,guard_memory_max=1<<30,
              log_device=st.st_dev,log_inode=st.st_ino,private_scratch_mount=held["private_scratch_mount"],
              canonical_publication_authorized=False)
    gate["verify_grant"](doc,iid,pid,ticks,doc["boot_id"],time.time())
    return doc


def launch():
    setup()
    proposal = prestart()
    put(C/"PRESTART.json", proposal)
    subprocess.run(["/usr/bin/systemctl","start", UNIT],check=True)
    producer,ticks = base["owner"]()
    pid,iid = int(producer["MainPID"]),producer["InvocationID"]
    held = dict(unit=UNIT,invocation_id=iid,pid=pid,start_ticks=ticks,boot_id=proposal["boot_id"],private_scratch_mount=scope["native"](pid))
    put(C/"HELD_GATE.json",held)
    plan = h["guard_plan"](iid, proposal["price"]["guard_floor"], proposal["initial_physical"]+scope["OUTPUT_ALLOWANCE"])
    plan_path = C/"guard-plan/guard-plan.json"
    ref = put(plan_path,plan)
    argv = h["guard_argv"](plan_path,ref["sha256"])
    subprocess.run(argv[-6:]+["--validate-plan-only"],check=True)
    subprocess.run(argv,check=True)
    deadline=time.monotonic()+65
    while True:
        files=sorted(Path(plan["receipt_directory"]).glob("sample-*.json"),key=lambda p:p.stat().st_mtime_ns)
        if files:
            try:
                intent=first(files[-1])
            except ValueError as error:
                if "was not a timer completion" not in str(error):
                    raise
            else:
                break
        need(time.monotonic()<deadline, "169 gate expired waiting for the first guard")
        time.sleep(.15)
    put(C/"START_INTENT.json",intent,0o444)
    post = price()
    need(post["fits"] and post["actor"] and post["actor"]["phase"]=="held", "169 fifth actor did not fit after its guard")
    put(C/"POST_GUARD_CAPACITY.json",post)
    released=grant()
    proof=put(C/"GRANT.json",released,0o444)
    put(h["BIND"]/"allow.json",(C/"GRANT.json").read_bytes(),0o444)
    return dict(grant=proof, invocation_id=iid, private_epoch=169)


if __name__ == "__main__":
    parser=argparse.ArgumentParser(__doc__)
    parser.add_argument("stage",choices=("initial-quote","price","prestart","setup","launch","grant","first"))
    parser.add_argument("sample",type=Path,nargs="?")
    args=parser.parse_args()
    with LOCK.open("rb") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        if args.stage=="initial-quote": obj=capacity["quote"]()
        elif args.stage=="first": obj=first(args.sample)
        else: obj=globals()[args.stage]()
    print(json.dumps(obj,sort_keys=True,indent=2))
