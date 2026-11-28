"""Reconcile the clean 167 tail with its accepted native exit and last guarded HOME allocation."""
import hashlib
import json
import os
from pathlib import Path
import stat

ROOT = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch167-checkpoint-tail-20261127-v1")
UNIT = "horizon-qualify-167-checkpoint-tail-20261127-v1.service"
IID = "fd94e15f60df427c962ed1458f8e7efd"
DRAIN = dict(path=str(ROOT/"NATIVE_TAIL_AND_GUARD_DRAIN.json"),sha256="84f37a4cb4886968c932b624b47a7863fde5b115eff2bbd11a4255f4c5f4bee9")
PROGRESS = dict(path=str(ROOT/"FIRST_PROTECTED_PROGRESS.json"),sha256="753ade79e4e3873c18eb0cec83d17f879d8e0e08fa45b97c740e8f6c3a6a5fe6")
SAMPLE = dict(path=str(ROOT/"guard-receipts/sample-15052233835e4e38bf6212e76b0cc87e.json"),sha256="2e50f1745a87e379aa7cc7d70797f15f68bebff318a4dbba41525044f8170511")
RUN = Path("/home/sol/.jetstreamer-private/epoch167-standard-lane-20261109-v1/checkpoint-inputs-20261127-v1/tail-72509256-72582854-v1")
ARCHIVE = RUN/"output/epoch-167-checkpoint-tail-private.jet"
MANIFEST = ARCHIVE.with_name(ARCHIVE.name+".segment.json")


def observed(core, fleet, progress, ref):
    first = core["bound"](PROGRESS)
    need = core["need"]
    drain = core["bound"](DRAIN)
    row = fleet["current_bounded167_checkpoint_tail"]
    event = row["native_terminal"]
    need(row["phase"] == "terminal" and row["unit"]["Id"] == UNIT and row["actor"] == first["actor"] == progress["actor"]
         and row["release"] == first["release"] and ref == PROGRESS and row["actor"]["producer_invocation_id"] == IID
         and row["armed_floor"] == 9_487_309_623_189 and row["run_guard_cap_bytes"] == 80 << 30
         and not row["resource_credit_bytes"] and not row["archive_publication_authorized"]
         and event["_PID"] == "1" and event["_UID"] == "0" and event["UNIT"] == UNIT and event["INVOCATION_ID"] == IID
         and event["__REALTIME_TIMESTAMP"] == "1795846599221052" and event["_BOOT_ID"] == first["actor"]["boot_id"].replace("-","")
         and event["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448"
         and not any(r["epoch"] == 167 for key in ("actual_executing_replays","actual_active_private_diagnostics","actual_active_bootstraps") for r in fleet[key]),
         "accepted fleet does not contain the exact terminal 167 tail")
    group = Path("/sys/fs/cgroup/system.slice")/UNIT
    stopped = core["inactive"](UNIT)
    need(not stopped["ControlGroup"] and not group.exists(), "167 cgroup is no longer vacant")
    timer = UNIT.replace("-qualify-","-guard-").replace(".service",".timer")
    clock = core["state"](timer,"Id,ActiveState,Job,InvocationID")
    need(not clock["Job"] and clock["Id"] == timer and (clock["ActiveState"] == "inactive" and clock["InvocationID"] in ("",progress["guard"]["timer_invocation_id"])), "different 167 guard timer")
    guard = core["inactive"](timer.replace(".timer",".service"))
    native = drain["producer_terminal"]
    need(native == dict(boot=event["_BOOT_ID"],invocation=IID,manager_message_id=event["MESSAGE_ID"],
                        realtime_usec=event["__REALTIME_TIMESTAMP"],unit=UNIT)
         and drain["guard_timer"]["Id"] == timer and drain["guard_timer"]["ActiveState"] == "inactive"
         and drain["guard_service"]["Id"] == guard["Id"] and not guard["ControlGroup"]
         and not drain["resource_credit_bytes"] and not drain["canonical_publication_authorized"],
         "167 producer or protective guard no longer match their drain")
    retained = core["bound"](SAMPLE)
    floor = row["armed_floor"]
    need(retained["plan_sha256"] == progress["guard"]["plan"]["sha256"]
         and retained["producer"]["pid"] == progress["actor"]["producer_pid"] and retained["producer_invocation_id"] == IID
         and retained["minimum_free_bytes"] == floor and retained["producer_stop_enabled"] and retained["trip_reason"] is None
         and retained["worker_observation_error"] is retained["root_physical_observation_error"] is None
         and retained["root_physical_observation"]["maximum_physical_bytes"] == row["run_guard_cap_bytes"]
         and core["bound"](progress["guard"]["plan"])["worker_root"] == str(RUN),"different retained 167 guard")
    archive = ARCHIVE.lstat()
    metadata = MANIFEST.lstat()
    source = MANIFEST.read_bytes()
    manifest = json.loads(source)
    need(ARCHIVE.resolve() == ARCHIVE and MANIFEST.resolve() == MANIFEST and stat.S_ISREG(archive.st_mode)
         and stat.S_ISREG(metadata.st_mode) and archive.st_dev == metadata.st_dev == RUN.stat().st_dev
         and archive.st_ino == 112853028 and archive.st_nlink == metadata.st_nlink == 1 and archive.st_size == 20_279_360_388
         and hashlib.sha256(source).hexdigest() == "0e37cbfe70459e93ce4d3a6e8a06e75ca4e66a7161a9553c593d7a4665d155f1"
         and manifest["epoch"] == 167 and manifest["terminal"]["slot"] == 72_582_854 and manifest["output_slot_count"] == 73598,
         "closed 167 output or manifest changed")
    stamps = []
    for path, info in ((ARCHIVE,archive),(MANIFEST,metadata)):
        stamps.append(dict(path=str(path),dev=info.st_dev,ino=info.st_ino,bytes=info.st_size,
                           mtime_ns=info.st_mtime_ns,ctime_ns=info.st_ctime_ns,uid=info.st_uid,gid=info.st_gid,mode=oct(stat.S_IMODE(info.st_mode))))
    need(stamps == drain["source_stamps"] and drain["closed_manifest"] == dict(path=str(MANIFEST),sha256=hashlib.sha256(source).hexdigest())
         and manifest["archive_sha256"] == drain["declared_archive_sha256"], "closed 167 custody stamps changed")
    # The still-occupied, single-link archive alone supplies this lower bound. The uncredited
    # balance of the previous 80-GiB growth booking and the full 42-GiB producer slot stay protected.
    lower = min(archive.st_blocks*512, core["physical"](retained))
    need(lower > 0 and lower <= row["run_guard_cap_bytes"] and os.path.samestat(archive,ARCHIVE.lstat())
         and os.path.samestat(metadata,MANIFEST.lstat()),"167 retained allocation changed")
    return dict(record=PROGRESS, drain=DRAIN, terminal_event=event["__CURSOR"], final_native_guard=SAMPLE, unit=UNIT,
                invocation=IID, guard_floor=floor, occupied_archive_lower_bytes=lower,
                retained_ram=42<<30, released_ram=0, output_bytes=archive.st_size, resource_credit_bytes=0)


def reserve(core, final, native):
    """Partition the vacant original 167 booking once without reducing its full charge."""
    state = native["raw"]["joint"]["closed_167_tail"]
    intent = core["bound"](core["bound"](state["record"])["actor"]["intent"])
    price = intent["quote"]
    core["need"]("closed_167_suballocations" not in final and state["drain"] == DRAIN
                 and native["raw"]["tail_ram_resident"] == 0 and state["released_ram"] == 0
                 and price["producer_memory_bytes"] == state["retained_ram"] == 42<<30
                 and price["guard_memory_bytes"] == 1<<30 and intent["run_guard_cap_bytes"] == 80<<30,
                 "changed or previously partitioned 167 allocation")
    producer_quota = price["producer_cpu_quota_micros"]
    core["need"](producer_quota == 3_000_000 and final["ram_margin"] <= native["available_ram"], "changed 167 CPU or RAM reservation")
    source = dict(ram_bytes=4<<30,cpu_micros_per_second=1_000_000,home_evidence_bytes=16<<20,archive_scratch_bytes=0)
    build = dict(ram_bytes=768<<20,cpu_micros_per_second=500_000,home_evidence_bytes=16<<20)
    unassigned = dict(ram_bytes=state["retained_ram"]-source["ram_bytes"]-build["ram_bytes"],
                      cpu_micros_per_second=producer_quota-source["cpu_micros_per_second"]-build["cpu_micros_per_second"],
                      home_bytes=intent["run_guard_cap_bytes"]-state["occupied_archive_lower_bytes"]-source["home_evidence_bytes"]-build["home_evidence_bytes"])
    core["need"](min(unassigned.values()) >= 0,"167 suballocations exceed its retained booking")
    final["closed_167_suballocations"] = dict(source_qualification=source,epoch168_classifier_build=build,
            unassigned=unassigned, native_drain=DRAIN, retained_producer_ram=state["retained_ram"],
            retained_cpu_micros_per_second=producer_quota, retained_tree_cap=intent["run_guard_cap_bytes"],
            guard_ram_separate=price["guard_memory_bytes"], additional_home=0, additional_ram=0,
            replay_execution_authorized=False, archive_publication_authorized=False)
