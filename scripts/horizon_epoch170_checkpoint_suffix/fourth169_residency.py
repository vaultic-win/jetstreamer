"""Measure the guarded fourth 169 cgroup and its private noswap mount across shared availability."""
import os
from pathlib import Path

ROOT = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch169-hourly-retry-20261128-v4")
UNIT = "horizon-qualify-169-hourly-retry-20261128-v4.service"
SCOPE = dict(path=str(ROOT / "SCOPE.json"), sha256="f74d0b1dd33abe2b03705f3c69af3a74b27784bb293f69aff1f913fecf24ddb5")
LIMIT = 56 << 30
SCRATCH = 44 << 30


def sample(core, receiver, fleet, owner, memory):
    if not owner or owner["phase"] != "worker":
        return None
    row = receiver["current"](fleet)
    intent = core.bound(owner["intent"])
    grant = core.bound(owner["release"])
    scope = core.bound(SCOPE)
    evidence = Path(row["guard"]["path"])
    guard, ref = receiver["c"].read(evidence, sealed=False)
    group_path = "/system.slice/" + UNIT
    group = Path("/sys/fs/cgroup") / group_path.lstrip("/")
    node = owner["pid"]
    worker = row["worker"]
    processes = row["processes"]
    pids = {p[0] for p in processes}
    mount = intent["private_scratch_mount"]
    stop = Path(core.bound(owner["guard_plan"])["receipt_directory"]) / "stop-intent.json"
    core.need(ref == row["guard"] and evidence.parent == stop.parent and evidence.name == "sample-" + guard["guard_invocation_id"] + ".json"
              and row["phase"] == "worker" and row["guard_plan"] == owner["guard_plan"]
              and row["intent"] == owner["intent"] and row["release"] == owner["release"]
              and intent["scope"] == SCOPE and row["invocation_id"] == owner["invocation"] == grant["invocation_id"]
              and row["unit"]["Id"] == intent["unit"] == grant["unit"] == scope["producer_unit"] == owner["unit"] == UNIT
              and int(row["unit"]["MainPID"]) == row["actor"]["producer_pid"] == intent["pid"] == grant["pid"] == node
              and scope["quota"]["producer_ram"] == intent["actor_memory_bytes"] == grant["memory_max"] == LIMIT
              and scope["quota"]["scratch"] == mount["ram_limit_bytes"] == SCRATCH and mount["type"] == "tmpfs" and mount["noswap"]
              and mount == grant["private_scratch_mount"] == intent["namespace"]["scratch"]
              and len(processes) == 2 and pids == {node, worker["pid"]} and node != worker["pid"]
              and processes[0][:2] == [node, grant["start_ticks"]] and processes[1] == [worker[k] for k in ("pid","start_ticks","device","inode")]
              and worker["device"] == mount["device"] and guard["producer_invocation_id"] == owner["invocation"]
              and guard["producer"]["pid"] == node and guard["producer"]["cgroup"] == group_path
              and guard["producer_stop_enabled"] and guard["trip_reason"] is None and guard["plan_sha256"] == owner["guard_plan"]["sha256"]
              and [pid for pid,_ in guard["workers"]] == [worker["pid"]], "different 169 worker, release, guard or scratch")
    scratch = Path(mount["path"])
    projected = Path("/proc") / str(node) / "root" / scratch.relative_to("/")

    def recheck():
        core.need(not os.path.lexists(stop) and set(map(int, (group/"cgroup.procs").read_text().split())) == pids
                  and receiver["namespace"].inspect(node)["scratch"] == mount, "169 guard, cgroup or mount changed")
        node_ns = Path("/proc") / str(node) / "ns/mnt"
        for pid, ticks, device, inode in processes:
            proc = Path("/proc") / str(pid)
            exe = (proc/"exe").stat()
            core.need((proc/"cgroup").read_text().strip() == "0::" + group_path and node_ns.samefile(proc/"ns/mnt")
                      and (exe.st_dev,exe.st_ino) == (device,inode)
                      and int((proc/"stat").read_text().rsplit(") ",1)[1].split()[19]) == ticks, "169 process changed")

    def occupied():
        vfs = os.statvfs(projected)
        core.need(vfs.f_frsize * vfs.f_blocks == SCRATCH, "different 169 scratch size")
        return vfs.f_frsize * (vfs.f_blocks-vfs.f_bfree)

    recheck()
    earlier = memory["memory"](group)
    earlier_usage = occupied()
    anon = []
    for pid, *_ in processes:
        fields, = (line.split() for line in (Path("/proc")/str(pid)/"smaps_rollup").read_text().splitlines() if line.startswith("Pss_Anon:"))
        core.need(len(fields) == 3 and fields[2] == "kB" and fields[1].isdecimal(), "invalid 169 proportional anonymous memory")
        anon.append(int(fields[1])*1024)
    later_usage = occupied()
    later = memory["memory"](group)
    recheck()
    paid = memory["lower"](earlier,later,sum(anon),min(earlier_usage,later_usage),scratch_limit=SCRATCH)
    return dict(intent=owner["intent"], release=owner["release"], plan=owner["guard_plan"], guard=row["guard"],
                scope=SCOPE, invocation=owner["invocation"], timer=intent["timer_iid"], processes=processes, mount=mount,
                pss_anon=anon, scratch_used=[earlier_usage,later_usage], before=earlier, after=later, realized=paid)


def apply(core, native, initial, final, first169):
    replacement = native["planned_169_retry"]
    core.need("fourth169_residency" not in native and native["required_ram"] >= LIMIT
              and native["ram_margin"] == native["available_ram"] - native["required_ram"]
              and replacement["fourth_scope"] == SCOPE and replacement["additional_ram"] == 8 << 30
              and native["stopped_169_compute_handoff"]["retained_159_ram"] + replacement["additional_ram"] == LIMIT
              and first169["phase"] == "terminal" and not native["resource_credit_bytes"],
              "unregistered or already counted 169 reservation")
    actor = native["independent_retry169"]
    paid = 0
    if actor and actor["phase"] == "worker":
        stable = ("intent","release","plan","scope","invocation","timer","processes","mount")
        core.need(initial and final and all(initial[k] == final[k] for k in stable)
                  and initial["release"] == actor["release"] and initial["intent"] == actor["intent"]
                  and initial["invocation"] == actor["invocation"] and initial["plan"] == actor["guard_plan"]
                  and all(0 <= v["realized"] <= LIMIT for v in (initial,final)), "169 changed across host availability")
        paid = min(initial["realized"],final["realized"])
    else:
        core.need(initial is final is None, "169 resident measurement without a guarded worker")
    native["required_ram"] -= paid
    native["ram_margin"] += paid
    native["fourth169_residency"] = dict(before=initial,after=final,realized_bytes=paid,remaining_bytes=LIMIT-paid,
                                          full_producer_limit=LIMIT, guard_separately_reserved=True, resource_credit_bytes=0)
