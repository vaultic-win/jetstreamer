"""Charge one bounded new 169 output while the fourth interval stays in private custody."""
import os
from pathlib import Path
import runpy
import stat

G = 1 << 30
CONTROL = 64 << 20
OUTPUT = 4*G
LIMIT = 56*G
ROOT = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch169-from-73245218-20261128-v1")
PRIOR = ROOT.with_name("epoch169-hourly-retry-20261128-v4")
UNIT = "horizon-qualify-169-from-73245218-20261128-v1.service"
FIELD = "current_private169_adjacent_hourly"
PKG = ROOT/"operator-v1"
OLD_UNIT = "horizon-qualify-169-hourly-retry-20261128-v4.service"
OLD_IID = "89f12725fa804408958878cb5cb8ca55"
TERMINAL = dict(path=str(PRIOR/"results/TERMINAL.json"),sha256="9c651de5f079ef6aef3227ad95546e3faeb83aab01bf5158a3968594bc3f4c93")
DONOR = dict(path=str(PRIOR/"START_INTENT.json"),sha256="d1837511edc09d506d6ba851d94b53ba5d5c67df6390bd0df36c8624443f35fa")


def need(ok, message):
    if not ok:
        raise ValueError(message)


def prior_fleet(peer,fleet):
    row = fleet.get(FIELD)
    registered = [v for v in fleet["actual_active_private_diagnostics"] if v["epoch"] == 169]
    if not row or row["phase"] == "terminal":
        need(not registered,"foreign live 169 on a closed reservation")
        return fleet
    held, ref = peer["read"](ROOT/"split-v1/HELD_OWNER.json")
    need(row["phase"] in ("held","bootstrap","worker") and row["unit"]["Id"] == held["producer_unit"] == UNIT
         and row["held_owner"] == ref and row["actor"] == held and registered == [row]
         and row["producer_invocation_id"] == row["unit"]["InvocationID"] == held["producer_invocation_id"]
         and not row["canonical_replay_claimed"] and not row["archive_publication_authorized"] and not row["resource_credit_bytes"],
         "unregistered 169 row in original receiver")
    return dict(fleet,actual_active_private_diagnostics=[v for v in fleet["actual_active_private_diagnostics"] if v != row])


def custody(peer,fleet):
    saved = fleet["current_private169_retry4"]
    end = peer["bound"](TERMINAL)
    intent = peer["bound"](DONOR)
    info = peer["bound"](INTERFACE)
    model = peer["bound"](info["scope"])
    validation = peer["bound"](model["previous_validation"])
    output = Path(validation["archive"])
    s = output.lstat()
    need(saved["unit"]["Id"] == end["unit"] == intent["unit"] == OLD_UNIT and saved["phase"] == "terminal"
         and saved["terminal"] == model["previous"] == TERMINAL and saved["held"] == model["previous_held"] == intent["held"]
         and saved["invocation_id"] == end["invocation_id"] == intent["producer_invocation_id"] == OLD_IID
         and end["grant_sha256"] == peer["read"](PRIOR/"GRANT.json")[1]["sha256"] and end["private_span"]
         and validation["validation"] == "pass" and validation["epoch"] == 169 and validation["terminal_slot"] == 73_245_218
         and not end["resource_credit_bytes"] and end["canonical_publication_authorized"] is False
         and output.resolve(strict=True) == output and stat.S_ISREG(s.st_mode) and s.st_nlink == 1
         and (s.st_dev,s.st_ino,s.st_size,s.st_ctime_ns,s.st_mtime_ns) ==
             tuple(end["archive"][k] for k in ("device","inode","size","ctime_ns","mtime_ns"))
         and s.st_uid == validation["archive_uid"] == 1001 and s.st_size == validation["archive_bytes"] == 1893471148,
         "fourth 169 private segment, inode or funding changed")
    for name in (OLD_UNIT,"horizon-guard-169-hourly-retry-20261128-v4.timer",
                 "horizon-guard-169-hourly-retry-20261128-v4.service"):
        peer["idle"](name)
    return dict(terminal=TERMINAL,previous_invocation=OLD_IID,held=saved["held"],start=DONOR,
                archive=validation["archive"],bytes=s.st_size,archive_sha256=validation["archive_sha256"],
                validation=model["previous_validation"])


def enrollment(peer):
    path = ROOT/"ADJACENT169_ENROLLMENT.json"
    if not os.path.lexists(path):
        return None
    spec,ref = peer["read"](path)
    scope = peer["bound"](INTERFACE)
    manifest = peer["bound"](spec["whole_roster"])
    writer = peer["bound"](spec["writer_active"])
    ready = peer["bound"](writer["ready"])
    need(spec["schema"] == "horizon-private-169-adjacent-enrollment-v1" and spec["interface"] == INTERFACE
         and spec["operator"] == scope["provider"] == ready["adjacent169_provider"] and ready["adjacent169_interface"] == INTERFACE
         and spec["previous"] == scope["previous"] == ready["adjacent169_predecessor"] == TERMINAL and spec["donor"] == DONOR
         and spec["capacity"]["path"] == str(Path(manifest["destination"])/"adjacent169_price.py")
         and any(m["name"] == "adjacent169_price.py" and m["sha256"] == spec["capacity"]["sha256"] for m in manifest["members"]),
         "unregistered 169 compute lease")
    return ref


def resident(layout,row):
    memory = runpy.run_path(str(Path(__file__).with_name("ram170_residency.py")))
    parent,child = row["actor"]["producer_pid"],row["worker"]["pid"]
    processes = ((parent,row["actor"]["start_ticks"]),(child,row["worker"]["start_ticks"]))
    scratch = layout.RUN/"scratch"
    ns = Path("/proc")/str(parent)/"root"/scratch.relative_to("/")
    def check():
        need(not os.path.lexists(layout.GUARDS/"stop-intent.json") and
             set(map(int,(layout.CGROUP/"cgroup.procs").read_text().split())) == {parent,child}
             and (Path("/proc")/str(parent)/"ns/mnt").samefile(Path("/proc")/str(child)/"ns/mnt")
             and ns.stat().st_dev == row["mounts"]["scratch_device"] == (Path("/proc")/str(child)/"exe").stat().st_dev
             and all(layout.ticks(pid) == ticks and (Path("/proc")/str(pid)/"cgroup").read_text().strip() ==
                     "0::"+layout.GROUP for pid,ticks in processes), "different guarded 169 population")
    def occupied():
        fs = os.statvfs(ns)
        need(fs.f_frsize * fs.f_blocks == 44*G,"different 169 noswap size")
        return (fs.f_blocks-fs.f_bfree)*fs.f_frsize
    check()
    first = memory["memory"](layout.CGROUP)
    occupied_before = occupied()
    anon = 0
    for pid,_ in processes:
        value, = [line.split() for line in (Path("/proc")/str(pid)/"smaps_rollup").read_text().splitlines()
                  if line.startswith("Pss_Anon:")]
        need(len(value) == 3 and value[2] == "kB" and value[1].isdecimal(),"invalid 169 Pss_Anon counter")
        anon += int(value[1])*1024
    after = occupied()
    last = memory["memory"](layout.CGROUP)
    check()
    return memory["lower"](first,last,anon,min(occupied_before,after),scratch_limit=44*G)


def sample(peer,fleet,writer):
    previous = custody(peer,fleet)
    funded = enrollment(peer)
    row = sample_retry(peer,fleet,writer)
    need(not funded or row["enrolled"],"169 booking lost writer registration")
    return dict(row,previous=previous,enrollment=funded)


def live(row):
    owner = row["owner"]
    if not owner or owner["phase"] == "terminal":
        return None
    return dict(unit=UNIT,invocation=owner["invocation_id"],pid=int(owner["unit"]["MainPID"]),phase=owner["phase"],
                guard_plan=owner["guard_plan"],held=owner["actor"],release=owner["release"])


def stable(before,after):
    for key in ("phase","owner","previous","enrollment","enrolled","floor"):
        need(before[key] == after[key],"adjacent 169 changed during price: "+key)
    return max(before["remaining"],after["remaining"])


def apply(native,before,after):
    stable(before,after)
    paid = native["planned_169_retry"]
    original = native["stopped_169_compute_handoff"]
    lower = min(before["resident"],after["resident"])
    need(not native["independent_retry169"] and native["fourth169_residency"]["realized_bytes"] == 0
         and paid["fourth_scope"]["path"] == str(PRIOR/"SCOPE.json") and paid["additional_home"] == OUTPUT+CONTROL
         and original["retained_159_ram"]+paid["additional_ram"] == LIMIT and original["retained_guard_ram"] == G
         and native["ram_margin"] == native["available_ram"]-native["required_ram"] and not native["resource_credit_bytes"]
         and 0 <= lower <= LIMIT and (not lower or before["phase"] == "worker" and before["owner"]["release"]),
         "different original or fourth 169 resource owner")
    native["required_ram"] -= lower
    native["ram_margin"] += lower
    native["adjacent_169_before"] = before
    native["adjacent_169_after"] = after
    native["adjacent_169_owner"] = live(before)
    native["adjacent_169_resident_bytes"] = lower


def reserve(quote,prospective):
    native=quote["base_169"]["native"]
    before,after=native["adjacent_169_before"],native["adjacent_169_after"]
    remaining=stable(before,after)
    charged=bool(after["enrollment"]) or prospective
    need(0 <= remaining <= OUTPUT and not quote["resource_credit_bytes"] and
         (not after["owner"] or charged and after["enrolled"]) and "adjacent_169_accounting" not in quote,
         "unfunded or duplicate 169 image")
    # The earlier 4 GiB + control remain in the common budget alongside the
    # already occupied predecessor segment. There is no old-image disk credit.
    cost = remaining+CONTROL if charged else 0
    quote["adjacent_169_accounting"] = dict(phase=after["phase"],enrollment=after["enrollment"],charged=charged,
        writer_enrolled=after["enrolled"],owner=after["owner"],previous=after["previous"],predecessor=TERMINAL,
        observed_floor=after["floor"],remaining_output=remaining,maximum_output=OUTPUT,control=CONTROL,
        additional_home=cost,additional_ram=0,additional_cpu=0,resident_bytes=native["adjacent_169_resident_bytes"])
    quote["required_home"] += cost
    quote["home_margin"] -= cost
    quote["fits"] = quote["fits"] and quote["home_margin"] >= 0


def runways(whole):
    third=whole["third_162_accounting"]
    six=third["remaining_output"] if third["charged"] and third["phase"] != "terminal" else 0
    newer=whole["after_floor170_accounting"]
    ten=newer["home_growth"] if newer["replacement_selected"] else whole["after_ram170_accounting"]["home_growth_bytes"]
    need(ten in (8*G,36*G) and 0 <= six <= 3*G, "unknown 162 or 170 output reservation")
    return whole["epoch143_remaining_replay_home"],six,ten


def protect(whole):
    lane=whole["adjacent_169_accounting"]
    if lane["charged"] and lane["phase"] != "terminal":
        floor=max([whole.get("epoch143_installed_guard_floor") or 0,*whole["observed_sibling_guard_floors"]])
        required=max(whole["epoch143_protected_runway_required_home"],floor+sum(runways(whole))+lane["remaining_output"])
        whole["adjacent169_joint_guard_requirement"]=required
        whole["home_margin"]=min(whole["home_margin"],whole["available_home"]-required)
        whole["fits"]=whole["fits"] and whole["home_margin"] >= 0
    return whole


def protect_170(candidate,whole):
    lane=whole["adjacent_169_accounting"]
    if lane["charged"] and lane["phase"] != "terminal":
        remaining,six,_=runways(whole)
        required=max(candidate["required_home"],candidate["guard_floor"]+remaining+six+candidate["candidate_170_growth_bytes"]+lane["remaining_output"])
        margin=min(candidate["home_margin"],candidate["available_home"]-required-candidate["shared_drawdown_allowance"])
        return dict(candidate,required_home=required,home_margin=margin,fits=candidate["fits"] and margin>=0,
                    protected_169_remaining=lane["remaining_output"])
    return candidate
