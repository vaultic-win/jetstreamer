"""Bind the existing held launcher to the next 170 scope, V37 and the sole V76 writer."""
from pathlib import Path
import runpy
import sys

OPERATOR = Path(__file__).resolve().parent
sys.path.insert(0,str(OPERATOR))
from following_prepare import ROOT as RT, need, read as checked, reference
from next_hourly170 import ALIAS, OLD_IID, PREVIOUS, ROOT, UNIT
from next_hourly170_price import candidate

DEP = ATTEMPT = ROOT
BRIDGE = "horizon-qualify-170-from-73766969-ram-20261128-v1.service"
ENROLL_OPTION = "--enroll-next-hourly-170"
PRODUCER_MEMORY = 56 << 30
RETRY = FOLLOWING = False
WRITERS = RT/"survivor172-cadence-20261122-v1"
DRAW = dict(path=str(RT/"epoch166-closed-compact-indexes-20261128-v1/SHARED_HOME_DRAWDOWN_0400_053730.json"),
            sha256="cb92e5a9b96960d0e2a98a7f2d9ce75d5ad221b84c4549955eea4ce05a0b87ab")


def package(directory, seal):
    receipt = checked(seal)
    need(seal["path"] == str(directory/"deployment-seal-receipt.json")
         and receipt["destination"] == str(directory),"foreign deployed directory")
    files = {}
    for member in receipt["members"]:
        path = directory/member["name"]
        info = path.lstat()
        need(path.parent == directory and path.resolve(strict=True) == path and path.is_file()
             and info.st_uid == 0 and info.st_nlink == 1 and not info.st_mode & 0o222
             and reference(path)["sha256"] == member["sha256"],"changed package member "+path.name)
        files[path.name] = member["sha256"]
    need(len(files) == len(receipt["members"]),"duplicate sealed member")
    return files


SELF = reference(OPERATOR/"deployment-seal-receipt.json")
files = package(OPERATOR,SELF)
BINDING = checked(dict(path=str(OPERATOR/"binding.json"),sha256=files["binding.json"]))
PROVIDER = Path(BINDING["provider"]["path"]).parent
need(OPERATOR == ROOT/"operator-v1" and PROVIDER.name == "issued-price-v37"
     and BINDING["interface"]["path"] == str(ROOT/"NEXT_HOURLY_WRITER_INTERFACE.json"),
     "unexpected next hourly operator or provider")
provider_files = package(PROVIDER,BINDING["provider"])
source = checked(dict(path=str(PROVIDER/"SOURCE.json"),sha256=provider_files["SOURCE.json"]))
need(source["next_hourly170_interface"] == BINDING["interface"]
     and source["next_hourly170_receiver"] == BINDING["receiver"]
     and Path(source["prior_shared_price"]["path"]).parent.name == "issued-price-v36",
     "missing V36/V37 next hourly registration")
prior = runpy.run_path(str(PROVIDER/"continuation_price.py"))["prior"]
read,bound,state,inactive,cmd = prior.read,prior.bound,prior.state,prior.inactive,prior.cmd
TREE = Path(bound(BINDING["interface"])["run"])


def scope():
    return bound(BINDING["interface"]),BINDING["interface"]


def compare_predecessor():
    expected,_ = scope()
    previous = bound(expected["predecessor"])
    final = bound(previous["custody"])
    done = bound(previous["drain"])
    need(final["bindings"]["invocation"] == OLD_IID and done["custody"] == previous["custody"]
         and done["guard_drained"] and done["producer_drained"] and done["scratch_released"]
         and final["comparison"] == previous["closed_comparison"] == expected["retained_comparison"]
         and final["actual_terminal"]["slot"] == expected["bootstrap"] and final["actual_terminal"]["slot_complete"]
         and not final["archive_publication_authorized"] and not done["resource_credit_bytes"],
         "missing independently read predecessor and original guard drain")
    return final["comparison"]


def predecessor_drained():
    p = compare_predecessor()
    guard = BRIDGE.replace("-qualify-","-guard-")
    for unit in (BRIDGE,guard):
        need(not inactive(unit)["ControlGroup"] and not (Path("/sys/fs/cgroup/system.slice")/unit).exists(),
             "the original producer or guard still occupies its cgroup")
    timer = state(guard.replace(".service",".timer"),"Id,ActiveState,Job")
    need(timer["ActiveState"] == "inactive" and not timer["Job"],"the original guard timer is live")
    return p


def writer(require_registration=True):
    peers = runpy.run_path(str(PROVIDER/"following_peers.py"))
    split = dict(path=str(peers["ISSUED"]/"deployment-seal-receipt.json"),sha256=peers["SEAL169"])
    active = peers["current_writer"](prior,split)
    owner = bound(active)
    ready = bound(owner["ready"])
    program = Path(owner["new"]["program"])
    need(ready["after_floor170_interface"] == scope()[0]["previous_interface"],"writer lost its 170 ancestor")
    if ready.get("next_hourly170_interface") is None and not require_registration:
        return active,None
    need(active["path"] == str(WRITERS/"FAILED166_CADENCE_V76_ACTIVE.json")
         and ready["old_owner"] == BINDING["preceding_writer"]
         and ready["next_hourly170_interface"] == BINDING["interface"],
         "the exact V76 writer has not accepted the next-hourly 170 interface")
    modules = package(Path(BINDING["receiver"]["path"]).parent,BINDING["receiver"])
    writer_members = package(program.parent,ready["package"])
    need(all(writer_members.get(name) == digest for name,digest in modules.items())
         and ENROLL_OPTION in program.read_text(),"the live writer omitted the bound receiver")
    return active,program


def price(phase, *, preliminary=False):
    old = predecessor_drained()
    active,program = writer(require_registration=not preliminary)
    whole = runpy.run_path(str(PROVIDER/"capacity.py"))["whole_roster"]()
    proof,scope_ref = scope()
    need(whole["writer"] == active and whole["package"] == BINDING["provider"]
         and proof["retained_comparison"] == old and not whole["resource_credit_bytes"],
         "shared owner changed during the next-hourly quote")
    fit = candidate(whole,proof["predecessor"],proof["staged_layout"],scope_ref,DRAW,phase=phase)
    return dict(fit,closed_comparison=old,writer_ready=program is not None,preliminary=preliminary,
                observed=whole["recorded_unix_seconds"])
