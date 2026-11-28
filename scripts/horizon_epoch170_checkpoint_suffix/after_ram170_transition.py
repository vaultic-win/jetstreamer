"""Carry V63's actual private owners and the same observer clock into V64."""
from pathlib import Path
from types import SimpleNamespace

from evidence import BASE, bound, checked, need
from transition import clock
import transition_v63 as previous
import second_hourly143 as second143
import after_ram170_status as successor

V63_SHA = "426de90d6f3a62d83c08b95e682cf55566744992b984259ec989726d815f4a08"
V63_SEAL = "18c6d258eca8596d2ae90729314b21dfc6413a22b9ddb2ea9a28deb3ca5ae101"


def native_assignments(fleet):
    active, closed = previous.native_assignments(fleet)
    path = max(BASE.glob("root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json"),key=lambda p:p.stat().st_mtime_ns)
    head = bound(path)
    need(checked(head) == fleet,"fleet advanced during V64 owner reconciliation")
    context = SimpleNamespace(fleet=fleet,fleet_ref=head,sample_ref=fleet["observer"])
    first = fleet[previous.hourly143_status.PROFILE.field]
    second = second143.census(context,first)
    if second:
        unit,iid = second143.PROFILE.unit,second["actor"]["producer_invocation_id"]
        if second["phase"] == "terminal":
            need(second["native_terminal"]["INVOCATION_ID"] == iid,"different second 143 terminal")
            closed[unit] = iid
        else:
            active[unit] = dict(unit=unit,iid=iid,pid=str(second["actor"]["producer_pid"]),intent=second["held_owner"])
    return active,closed


def ready(api, head, seal):
    root = api["ROOT"]
    previous_dir = root/api["failed166_package"](63)
    owner = dict(path=str(root/"FAILED166_CADENCE_V63_ACTIVE.json"),sha256=V63_SHA)
    active = checked(owner)
    before = checked(active["ready"])
    need(before["package"] == dict(path=str(previous_dir/"deployment-seal-receipt.json"),sha256=V63_SEAL)
         and active["new"]["program"] == str(previous_dir/"status_cycle.py"),"different V63 writer")
    fleet = checked(head)
    cfg, timer = fleet["sole_next_observer"],fleet["sole_next_timer"]
    assignments, closed = native_assignments(fleet)
    prior = successor.contract.previous_owner(fleet)
    need(prior["actor"]["producer_invocation_id"] == successor.contract.IID
         and successor.UNIT not in assignments and not successor.following.ACTOR.exists()
         and not successor.old.ACTOR.exists() and not successor.following.RELEASE.exists(),
         "following producer already crossed writer enrollment")
    successor.legacy_idle()
    config = api["sealed"](cfg)
    need(not successor.retained_population(fleet,config), "fourth-window assignment already present")
    done = clock(api,fleet,config,timer,cfg)
    current = api["CURRENT"].parent
    members = {key:bound(current/Path(ref["path"]).name) for key,ref in before.items()
               if isinstance(ref,dict) and "path" in ref and Path(ref["path"]).parent == previous_dir and key != "package"}
    return before | members | dict(
        package=seal,old_owner=owner,fleet=head,config=cfg,timer=timer,completed_sample=done,
        protected_private_assignments=assignments,terminal_private_invocations=closed,
        after_ram170_interface=successor.INTERFACE,after_ram170_receiver=bound(current/"after_ram170_status.py"))


def validate(api, proposed, seal):
    actual = ready(api,proposed["fleet"],seal)
    need(actual == proposed or (proposed["completed_sample"] is None and actual["completed_sample"] is not None
         and dict(actual,completed_sample=None) == proposed),"V64 handoff lost its fleet or clock")
