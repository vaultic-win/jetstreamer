"""Resume the original post-replay sample and retain the complete predecessor roster."""
from pathlib import Path
from evidence import BASE, bound, checked, need, sealed
import transition_v76 as prior
import finalizing172 as final

V76_SHA = "50c63b7091977e256d3184b59b7ebfad6a61cc98a5db6e2658d19b33fa36d3d1"
V76_SEAL = "dbd4f4fd773442371e2043ba58293b01338bc6d068b27bc8ef253d6e987e5dc4"
V76_READY = "6b4168edac84544cde78bca9a6593ae79d14562e93cea1e8624a3154c274fd8c"
SAMPLE = dict(path=str(BASE/"sample-root134808-live166167170-20261128-v1.json"),sha256="fcf56f36e8f5290cc041821d69f87d17f5c6376f225726a64db27fc45df40d48")
assembly = prior.assembly


def native_assignments(fleet):
    active, closed = prior.native_assignments(fleet)
    state = final.observe(fleet)
    unit = final.full172.UNIT
    if state["identity"]:
        manager = state["identity"]["unit"]
        active[unit] = dict(unit=unit,iid=manager["InvocationID"],pid=manager["MainPID"],intent=final.ARCHIVE)
    else:
        closed[unit] = state["producer_invocation_id"]
    return active,closed


def ready(api,head,seal):
    base = api["ROOT"]
    old = base/api["failed166_package"](76)
    owner = dict(path=str(base/"FAILED166_CADENCE_V76_ACTIVE.json"),sha256=V76_SHA)
    prior_owner = checked(owner)
    previous = checked(prior_owner["ready"])
    latest = max(BASE.glob("root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json"),key=lambda p:p.stat().st_mtime_ns)
    selection = checked(checked(final.SELECTED)["selection"])
    need(head == selection["fleet"] == bound(latest) and prior_owner["ready"]["sha256"] == V76_READY and
         prior_owner["new"]["program"] == str(old/"status_cycle.py") and
         previous["package"] == dict(path=str(old/"deployment-seal-receipt.json"),sha256=V76_SEAL),
         "different V76 writer, clock or fleet")
    fleet = checked(head)
    config,timer = fleet["sole_next_observer"],fleet["sole_next_timer"]
    cfg = final.effective(sealed(config))
    sample = checked(SAMPLE)
    need(selection["original"] == config and selection["timer"]["Id"] == timer and not api["timer_names"]()
         and sample["cadence"]["configured_not_before_utc"] == cfg["not_before_utc"] and SAMPLE["path"] == cfg["output"],
         "different completed observer")
    api["check_sample"](fleet,sample,cfg)
    active,closed = native_assignments(fleet)
    current = api["CURRENT"].parent
    copies = {k:bound(current/Path(v["path"]).name) for k,v in previous.items()
              if k != "package" and isinstance(v,dict) and "path" in v and Path(v["path"]).parent == old}
    return previous | copies | dict(package=seal,old_owner=owner,fleet=head,config=config,timer=timer,
        completed_sample=SAMPLE,protected_private_assignments=active,terminal_private_invocations=closed,
        epoch167_assembly_owner=assembly.owner_binding(),original172_archive=final.ARCHIVE,
        original172_observer_selection=final.SELECTED,original172_reader=bound(current/"finalizing172.py"))


def validate(api,proposed,seal):
    need(ready(api,proposed["fleet"],seal)==proposed, "V77 predecessor or protected roster changed")
