"""Hand V47's scheduled sample, active 170 interfaces and 143 exclusion to V48."""
from pathlib import Path
from evidence import bound, checked, need
from transition import clock
import rolling170_fourth_status as rolling
import split_status169 as focused
import status162

V47_SHA = "def64d8842984dee1835c05aefa8b5f344c52f9b97e8691db123b1cce2daca86"
V47_SEAL = "cdeef56bc6fddb7189be65ace5a72468514ed97d08b470be5248d79da8177f55"
REBOUND_SHA = "61883f8f6fd84c70a145042944ef602369d6b798decd34ade652d26e8cbf565e"


def ready(api, head, seal):
    root, base, current = api["ROOT"], api["BASE"], api["CURRENT"]
    oldref = dict(path=str(root / "FAILED166_CADENCE_V47_ACTIVE.json"), sha256=V47_SHA)
    old = checked(oldref)
    earlier = checked(old["ready"])
    previous = root / api["failed166_package"](47)
    need(earlier["package"] == dict(path=str(previous / "deployment-seal-receipt.json"), sha256=V47_SEAL)
         and old["new"]["program"] == str(previous / "status_cycle.py"), "unregistered V47 owner")
    ref143 = dict(path=str(base / "epoch143-first-hourly-20261127-v1/REENTRY_V47_REBOUND.json"), sha256=REBOUND_SHA)
    listener = checked(ref143)
    need(listener["original"] == earlier["retained_143_listener"] and listener["phase"] == earlier["retained_143_phase"]
         and listener["writer_package"] == earlier["package"], "V47 lost its inherited 143 execution exclusion")
    fleet = checked(head)
    need(Path(head["path"]) == max(base.glob("root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json"), key=lambda f:f.stat().st_mtime_ns)
         and not fleet.get(focused.FIELD), "V48 handoff has a superseded fleet or a prior 169 enrollment")
    cfgref, timer = fleet["sole_next_observer"], fleet["sole_next_timer"]
    cfg = api["sealed"](cfgref)
    completed = clock(api, fleet, cfg, timer, cfgref)
    api["tail167_status"].retained_population(fleet, cfg)
    api["bridge170_status"].retained_population(fleet, cfg)
    rolling.retained_population(fleet, cfg)
    need(earlier["successor170_interface"] == rolling.INTERFACE
         and earlier["prior_successor170_interface"] == rolling.history.INTERFACE
         and focused.reader()["current"](fleet) is None and status162.current(fleet) is None, "unexpected 170 assignment or previously started 169")
    # All earlier receiver source references must name the exact retained member
    # in this deployment; the source path participates in the writer handoff.
    rebound = {}
    for key, ref in earlier.items():
        if isinstance(ref, dict) and "path" in ref and Path(ref["path"]).parent == previous:
            name = Path(ref["path"]).name
            if name != "deployment-seal-receipt.json":
                rebound[key] = bound(current.with_name(name))
    return earlier | rebound | dict(package=seal, old_owner=oldref, fleet=head, config=cfgref,
         timer=timer, completed_sample=completed, retained_143_v47_rebound=ref143,
         split162_reader=bound(current.with_name("status162.py")),
         split162_provider=api["read_ref"](current.with_name("split162_provider.json")),
         split169_reader=bound(current.with_name("split_status169.py")),
         split169_provider=api["read_ref"](current.with_name("split169_provider.json")))


def validate(api, proposed, seal):
    actual = ready(api, proposed["fleet"], seal)
    need(actual == proposed or proposed["completed_sample"] is None and actual["completed_sample"] is not None
         and dict(actual, completed_sample=None) == proposed, "V48 lost a receiver or an armed observation")
