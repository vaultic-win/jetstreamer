"""Adopt the live V44 clock and the disjoint second bounded epoch 170 route."""
from pathlib import Path

from evidence import bound, checked, need
from transition import clock
import rolling170_status as rolling

V44_SHA = "fa89af4b94631111c9998170d86758d11db8728dbdc3fe7648df48eef4bba9eb"
V44_SEAL = "ffbcf9381420fe08966f35d24e4b7fada4e3e8684339c92600a4a1169fb1629b"


def ready(api,head,seal):
    root, base, current = api["ROOT"],api["BASE"],api["CURRENT"]
    oldref = dict(path=str(root/"FAILED166_CADENCE_V44_ACTIVE.json"),sha256=V44_SHA)
    old = checked(oldref)
    earlier = checked(old["ready"])
    need(earlier["package"]["sha256"] == V44_SEAL and earlier["successor170_interface"] == rolling.previous.INTERFACE
         and old["new"]["program"] == str(root/api["failed166_package"](44)/"status_cycle.py"),"different V44 writer")
    fleet = checked(head)
    need(Path(head["path"]) == max(base.glob("root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json"),key=lambda p:p.stat().st_mtime_ns),
         "V45 needs the latest fleet")
    ref,timer = fleet["sole_next_observer"],fleet["sole_next_timer"]
    cfg = api["sealed"](ref)
    complete = clock(api,fleet,cfg,timer,ref)
    api["tail167_status"].retained_population(fleet,cfg)
    api["bridge170_status"].retained_population(fleet,cfg)
    rolling.retained_population(fleet,cfg)
    rolling.interface()
    bindings = {"full170_receiver":"full170_status.py","focused168_receiver":"focused168_status.py",
        "joint168_receiver":"joint168_status.py","joint168_native_reader":"joint168_capacity.py",
        "bridge170_status":"bridge170_status.py","successor170_receiver":"rolling170_status.py",
        "prior_successor170_receiver":"successor170_status.py","next_successor170_receiver":"continuation170_native.py",
        "continuation170_contract":"continuation170_contract.py","retry5_generation":"retry5-168-generation.json",
        "hourly_reader":"first_hourly143.py","hourly_population":"hourly_population.py"}
    return dict(earlier,package=seal,old_owner=oldref,fleet=head,config=ref,timer=timer,completed_sample=complete,
                successor170_interface=rolling.INTERFACE,prior_successor170_interface=rolling.previous.INTERFACE,
                **{k:bound(current.with_name(v)) for k,v in bindings.items()})


def validate(api,proposed,seal):
    actual = ready(api,proposed["fleet"],seal)
    need(actual==proposed or proposed["completed_sample"] is None and actual["completed_sample"] is not None
         and dict(actual,completed_sample=None)==proposed,"V45 lost the original observer")
