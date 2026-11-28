"""Recover the completed 06:48 observation after the V34 bridge exclusivity failure."""
import json
from pathlib import Path
import subprocess

from evidence import bound, checked, need
from transition import clock
import bounded167_v2_operator as retry
import bridge170_status as bridge

V34_SHA = "ecfd4676d93dd3b650bfa2d27c6fc73cd6bdc5cf5534e8c22870ca120dfdfd29"
V34_SEAL_SHA = "d62ac67045ac3162352ba27202dee7aed63521ba7ba50f3fc816b4b9d78d0b33"
HEAD_SHA = "95d034c38ab07a7b9d6087234ffffeb9616024942b2262499b4c7bac7de5eaea"
SAMPLE_SHA = "aa3738110765eb08c8a55ed5cfbc557a5eb4ed3fecd38a950d2a34f0c472cf8c"
FAILURE = "98e322203f7a4ed290d09fe03c09fe15"


def journal(*query):
    raw=subprocess.check_output(["/usr/bin/journalctl","--no-pager","-q","-o","json",*query],timeout=15)
    return [json.loads(line) for line in raw.splitlines()]


def ready(api, head, seal):
    root,base,current=api["ROOT"],api["BASE"],api["CURRENT"]
    old_ref=dict(path=str(root/"FAILED166_CADENCE_V34_ACTIVE.json"),sha256=V34_SHA)
    old=checked(old_ref)
    previous=checked(old["ready"])
    actor=old["new"]
    need(head==dict(path=str(base/"root061808-live166167170-20261127-v1/ROOT_COMPLETE_OPERATIONAL_FLEET.json"),
                    sha256=HEAD_SHA) and previous["package"]["sha256"]==V34_SEAL_SHA
         and actor["program"]==str(root/api["failed166_package"](34)/"status_cycle.py"),
         "foreign V34 predecessor")
    fleet=checked(head)
    config=fleet["sole_next_observer"]
    cfg=api["sealed"](config)
    timer=fleet["sole_next_timer"]
    completed=clock(api,fleet,cfg,timer,config)
    need(completed==dict(path=str(base/"sample-root064808-live166167170-20261127-v1.json"),sha256=SAMPLE_SHA),
         "V35 requires the original completed 06:48 observation")
    bridge.interface()
    accepted=bridge.retained_population(fleet,cfg)
    need(bridge.active(accepted) and accepted["phase"]=="worker" and accepted["observer_config"] is not None
         and retry.historical_terminal(fleet,cfg)==previous["bounded167_v1_terminal"],
         "V34 did not enroll the exact private bridge with its protected cadence")
    iid,unit=actor["invocation_id"],actor["unit"]
    messages=journal("_SYSTEMD_INVOCATION_ID="+iid)
    error,=(line for line in messages if line.get("MESSAGE")=="ValueError: metered 170 overlaps the diagnostic")
    failure,=(line for line in journal("_PID=1","UNIT="+unit,"INVOCATION_ID="+iid,"MESSAGE_ID="+FAILURE)
              if line.get("COMMAND")=="ExecStart")
    need(error["_PID"]==str(actor["pid"]) and failure["_BOOT_ID"]==error["_BOOT_ID"]
         and failure["EXIT_STATUS"]=="1" and failure["EXIT_CODE"]=="exited"
         and int(failure["__REALTIME_TIMESTAMP"])>=int(error["__REALTIME_TIMESTAMP"]),
         "V34 failed writer proof does not match the bridge exclusivity failure")
    return dict(previous, package=seal, old_owner=old_ref, fleet=head, config=config, timer=timer,
                completed_sample=completed,failed_writer=dict(event=failure,error=error),
                full170_receiver=bound(current.with_name("full170_status.py")),
                focused168_receiver=bound(current.with_name("focused168_status.py")),
                retry5_generation=bound(current.with_name("retry5-168-generation.json")),
                joint168_receiver=bound(current.with_name("joint168_status.py")),
                joint168_native_reader=bound(current.with_name("joint168_capacity.py")),
                bounded167_receiver=bound(current.with_name("bounded167_status_v2.py")),
                bounded167_admission=bound(current.with_name("bounded167_v2_operator.py")),
                bridge170_status=bound(current.with_name("bridge170_status.py")))


def validate(api, proposed, seal):
    actual=ready(api,proposed["fleet"],seal)
    need(actual==proposed, "V35 recovery changed the completed clock or exact bridge lineage")
    return actual["completed_sample"]
