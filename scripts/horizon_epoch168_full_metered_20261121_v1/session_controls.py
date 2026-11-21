"""Exercise fit selection, native-generation binding and atomic nonreplacement in isolation."""
from copy import deepcopy
from pathlib import Path
import json
import sys
import tempfile

sys.path.insert(0,str(Path(__file__).resolve().parent))
import fit
import incident
import time
import session
import same_five


def run():
    pre=dict(eligible_with_168_alone=True,registered_population_compatible=True,fresh_phase_compatible=True,
             available_HOME_bytes=140,complete_required_DATA_bytes=100,available_memory_bytes=150,
             required_available_memory_bytes=130,population={"167":{"pid":10,"ticks":12},"169":{"timer":"a"*32}},
             phase145={"final":"verified-original"},status_registration={"sha256":"b"*64},fleet={"sha256":"c"*64},
             retired_original_peers={},standalone_guard_floor=100)
    assert fit.select(pre)==100 and fit.select(pre,dict(pre,standalone_guard_floor=101),110)==101
    early=dict(pre,phase145={"window":{"original_five_peer_failure":{"sha256":"f"*64}}},
               combined_disk_fits=True,combined_required_HOME_bytes=138)
    assert fit.select(early)==100
    for late in (dict(early,combined_disk_fits=False),dict(early,combined_required_HOME_bytes=141)):
        try: fit.select(early,late,110)
        except ValueError: pass
        else: raise AssertionError("accepted unfunded 136 donor")
    changes=[("population",{"167":{"pid":10,"ticks":13},"169":{"timer":"a"*32}}),
             ("population",{"167":{"pid":10,"ticks":12},"169":{"timer":"d"*32}}),
             ("phase145",{"final":"another-generation"}),("status_registration",{}),
             ("fleet",{}),("retired_original_peers",{"terminal":"new"}),("fresh_phase_compatible",False),
             ("registered_population_compatible",False),("standalone_guard_floor",111),("available_HOME_bytes",99),
             ("available_memory_bytes",129)]
    for name,value in changes:
        post=deepcopy(pre);post[name]=value
        try: fit.select(pre,post,110)
        except ValueError: continue
        raise AssertionError("accepted altered proof "+name)
    fleet={"path":"fixture","sha256":"c"*64}
    booked={e:dict(cap_bytes=cap,remaining_bytes=cap-1024,physical_bytes=1024) for e,cap in incident.CAPS.items()}
    booked["168"]["root"]=str(incident.s.TREE)
    floor=8297502499408
    required=floor+booked["168"]["remaining_bytes"]
    sample=dict(schema="horizon-incident-replay-fit-v1",epoch=168,fleet=fleet,fits=True,
        actual_original_stops={e:{"guard_timer_retirement":incident.TIMER_DRAIN} for e in ("166","167","170")},
        survivors={"169":{},"172":{}},candidate=None,normal168=None,bookings=booked,complete_required_HOME_bytes=required,
        protected_raw_floor_bytes=floor,available_HOME_bytes=required,complete_cpu_quota_micros=64_000_000,
        complete_memory_plus_reserve_bytes=fit.MEM,required_available_memory_bytes=100,available_memory_bytes=100,
        candidate136=dict(cap=72*fit.G,remaining=72*fit.G,occupied=False),recorded_unix_seconds=int(time.time()),
        stopped_generation_resident_credit_bytes=0,resource_credit_bytes=0)
    assert incident.capacity(sample,fleet,None)
    actor={"producer_pid":5,"producer_invocation_id":"a"*32}
    post=dict(sample,candidate=actor,normal168={"stage":"gated","actor":actor})
    assert incident.capacity(post,fleet,actor)
    for bad in (dict(sample,actual_original_stops={}),dict(sample,candidate=actor),dict(sample,survivors={}),
                dict(sample,stopped_generation_resident_credit_bytes=1),dict(sample,recorded_unix_seconds=0),
                dict(sample,candidate136=dict(sample["candidate136"],remaining=0)),dict(sample,complete_required_HOME_bytes=floor)):
        try: incident.capacity(bad,fleet,None)
        except ValueError: pass
        else: raise AssertionError("accepted foreign or incomplete incident state")
    with tempfile.TemporaryDirectory() as td:
        d=Path(td); a=d/"source";b=d/"dest"
        a.write_bytes(b"first");b.write_bytes(b"other")
        try:session.move(a,b)
        except FileExistsError: pass
        else:raise AssertionError("replaced existing path")
        assert a.read_bytes()==b"first" and b.read_bytes()==b"other"
        b.unlink();session.move(a,b)
        assert not a.exists() and b.read_bytes()==b"first"
    return dict(fixture_only=True,stage_positive=2,fit_denials=len(changes),native_rename_noreplace=True)


def native_five(receipt):
    sample=json.loads(receipt.read_bytes())
    assert sample["166_credit_bytes"]==0 and sample["early"] and not sample["launch"]
    prior=sample["original"]
    current=sample["fit"]
    assert same_five.predecessor(prior,current,fit.A145)==same_five.FAILURE
    for key,value in (("joint_closed166",False),("joint_closed166",True),("joint136_enabled",False),
                      ("metered168",{}),("charged_cpu_micros",0),("remaining_native_owners",{})):
        try: same_five.predecessor(prior,dict(current,**{key:value}),fit.A145)
        except ValueError: continue
        raise AssertionError("accepted foreign native fit "+key)
    return dict(original_five_native_fit=str(receipt),negative_cases=6)


if __name__=="__main__":
    print(run())
    if len(sys.argv)==2:
        print(native_five(Path(sys.argv[1])))
