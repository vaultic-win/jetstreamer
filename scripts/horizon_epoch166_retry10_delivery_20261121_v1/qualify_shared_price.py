"""Check both qualified source generations and the simultaneous publication equation."""
import copy
import hashlib
import json
from pathlib import Path
import runpy
import time

R=Path("/var/lib/jetstreamer/horizon_runtime_data")

def trials(module,fit,fleet):
    records={}
    for unit,folder in [(166,"epoch166-retry10-delivery-20261121-v1/qa-f575041147e641a7804574723b890172"),
                        (168,"epoch168-current-delivery-20261121-v1/qa-7c6af9f813ed4f9bb1263e9da87454ca")]:
        d=R/folder/"test-publisher/authority"
        data=(d/"TERMINAL_SUCCESS.json").read_bytes();t=json.loads(data)
        live=(d/"LIVE.json").read_bytes()
        proof=runpy.run_path(str(R/"epoch168-current-delivery-20261121-v1/closure-tools"/("closure.py" if unit==166 else "closure168.py")))
        guard=proof["ORIGINAL"] if unit==166 else proof["guard"]
        origin=json.loads(live)
        guard.validate_terminal(t,origin,dict(path=str(d/"LIVE.json"),sha256=hashlib.sha256(live).hexdigest()),origin["admission"],origin["first_protected_worker"])
        records[unit]=dict(path=str(d/"TERMINAL_SUCCESS.json"),sha256=hashlib.sha256(data).hexdigest())
    positive=[];refusals={}
    for combination in [(168,),(166,),(166,168)]:
        actual=copy.deepcopy(fit);registered=copy.deepcopy(fleet)
        scenario="-".join(map(str,combination))
        for epoch in combination:
            key=str(epoch)
            original=next(v for v in registered["actual_executing_replays"] if v["epoch"]==epoch)
            registered["actual_executing_replays"].remove(original)
            actual["population"].pop(original["unit"]["Id"])
            actual["required_available_memory_bytes"]+=actual["joined_resident_lower_bounds"].pop(key)
            if epoch==166:
                actual["replacements"].pop(key);registered["original_disk_guard_recovery_workers"].pop(key)
            else:
                actual["normal168"]=None;actual["active168_guard_floor"]=0
            actual["bookings"][key]["measurement"]="two complete stopped-tree walks"
            registered[module["FLEET_FIELDS"][epoch]]=records[epoch]
            actual[module["CLOSURES"][epoch]]=dict(terminal=records[epoch])
        actual["recorded_unix_seconds"]=int(time.time())
        actual["available_memory_bytes"]=max(actual["available_memory_bytes"],actual["required_available_memory_bytes"])
        actual["available_HOME_bytes"]=max(actual["available_HOME_bytes"],actual["complete_required_HOME_bytes"]+len(combination)*module["BOOK"])
        for epoch in combination:
            def verify(value=actual,inventory=registered):
                return module["validate"](value,inventory,actual["fleet"],records[epoch],epoch)
            floor=verify()
            assert floor==actual["complete_required_HOME_bytes"]+len(combination)*(16<<20)
            positive.append(dict(closures=list(combination),publisher=epoch,preserved_cap=actual["bookings"][str(epoch)]["cap_bytes"],extra_home=floor-actual["complete_required_HOME_bytes"]))
            for name,field,update in [("duplicated-storage","available_HOME_bytes",floor-1),
                                      ("closed-memory-credit","required_available_memory_bytes",actual["required_available_memory_bytes"]-1),
                                      ("wrong-native-roster","population",{}),
                                      ("terminal-of-other-generation",module["CLOSURES"][epoch],dict(terminal=records[334-epoch]))]:
                try:verify(dict(actual,**{field:update}))
                except ValueError as e:refusals[scenario+"-"+str(epoch)+"-"+name]=str(e)
                else:raise AssertionError("accepted "+name)
            if 168 in combination:
                try:verify(dict(actual,registered_host_equation=dict(actual["registered_host_equation"],retained_168_remaining=0)))
                except ValueError as e:refusals[scenario+"-"+str(epoch)+"-missing-168-booking"]=str(e)
                else:raise AssertionError("168 reservation disappeared")
    return dict(positive_publication_prices=positive,rejected=refusals,original_fixture_terminals=records,
                hypothetical_population_only=True,production_terminal_or_publication=False)
