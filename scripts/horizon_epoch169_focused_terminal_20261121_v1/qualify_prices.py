"""Exercise each retained focused booking against original native delivery fixtures."""
import copy
import hashlib
import itertools
import json
import os
from pathlib import Path
import runpy
import time

def subsets(keys):
    return itertools.chain.from_iterable(itertools.combinations(keys,k) for k in range(len(keys)+1))

def readref(ref):
    raw=Path(ref["path"]).read_bytes()
    assert hashlib.sha256(raw).hexdigest()==ref["sha256"]
    return json.loads(raw)

def run(provider,transition,measured):
    full=runpy.run_path(str(provider/"post-stop-fit"));pub=runpy.run_path(str(provider/"publication-fit"))
    budget=runpy.run_path(str(transition));fit=full["fit"];s=full["s"]
    r=full["R"];t=r/"epoch169-focused-terminal-20261121-v1";cl=runpy.run_path(str(t/"closure-tools/closure169.py"))
    original=cl["live"]()[0]
    assert full["focused169_terminal"]({}, {169:None}) is None
    try:full["focused169_terminal"]({"focused169_terminal":{}},{})
    except ValueError:pass
    else:raise ValueError("missing guard accepted")
    v12=readref(dict(path=str(provider.parent/"tools-v12/qualification.json"),sha256="115fa1b4a0bd3c702d484a9f59cdfe272743c01ff5acfcd4e5b7c6f2da3fc4aa"))
    historical=v12["five_publication_prices"]["native_fixtures"]
    canonical={}
    for k,artifact in historical.items():
        actual=readref(artifact["terminal"]);qualified=readref(artifact["native_qualification"])
        assert actual["epoch"]==int(k) and actual["producer_invocation_id"]==budget["GENERATIONS"][int(k)]
        canonical[int(k)]=dict(terminal=artifact["terminal"],admission=actual["source_admission"],producer_invocation_id=actual["producer_invocation_id"],resource_credit_bytes=0,
                               guard_retirement=qualified["fixture_checks"]["publisher"])
    assert set(canonical)==set(pub["FLEET_FIELDS"])
    ledger=full["bound"](fit.BOOK);prior=s.read(r/"epoch169-focused-admission-20261120-v4/POST_GUARD_CAPACITY.json","803bb540a6601238e8754c733a8cf900a9b6d103116ad6dac50bdcc2a081defc")[0]["protected_raw_floor_bytes"]
    inventory=readref(measured["fleet"]); groups=("actual_executing_replays","actual_active_bootstraps","actual_active_private_diagnostics")
    fleet={k:[dict(epoch=row["epoch"],unit={"Id":row["unit"]["Id"]}) for row in inventory[k]] for k in groups}
    fleet["continuing_audit_obligation"]=inventory["continuing_audit_obligation"]
    fleet["original_disk_guard_recovery_workers"]={k:True for k in inventory["original_disk_guard_recovery_workers"]}
    del inventory
    projected_ref=dict(path=str(t/"TERMINAL.json"),sha256="0"*64)
    fixture_guard=dict(path=str(t/"TERMINAL_GUARD_DRAINED.json"),sha256="1"*64)
    diag=dict(terminal=projected_ref,guard_retirement=fixture_guard,actual_guard_plan=full["fit"].P169,live=cl["live"]()[1],
              disposition=cl["MISMATCH"],producer_invocation_id=cl["IID"],resource_credit_bytes=0)
    ram=int(Path("/proc/meminfo").read_text().splitlines()[0].split()[1])*1024
    def reject(callback):
        try:callback()
        except (ValueError,KeyError):return
        raise ValueError("invalid funding accepted")
    counts=dict(populations=0,publisher_prices=0,transfer_combinations=0,adverse=0)
    floors=[]
    for focused in (False,True):
      for group in subsets(sorted(canonical)):
        data=copy.deepcopy(measured);roster=copy.deepcopy(fleet)
        closed={ep:canonical[ep] for ep in group}
        for ep in (*group,*([169] if focused else [])):
            key=str(ep);group_name,next_row=next((k,row) for k in groups for row in roster[k] if row["epoch"]==ep)
            roster[group_name].remove(next_row);data["population"].pop(next_row["unit"]["Id"])
            if ep in (169,172):
                native=data["survivors"].pop(key);guard=native["guard"]
                data["required_available_memory_bytes"]+=native["resident"]
                book=dict(root=original["booked_tree"]["path"] if ep==169 else str(full["H"]/"epoch172-standard-lane-20261110-v1"),
                          cap_bytes=guard["cap"],physical_bytes=guard["cap"]-guard["remaining"],remaining_bytes=guard["remaining"],historical_realized_bytes=0,
                          measurement="two complete stopped-tree walks",plan=guard["plan"],retired_guard_floor=guard["floor"])
                data["bookings"][key]=book
            else:
                data["required_available_memory_bytes"]+=data["joined_resident_lower_bounds"].pop(key)
                data["bookings"][key]["measurement"]="two complete stopped-tree walks"
                if ep==168:data["normal168"],data["active168_guard_floor"]=None,0
                else:
                    roster["original_disk_guard_recovery_workers"].pop(key);data["replacements"].pop(key)
                    data["closed_prestart_remaining"][key]=pub["PRESTART"][ep]
            if ep==169:
                data["closed_focused169"]=diag;roster["focused169_terminal"]=projected_ref;roster["focused169_guard_retirement"]=fixture_guard
            else:
                data[pub["CLOSURES"][ep]]=closed[ep];roster[pub["FLEET_FIELDS"][ep]]=closed[ep]["terminal"]
                if ep==172:roster["full172_guard_retirement"]=closed[ep]["guard_retirement"]
        tree=data["bookings"]["168"]
        raw,eq=full["host_floor"](roster,ledger,tree,data["survivors"],data["bookings"].get("172"),data["bookings"].get("169"))
        data["registered_host_equation"]=eq;data["original_aggregate_HOME_bytes"]=raw+data["epoch170_extension"]["extra_bytes"]
        base,floor,deficit=full["disk_budget"](data["original_aggregate_HOME_bytes"],data["candidate136"],data["bookings"],145,data["survivors"],data["replacements"],data["active168_guard_floor"],data["closed_prestart_remaining"])
        assert deficit==data["historical_baseline_deficit_bytes"]
        data.update(complete_required_HOME_bytes=base,protected_raw_floor_bytes=floor,recorded_unix_seconds=int(time.time()))
        assert pub["closing"](data,roster)==closed
        assert data["required_available_memory_bytes"]==pub["MEM"]-sum(v["resident"] for v in data["survivors"].values())-sum(data["joined_resident_lower_bounds"].values())
        unfunded=data["available_HOME_bytes"]<base+len(closed)*pub["BOOK"] or data["available_memory_bytes"]<data["required_available_memory_bytes"]
        if group and unfunded:
            reject(lambda:pub["validate"](data,roster,data["fleet"],closed[group[0]]["terminal"],group[0]))
        positive=dict(data,available_HOME_bytes=max(base+len(group)*pub["BOOK"],data["available_HOME_bytes"]),
                      available_memory_bytes=max(data["required_available_memory_bytes"],data["available_memory_bytes"]))
        counts["populations"]+=1
        for ep in group:
            assert pub["validate"](positive,roster,data["fleet"],closed[ep]["terminal"],ep)==base+len(group)*pub["BOOK"]
            counts["publisher_prices"]+=1
        for transfers in subsets(group):
            grants={ep:dict(retained_growth_bytes=pub["BOOK"],maximum_transfer_bytes=budget["ALL_CAP"][ep]) for ep in transfers}
            _,row=budget["calculate"](data,ledger,roster,prior,grants,closed,ram,64)
            counts["transfer_combinations"]+=1
        if focused:
            for defect in ("book","guard","resident","double-charge","grant"):
                bad=copy.deepcopy(data);reg=copy.deepcopy(roster)
                if defect=="book":bad["bookings"]["169"]["physical_bytes"]+=1
                elif defect=="guard":reg.pop("focused169_guard_retirement")
                elif defect=="resident":bad["joined_resident_lower_bounds"]["169"]=1
                elif defect=="double-charge":bad["survivors"]["169"]=measured["survivors"]["169"]
                if defect=="grant":
                    reject(lambda:budget["calculate"](bad,ledger,reg,prior,{169:{"retained_growth_bytes":pub["BOOK"],"maximum_transfer_bytes":0}},closed,ram,64))
                else:reject(lambda:pub["closing"](bad,reg))
                counts["adverse"]+=1
        floors.append(dict(old_available_resources_insufficient=unfunded,focused169_closed=focused,canonical=list(group),raw=raw,required_HOME_bytes=base,hard_memory_bytes=pub["MEM"],required_available_memory_bytes=data["required_available_memory_bytes"]))
    assert counts==dict(populations=64,publisher_prices=160,transfer_combinations=486,adverse=160)
    registrations={k:v for k,v in v12.items() if k.startswith("phase145") and k.endswith("registration")}
    assert len(registrations)==6 and measured["phase145"]["stage"]=="leased-worker"
    for k,registration in registrations.items():
        profile=Path(registration["profile"]["path"]).name
        assert hashlib.sha256((provider/profile).read_bytes()).hexdigest()==registration["profile"]["sha256"]
        readref(registration["seal"])
    return dict(projection_only=True,counts=counts,paid145=measured["phase145"],phase145_registrations=registrations,prices=floors,
                canonical_source_fixtures=historical,hypothetical_diagnostic_receipt=True,resource_credit_bytes=0)
