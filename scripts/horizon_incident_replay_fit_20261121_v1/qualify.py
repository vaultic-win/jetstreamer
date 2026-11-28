"""Qualify the fixed provider on the native registered fleet before normal deployment."""
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys

def digest(b):return hashlib.sha256(b).hexdigest()

def rejected(call):
    try:call()
    except (ValueError,KeyError):return
    raise ValueError("invalid input passed its gate")

def fork_control(m,fleet):
    s=m["s"];a=m["bound"](m["fit"].AD172);w=m["bound"](m["fit"].W172)
    first=m["bound"](a["first_guard"]);bootstrap=m["bound"](first["receipt"])
    historical=m["bound"](w["worker_guard"]["receipt"])
    def completed(v):
        raw=m["fit"].command("/usr/bin/journalctl","--no-pager","-ojson","--output-fields=UNIT,INVOCATION_ID,JOB_RESULT","_PID=1",
            "UNIT="+first["timer"]["Id"].replace(".timer",".service"),"INVOCATION_ID="+v["guard_invocation_id"],"-n12")
        s.need(any(json.loads(l).get("JOB_RESULT")=="done" and json.loads(l).get("INVOCATION_ID")==v["guard_invocation_id"]
                   for l in raw.splitlines()),"native fork control guard incomplete")
    def sample():
        _,roster=m["fleet_head"](fleet)
        p=m["survivors"](roster,m["bound"](m["fit"].BOOK))["172"]
        proof=p["guard"]["guard"];g=m["bound"](proof);completed(g)
        return dict(producer_unit=p["unit"],producer_invocation_id=p["invocation_id"],producer_pid=p["processes"][0][0],
                    start_ticks=p["processes"][0][1],processes=p["processes"],timer=p["timer"],timer_invocation_id=p["timer_invocation_id"],
                    plan=p["guard"]["plan"],first_guard=a["first_guard"],actor=m["fit"].AD172,admission=m["fit"].AD172,
                    guard=proof,guard_time=g["recorded_unix_seconds"])
    before=sample();completed(bootstrap);completed(historical)
    s.need(bootstrap["workers"]==[] and historical["workers"][0][0]==before["processes"][1][0] and
           all(g["producer_invocation_id"]==before["producer_invocation_id"] and g["plan_sha256"]==before["plan"]["sha256"] and
               g["producer"]["pid"]==before["producer_pid"] and g["trip_reason"] is None for g in [bootstrap,historical])
           and first["timer"]["InvocationID"]==w["worker_guard"]["timer"]["InvocationID"]==before["timer_invocation_id"],
           "normal node-to-worker guard chain differs")
    for attempt in range(3):
        try:
            observed=m["capture"](145,fleet)
            break
        except ValueError as ex:
            if str(ex)!="foreign 145 descendants" or attempt==2:raise
            runpy.run_path(str(Path(__file__).with_name("publication-fit")))["wait_for_145_probe"]()

    import time
    deadline=time.monotonic()+25
    while True:
        after=sample()
        if after["guard"]!=before["guard"]:break
        s.need(time.monotonic()<deadline,"next real timer guard missing")
        time.sleep(.8)
    m["same_fork"](before,after,True)
    for key in ("producer_invocation_id","processes","timer_invocation_id","plan","producer_pid","start_ticks"):
        rejected(lambda k=key:m["same_fork"](before,dict(after,**{k:None}),True))
    rejected(lambda:m["same_fork"](before,before,True))
    return observed,dict(first_no_worker=first["receipt"],first_with_worker=w["worker_guard"]["receipt"],before=before,after=after,
                         complete_native_fit=True,changed_identities_rejected=True)

def main():
    if os.geteuid() or not sys.flags.isolated or not __debug__:raise ValueError("native isolated root session required")
    here=Path(__file__).resolve().parent;repo=Path(sys.argv[4]).resolve(strict=True)
    path=here/"post-stop-fit"
    m=runpy.run_path(str(path));s=m["s"];D=m["D"]
    fleet=s.ref(Path(sys.argv[1]),sys.argv[2]);commit=sys.argv[3]
    def git(*args):
        return subprocess.check_output(["/usr/bin/git","-c","safe.directory="+str(repo),"-C",repo,*args])
    git("merge-base","--is-ancestor",commit,"origin/account-updates")
    src={}
    for name in ("post-stop-fit","retire-original-timers.py","incident_extensions.py","qualify.py"):
        p=here/name;b=p.read_bytes()
        s.need(b==git("show",commit+":scripts/horizon_incident_replay_fit_20261121_v1/"+name),"unpublished qualification source")
        src[name]=digest(b)
    closure_path=here/"closure.py"
    source=git("show",commit+":scripts/horizon_epoch166_retry10_delivery_20261121_v1/closure.py")
    s.need(closure_path.read_bytes()==source,"different terminal registration source")
    src["closure.py"]=digest(source)
    _,adapter,timeout_rejoin=m["profile145"](here,timeout_rejoin=True)
    timeout=runpy.run_path(str(adapter))
    s.need(timeout["TIMEOUT_REJOIN"] and timeout["REJOIN"] and timeout["OLD"]==m["extensions"]["FAILED_REJOIN"]
           and timeout["OLD_FAILURE"]=="baa00ca8b52aca80b105bf5582f955af8a3f9e22ce662908ce7a75afccfb1943"
           and timeout["OLD_RECOVERY"]=="e992566275e63b28a020c847c02637626b245161a2e39f843ac1da4d64793b2f"
           and timeout["IMAGE"].parent==adapter.parent and timeout["UNIT"]==m["extensions"]["VERIFIER_UNIT"],
           "new 145 verifier adapter targets another predecessor")
    rejected(lambda:m["profile145"](here,post=True,timeout_rejoin=True))
    rejected(lambda:m["profile145"](here,rejoin=True,timeout_rejoin=True))
    _,post8,post8_binding=m["profile145"](here,recovery_post=True)
    adapter8=runpy.run_path(str(post8))
    s.need(adapter8["TIMEOUT_SUCCESSOR"] and adapter8["BOOTSTRAP"]=="d37f36f898a44932a19fd50d7014a6fe"
           and adapter8["ADVANCING"]=="6235fbd8e36064d57a9cd6b7af2ad0d05ce8b41766134cde7be7337ebc133d76"
           and adapter8["PIPE"].parent.name=="public-rseek-reconnect-56bf2bf0937f","foreign 145 successor post adapter")
    for name in ("qualify_four_prices.py","publication-fit"):
        data=(here/name).read_bytes()
        s.need(data==git("show",commit+":scripts/horizon_epoch166_retry10_delivery_20261121_v1/"+name),"different publication pricing source")
        src[name]=digest(data)
    _,_,rejoin=m["profile145"](here,rejoin=True)
    _,_,current_post=m["profile145"](here,post=True,rejoin=True)
    _,_,binding=m["profile145"](here)
    _,_,post_binding=m["profile145"](here,True)
    rejected(lambda:m["fleet_head"](dict(fleet,sha256="0"*64)))
    if fleet!=m["PREV"]:rejected(lambda:m["fleet_head"](m["PREV"]))
    rejected(lambda:m["capture"](171,fleet))
    observed,fork=fork_control(m,fleet)
    ext=m["extensions"];mgr=s.show(ext["VERIFIER_UNIT"])
    if mgr["ActiveState"]=="failed" and mgr["InvocationID"] in (ext["FAILED_VERIFIER"],ext["FAILED_REJOIN"]):
        closure=ext["failed_verifier"](s,mgr,mgr["InvocationID"])
        s.need(all(observed["phase145"][k]==v for k,v in closure.items()),"failed 145 evidence missed from full fit")
        for key,value in [("InvocationID","0"*32),("ActiveState","active"),("MainPID","1"),("ExecMainStatus","0")]:
            rejected(lambda:ext["failed_verifier"](s,dict(mgr,**{key:value}),mgr["InvocationID"]))
        rejected(lambda:ext["failed_verifier"](s,mgr,"f"*32))
    elif mgr["InvocationID"]=="d37f36f898a44932a19fd50d7014a6fe":
        original,_=s.read(D/"native-0581394abb5a44b98358e7f72f141302.json","e6b2eca697f54ea89d3bb2222521a92a56d90ff18c04a8daca26b443dab11baf")
        closure=original["closed_verifier145"];phase=observed["phase145"]
        s.need(phase["invocation_id"]==mgr["InvocationID"] and phase["stage"]=="leased-worker" and
               phase["window"]["failed_predecessor"]==closure["failure"] and phase["window"]["prior_started"]==closure["recovery"] and
               phase["window"]["leases_parent"] and phase["window"]["leases_worker"],"foreign advancing timeout recovery")
    else:
        original,_=s.read(D/"native-462833a6aba74481af5e276512bdcad4.json",
                           "3d9b77551ceafa52ca0fef30f957b7aba6053f55c84e320cf2632067b85c6ec0")
        closure=original["closed_verifier145"]
        phase=observed["phase145"]
        s.need(phase["invocation_id"]==mgr["InvocationID"]=="dc043eb78c4a4349b0098760dc764a1f" and phase["stage"]=="leased-worker" and
               phase["window"]["failed_predecessor"]==closure["failure"] and
               phase["window"]["prior_started"]==closure["recovery"] and
               phase["window"]["leases_parent"] and phase["window"]["leases_worker"],"foreign advancing 145")
    s.need(observed["fits"] and observed["stopped_generation_resident_credit_bytes"]==0 and
           set(observed["actual_original_stops"])=={"166","167","170"} and set(observed["survivors"])=={"169","172"} and
           set(observed["bookings"])=={"166","167","168","170"} and
           observed["available_HOME_bytes"]>=observed["complete_required_HOME_bytes"] and
           observed["available_memory_bytes"]>=observed["required_available_memory_bytes"],"native capacity failed")
    booking168=observed["bookings"]["168"]
    guard168=m["bound"](booking168["measured_guard"])
    s.need(guard168["producer_invocation_id"]==observed["normal168"]["actor"]["producer_invocation_id"] and
           guard168["root_physical_observation"]["maximum_physical_bytes"]==booking168["cap_bytes"],"unbound 168 sample")
    if booking168["measurement"]=="two complete native whole-tree walks":
        physical=guard168["root_physical_observation"]
        s.need(booking168["physical_bytes"]==min(physical[k]["physical_bytes"] for k in ("first","second"))
               and all(physical[k]["vanished_entries"]==0 for k in ("first","second")),"168 booking/sampled bytes differ")
    floor=m["disk_budget"];raw=observed["original_aggregate_HOME_bytes"];books=observed["bookings"];peer=observed["survivors"];optional=observed["candidate136"]
    for epoch in (145,166,167,168,170):
        required,protected,delta=floor(raw,optional,books,epoch,peer,observed["replacements"],observed["active168_guard_floor"])
        allowance=books.get(str(epoch),{}).get("remaining_bytes",0)
        s.need(required==protected+allowance and protected>=8297502499408 and delta>=0,"unfunded candidate")
    normal=observed["normal168"]
    s.need(normal and normal["admission"] and normal["first_worker"] and normal["ordinary_canonical"] and
           {"166","167"}<=observed["replacements"].keys() and observed["joined_resident_lower_bounds"]["168"]>0 and
           observed["active168_guard_floor"]==m["bound"](m["bound"](normal["admission"])["actual_guard_plan"])["minimum_free_bytes"] and
           observed["protected_raw_floor_bytes"]>=observed["active168_guard_floor"],"missing admitted 168 protection")
    # A replacement's new bytes consume its own prepaid interval exactly once.
    older=books["170"];grown=dict(books);amount=1<<20
    grown["170"]=dict(older,remaining_bytes=older["remaining_bytes"]-amount,physical_bytes=older["physical_bytes"]+amount)
    baseline=floor(raw,optional,books,170,peer,{})
    realized=floor(raw,optional,grown,170,peer,{"170":dict(prestart_remaining=older["remaining_bytes"],floor=baseline[1])})
    s.need(realized[0]+amount==baseline[0] and realized[1]==baseline[1],"own growth changes protected unrelated claims")
    incumbent=observed["replacements"]["166"]
    others={k:v for k,v in observed["replacements"].items() if k!="166"}
    paid={"166":incumbent["prestart_remaining"]}
    baseline=floor(raw,optional,books,145,peer,observed["replacements"],observed["active168_guard_floor"])
    transitioned=floor(raw,optional,books,145,peer,others,observed["active168_guard_floor"],paid)
    # The obsolete 166 guard floor may be removed once the exact guard drains.
    # Keep the complete original aggregate when its remaining native floors do not dominate.
    s.need(baseline[0]==max(transitioned[0],incumbent["floor"]) and transitioned[2]==baseline[2],
           "closed 166 physical storage was credited twice")
    term=runpy.run_path(str(closure_path))
    s.need(not term["DONE"].exists() and not (term["T"]/"TERMINAL_SUCCESS.json").exists() and
           observed["closed_recovered166"] is None and term["IID"]==incumbent["producer_invocation_id"],
           "active generation registered as closed")
    rejected(lambda:term["expected_timer"]({"Id":"foreign"}))
    metered,registration168=m["terminal168_profile"]()
    try:metered["inspect"]()
    except FileNotFoundError as ex:
        s.need(Path(ex.filename)==metered["T"]/"TERMINAL_SUCCESS.json","closure helper rejected unrelated evidence")
    else:raise ValueError("live 168 incorrectly marked closed")
    s.need(observed["closed_metered168"] is None and observed["normal168"]["actor"]["producer_invocation_id"]==metered["IID"] and
           observed["registered_host_equation"]["retained_168_remaining"]==books["168"]["remaining_bytes"],
           "metered 168 original allowance not in complete host fit")
    # The common raw equation already includes cap minus physical 168 bytes.
    # Dropping its retired guard must not subtract physical growth for a second time.
    f,rows=m["fleet_head"](fleet)
    t=dict(physical_bytes=books["168"]["physical_bytes"],root=books["168"]["root"],cap=books["168"]["cap_bytes"])
    raw168,eq=m["fit"].floor(f,m["bound"](m["fit"].BOOK),t,peer)
    s.need(raw==raw168+(observed["epoch170_extension"]["extra_bytes"] if observed["epoch170_extension"] else 0) and
           eq["retained_168_remaining"]==t["cap"]-t["physical_bytes"] and
           floor(raw,optional,books,145,peer,others,0,paid)[0]<=baseline[0],"closed metered booking changed original equation")
    adapter=runpy.run_path(str(here/"publication-fit"))
    prices=runpy.run_path(str(here/"qualify_four_prices.py"))["trials"](m,adapter,observed,f)
    name="native-"+os.environ["INVOCATION_ID"]+".json"
    receipt=dict(schema="horizon-incident-replay-fit-native-qualification-v1",source_commit=commit,source_sha256=src,fit=observed,five_publication_prices=prices,phase145_recovery_post_registration=post8_binding,phase145_timeout_rejoin_registration=timeout_rejoin,phase145_registration=binding,phase145_post_registration=post_binding,phase145_rejoin_registration=rejoin,phase145_current_post_registration=current_post,closed166_budget_conserved=True,closed168_booking_once=True,closure168_registration=registration168,
                 rejected=["wrong fleet digest","nonmember epoch","superseded incident fleet"],own_growth_conservation=True,worker_fork_control=fork,closed_verifier145=closure)
    target=D/name
    with target.open("xb") as f:
        os.fchmod(f.fileno(),0o400);f.write((json.dumps(receipt,sort_keys=True,indent=2)+"\n").encode());f.flush();os.fsync(f.fileno())
    fd=os.open(D,os.O_DIRECTORY);os.fsync(fd);os.close(fd)
    print(json.dumps(dict(path=str(target),sha256=digest(target.read_bytes()))))

if __name__=="__main__":main()
