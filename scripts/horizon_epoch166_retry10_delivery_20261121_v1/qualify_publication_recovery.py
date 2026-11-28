"""Exercise durable pre-admission recovery inside an isolated root-owned fixture."""
from itertools import combinations
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

here = Path(__file__).resolve().parent
sys.path[:0] = [str(here), str(here.parent/"horizon_epoch166_delivery_20261121_v1")]
import publication_recovery as recovery
import retry10_event as pub
import terminal_event as event


def put(path, body):
    event.once(path, body)
    return recovery.checked(path)[1]


def fixture(root):
    root.mkdir(mode=0o700)
    state = root/"event-state"
    state.mkdir(mode=0o700)
    archive = dict(sha256="e"*64, size=9, inode=79, device=22)
    terminal = put(root/"TERMINAL_SUCCESS.json", dict(transaction_id="local", local_archive=archive))
    auth = SimpleNamespace(T=root, inspect=lambda: {"terminal": terminal})
    profile = pub.Publication(166, root, root/"run-committed.sh", root/"publication-fit",
                              "horizon-recovery-qa-"+os.environ["INVOCATION_ID"][:12]+"-"+root.name+".service", auth)
    return profile, state, terminal, archive


def make_admission(profile, terminal, archive, iid, intent):
    run = profile.delivery / ("run-"+iid)
    run.mkdir(mode=0o700)
    cap = put(run/"capacity.json", dict(terminal=terminal, boot_id=recovery.boot(), invocation_id=iid,
        fleet=intent["fleet"],provider={"sha256":intent["provider_sha256"]}))
    return put(run/"admission.json", dict(epoch=166, invocation_id=iid, unit=profile.unit,
        schema="horizon-epoch166-committed-publication-admission-v1", operation="current-reader-sync-retain-local",
        boot_id=recovery.boot(), transaction_id="local", terminal_sha256=terminal["sha256"],
        archive_bytes=archive["size"], archive_sha256=archive["sha256"], archive_inode=archive["inode"],
        archive_device=archive["device"], capacity=cap, publication_authorized=True))


def delayed_cadence(root):
    source = event.R / "root154959-live166167170-20261121-v1"
    fleet, fr = event.document(source/event.FLEET_NAME, 0o600)
    observer, observed = event.document(Path(fleet["observer"]["path"]), 0o644)
    report, rr = event.document(Path(fleet["authenticated_status_audit"]["path"]), 0o600)
    assert fr["sha256"].startswith("3c83ed29") and observed == fleet["observer"] == report["observer"]
    assert rr == fleet["authenticated_status_audit"]
    scheduled = "2026-11-21T15:49:59Z"
    now = fleet["recorded_unix_seconds"]
    actual = event.sample_time(fleet, source, scheduled)
    assert actual == fleet["sampled_at_utc"] == report["sampled_at_utc"] == "2026-11-21T15:50:22Z"
    def write(path, body, mode):
        path.write_text(json.dumps(body))
        path.chmod(mode)
        return event.document(path, mode)[1]
    header = {k: fleet[k] for k in ("owner", "recorded_unix_seconds", "sampled_at_utc", "observer",
                                     "all_active_status_reports_authenticated_readback", "authenticated_status_count")}
    group_count = readbacks = 0
    for size in range(1,6):
        for group in combinations(event.report_labels(), size):
            runtime = root / ("sample-" + "-".join(map(str, group))) / "r"
            reports = runtime.parent/"reports"
            directory = runtime/source.name
            directory.mkdir(parents=True)
            base = reports / "cycle154959-live166167170-19-20261121-v1"
            target = event.completion_report_dir(base,group)/"COMPLETED.json"
            target.parent.mkdir(parents=True)
            rep = write(target, report, 0o600)
            terms = {event.report_labels()[e]+"_local_commit":{"path":"/fixture/"+str(e),"sha256":f"{e:064x}"} for e in group}
            candidate = dict(header,**terms,authenticated_status_audit=rep)
            path = directory/event.FLEET_NAME
            fref = write(path,candidate,0o600)
            changes=event.Changes()
            try:
                for field,term in terms.items():
                    assert event.accepted(runtime,reports,term,changes,lambda r:r,now,field)==dict(fleet=fref,report=rep)
                    assert event.accepted(runtime,reports,term,changes,lambda r:r,now+2401,field) is None
                    readbacks+=1
                if group==(166,172):
                    for changed in (dict(candidate, sampled_at_utc="2026-11-21T15:49:59Z"),
                                    dict(candidate, observer=rr),
                                    dict(candidate, full172_local_commit=None)):
                        write(path,changed,0o600)
                        try:
                            event.accepted(runtime,reports,terms["recovered166_local_commit"],changes,lambda r:r,now,
                                           "recovered166_local_commit")
                        except event.Rejected:
                            pass
                        else:
                            raise AssertionError("crossed or incomplete delayed sample was accepted")
            finally:
                changes.close()
            group_count+=1
    assert (group_count,readbacks)==(31,80)
    return dict(fleet=fr,observer=observed,report=rr,scheduled="2026-11-21T15:49:59Z",actual=actual,
                subsets=group_count,checked_readbacks=readbacks,stale_rejected=True,crossed_refusals=3)


def suite(root):
    p,state,term,a = fixture(root/"native")
    fit = "f"*64
    ref = lambda c: dict(path=str(root/("fleet-"+c)), sha256=c*64)
    earlier = dict(fleet=ref("a"), status=ref("b"), report=ref("c"))
    fresh = dict(fleet=ref("d"), status=ref("e"), report=ref("f"))
    sock = root/"missing.sock"
    old = dict(terminal=term, **earlier, unit=p.unit, controller=str(p.launch), provider_sha256=fit,
               ssh_socket=str(sock), observed_unix_seconds=int(time.time()))
    native_ref = put(state/"INTENT.json", old)
    binary = p.launch.with_name("controller")
    source = p.delivery/"controller.c"
    source.write_text('#include <stdio.h>\n#include <unistd.h>\nint main(void){sleep(3);fputs("Error: fresh publication fit failed: fixture\\n",stderr);sleep(1);return 1;}\n')
    subprocess.run(["/usr/bin/cc","-O0","-o",binary,source],check=True)
    args = ["/usr/bin/systemd-run","--quiet","--unit="+p.unit,"-p","Type=exec","-p","PrivateNetwork=yes",
            "-p","ProtectSystem=strict","-p","ProtectHome=read-only","-p","MemoryMax=32M","-p","MemorySwapMax=0",
            "-p","CPUQuota=10%","-p","Nice=15","-p","TasksMax=8","-p","RuntimeMaxSec=15", "--",
            binary,"sync",old["fleet"]["path"],old["fleet"]["sha256"],fit]
    assert recovery.unoccupied(recovery.manager(p.unit))
    subprocess.run(args,check=True)
    active, native = recovery.observe(p,term,old,set())
    assert active == "running", (active, native)
    submitted = put(state/"SUBMISSION.json", dict(terminal=term, **earlier, unit=p.unit, manager=native["manager"]))
    iid=native["manager"]["InvocationID"]
    for _ in range(60):
        if recovery.manager(p.unit)["ActiveState"]=="failed":
            break
        time.sleep(0.15)
    disposition, failed=recovery.observe(p,term,old,set())
    assert disposition=="fit-refused", (disposition,failed)
    assert recovery.observe(p,term,dict(old, fleet=fresh["fleet"]),set())[0]=="uncertain"
    cmd=failed['exec_start']; mgr=failed['manager']
    good_history={iid:[recovery.STARTED]}; log=recovery.journal("_SYSTEMD_INVOCATION_ID="+iid,"_PID="+mgr["ExecMainPID"])
    def reject(m=mgr, c=cmd, h=good_history, e=log):
        assert recovery.classify(p, old, set(), m, c, h, e)=="uncertain"
    reject(m=dict(mgr,Job="215"));reject(m=dict(mgr,ControlPID="1"))
    reject(c=[cmd[0],[cmd[0],"prepare",*cmd[1][2:]],*cmd[2:]])
    reject(h=dict(good_history,**{"1"*32:[recovery.STARTED]}))
    reject(e=[dict(x,_EXE="/foreign-controller") for x in log])
    reject(e=[dict(x,_BOOT_ID="0"*32) for x in log])
    reject(e=[dict(x,MESSAGE="Error: unknown") for x in log])
    rejection_count=7
    class Fresh:
        changed=False
        def wait(self):
            assert not self.changed and (state/"recovery-000000-retryable.json").exists()
            self.changed=True
    changes=Fresh()
    calls=[]
    new=p._replace(launch=p.delivery/"v2/run-committed.sh")
    previous={str(p.launch):fit}
    new_fit="9"*64
    def fake_launch(pr, intent, _):
        assert pr==new and intent["controller"]==str(new.launch) and intent["provider_sha256"]==new_fit and intent["fleet"]==fresh["fleet"] and recovery.unoccupied(recovery.manager(p.unit))
        calls.append(intent["fleet"])
        make_admission(p,term,a,"2"*32,intent)
        return dict(returncode=0,pre_manager_refusal=False)
    with patch.object(recovery.event,"agents",lambda:sock), patch.object(recovery,"launch",fake_launch):
        get=lambda:fresh if changes.changed else earlier
        ans=recovery.service(new,state,term,new_fit,get,changes,previous)
        assert ans==recovery.service(new,state,term,new_fit,get,changes,previous) and len(calls)==1 and changes.changed
    assert recovery.checked(state/"INTENT.json")[1]==native_ref and recovery.checked(state/"SUBMISSION.json")[1]==submitted
    # A launcher or event crash without attributable evidence cannot silently submit again.
    p2,s2,t2,a2=fixture(root/"uncertain")
    old2=dict(old,terminal=t2,unit=p2.unit,controller=str(p2.launch))
    put(s2/"INTENT.json",old2)
    try:
        with patch.object(recovery,"launch",side_effect=AssertionError("unknown attempt relaunched")):
            recovery.service(p2,s2,t2,fit,lambda:fresh,Fresh())
    except event.Rejected as err:
        assert "reconciliation" in str(err)
    else:
        raise AssertionError("unknown prior attempt certified")
    p3,s3,t3,a3=fixture(root/"preflight")
    calls3=[]
    def refused_then_admitted(profile, intent, _):
        calls3.append(intent["fleet"])
        if len(calls3)==1:
            return dict(returncode=1,pre_manager_refusal=True)
        make_admission(profile,t3,a3,"3"*32,intent)
        return dict(returncode=0,pre_manager_refusal=False)
    class Updated:
        changed=False
        def wait(self):
            refuse=recovery.checked(s3/"recovery-000000-retryable.json")[0]
            assert not self.changed and refuse["reason"]=="pre-manager-refusal"
            self.changed=True
    changed=Updated()
    with patch.object(recovery.event,"agents",lambda:sock), patch.object(recovery,"launch",refused_then_admitted):
        get=lambda:fresh if changed.changed else earlier
        res=recovery.service(p3,s3,t3,fit,get,changed)
        assert recovery.service(p3,s3,t3,fit,get,changed)==res and calls3==[earlier["fleet"],fresh["fleet"]]
        done=recovery.checked(s3/"SUBMISSION.json")[0]
        assert done["admission"]==res["admission"] and done["fleet"]==fresh["fleet"] and done["admitted_invocation_id"]=="3"*32
    # Exercise the real sealed launchers at a named, missing socket before PID1.
    preflight={}
    assert not sock.exists()
    for epoch in event.PUBLICATION_EPOCHS:
        profile=pub.current_reader(epoch)
        before=recovery.manager(profile.unit)
        assert recovery.unoccupied(before)
        result=recovery.launch(profile,dict(old,fleet=fresh["fleet"]),sock)
        assert result["pre_manager_refusal"] and recovery.manager(profile.unit)==before
        preflight[str(epoch)]=dict(launcher=event.member(profile.launch,0o555)[1],result=result)
    five_price = {}
    receipt = event.R / "incident-replay-fit-20261121-v1/FIVE_TERMINAL_PUBLICATION_CAPACITY.json"
    prices, price_ref = recovery.checked(receipt)
    assert price_ref["sha256"] == "c6188c635e858d17c4d5cbf41f8985fbb0f6fabe01c9f637a879f54e087aea51"
    manifest, manifests_ref=recovery.checked(receipt.parent/"FOUR_V12_PUBLICATION_CONTROLLERS.json")
    assert manifests_ref["sha256"]=="94bc663185a268b2999b78eb9242d0322836cffa7033eedc01f213cee166a47b"
    assert manifest["capacity"]==price_ref and manifest["canonical_writes"]==0 and manifest["unit_changes"]==0
    for epoch in event.PUBLICATION_EPOCHS:
        profile=pub.five_source_reader(epoch)
        prior=pub.current_reader(epoch)
        prior_manifest=event.document(profile.delivery/"event-tools-current/programs.json",0o444)[0]
        assert prior.unit==profile.unit and prior.delivery==profile.delivery and pub.bound_fit(prior,prior_manifest)
        authority=prices["epochs"][str(epoch)]
        launcher=event.member(profile.launch,0o555)[1]
        programs={"run-committed.sh":launcher,"publication-fit":authority["executable"]}
        assert pub.bound_fit(profile,programs)==authority["executable"]["sha256"]
        ctrl_seal,seal_ref=event.document(profile.launch.parent/"deployment-seal-receipt.json",0o444)
        assert ctrl_seal["destination"]==str(profile.launch.parent)
        qualified=manifest["epochs"][str(epoch)]
        assert qualified["controller"]==seal_ref and qualified["launcher"]==launcher and qualified["provider"]==authority["executable"]
        controller=event.member(profile.launch.with_name("controller"),0o555)[1]
        for member in (controller,launcher):
            assert any(m["name"]==Path(member["path"]).name and m["sha256"]==member["sha256"] for m in ctrl_seal["members"])
        before=recovery.manager(profile.unit)
        assert recovery.unoccupied(before)
        out=recovery.launch(profile,dict(old,fleet=fresh["fleet"],provider_sha256=authority["executable"]["sha256"]),sock)
        assert out["pre_manager_refusal"] and recovery.manager(profile.unit)==before
        five_price[str(epoch)]=dict(programs=programs,controller=controller,controller_seal=seal_ref,
                                   prior_manifest=prior_manifest,capacity=authority)
    cadence_path = (event.R/"epoch172-current-delivery-20261121-v1/five-cadence-fixture-stage-v3"
                    /"1ba1bbbfba8843d2bbcc8bed82552a9f/QUALIFIED.json")
    cadence, cadence_ref = event.document(cadence_path,0o600)
    assert cadence_ref["sha256"]=="e7a2c9d3e3e2b7ebc4403aab75e8f11d32fb4db1aa6189bc006b131b26b33f79"
    original, fr=event.document(Path(cadence["base_fleet"]["path"]),0o600)
    assert fr==cadence["base_fleet"]
    joined=[]
    for case in cadence["fixture_status_and_fleet_passes"]:
        report, rr=event.document(Path(case["report"]["path"]),0o600)
        assert rr==case["report"] and set(report["status_epochs"])==event.EPOCHS and report["authenticated_readback"]
        candidate=dict(original,effective_status_receipts=report["receipts"])
        for epoch in (e for e in case["closed"] if e in event.PUBLICATION_EPOCHS):
            profile=pub.five_source_reader(epoch)
            receipt, sr=event.document(Path(report["receipts"][str(epoch)]["path"]),0o600)
            term_ref=receipt[profile.authority.FIELD]
            term_body, actual=event.document(Path(term_ref["path"]),0o600)
            assert actual==term_ref and pub.status_evidence(candidate,report,term_ref,term_body["local_archive"],profile)==sr
            joined.append(dict(epoch=epoch,group=case["closed"],programs=five_price[str(epoch)]["programs"],report=rr,status=sr))
    assert len(cadence["fixture_status_and_fleet_passes"])==28 and {j["epoch"] for j in joined}==set(event.PUBLICATION_EPOCHS)
    with TemporaryDirectory(dir=root, prefix="delayed-cadence-") as scratch:
        delayed = delayed_cadence(Path(scratch))
    return dict(registered_controllers=manifests_ref,registered_cadence=cadence_ref,joined_terminal_status=joined,
                five_price=five_price,price_authority=price_ref,legacy_to_successor_retried=True,
                delayed_cadence=delayed,native_active=native,native_fit_refusal=failed,fixture_admission=ans,refutations=rejection_count,
                stale_fleet_waited=True,prior_intent=native_ref,prior_submission=submitted,admitted_once=len(calls),
                unknown_held=True,pre_manager_retried_once=True,actual_pre_manager_refusals=preflight,production_dispatches=0,r2_writes=0)


if __name__=="__main__":
    assert __debug__ and sys.flags.isolated and os.geteuid()==0 and len(sys.argv)==2
    print(json.dumps(suite(Path(sys.argv[1])),sort_keys=True))
