"""Test the recovered closure and status route on an isolated real cohort and recent fleet."""
import copy
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import runpy
import sys
from types import SimpleNamespace
from unittest.mock import patch

def run(package,work,fleet_path,fixture,fit_program):
    sys.path.insert(0,str(package))
    import closure
    import evidence
    import guard_stops
    import recovered166
    import retry10_event
    import status
    import terminal_event as event
    from cycle import Cycle
    import recovered

    need=evidence.need
    checks={}
    def rejected(name,action):
        try:action()
        except (ValueError,KeyError,FileNotFoundError) as exc:checks[name]=str(exc)
        else:raise AssertionError(name+" unexpectedly passed")
    def put(path,value):
        evidence.durable(path,value);return evidence.bound(path)
    fleet=evidence.checked(evidence.bound(fleet_path))
    current=evidence.bound(fleet_path)
    sample=evidence.checked(fleet["observer"])
    need(not (closure.T/"TERMINAL_SUCCESS.json").exists() and recovered166.transition(fleet) is None,"actual producer already terminal")
    rejected("no-genuine-terminal",closure.committed)
    rejected("local-publication-requires-closed-fleet",lambda:runpy.run_path(str(fit_program))["capture"](fleet_path,current["sha256"]))
    term,termref=event.document(fixture/"TERMINAL_SUCCESS.json",0o400)
    live,lr=event.document(fixture/"LIVE.json",0o600)
    ar=live["admission"];wr=live["first_protected_worker"]
    closure.validate_terminal(term,live,lr,ar,wr)
    old=evidence.checked(evidence.bound(closure.R/"epoch166-terminal-20261121-v1/LIVE.json"))["native"]["manager"]
    for key,value in [("producer_invocation_id",old["InvocationID"]),("producer_unit",old["Id"]),("canonical_r2_verified",True),
                      ("resource_credit_bytes",1),("source_admission",{}),("live",{})]:
        rejected("terminal-"+key,lambda k=key,v=value:closure.validate_terminal(dict(term,**{k:v}),live,lr,ar,wr))
    proof=dict(terminal=termref,first_worker=wr,admission=ar,live=lr,guard_retirement=dict(path="/fixture/drained",sha256="b"*64))
    original=evidence.checked(wr)["observer_row"]
    cfg=evidence.sealed(fleet["sole_next_observer"]);projected=recovered166.projected(cfg,original)
    need(projected==dict(cfg,replays=[r for r in cfg["replays"] if r!=original]) and len(cfg["replays"])==len(projected["replays"])+1,
         "other native rows changed")
    rejected("foreign-observer",lambda:recovered166.projected(cfg,dict(original,expected_producer_invocation_id=old["InvocationID"])))
    tmp=work/"project";evidence.ensure_dir(tmp);fake_ref=put(tmp/"fleet.json",dict(native_predecessor=current,observer=fleet["observer"]))
    selected,path=recovered166.select_config(cfg,Path(fleet["sole_next_observer"]["path"]),fake_ref,fleet,proof)
    need(selected==projected==evidence.sealed(evidence.bound(path)) and recovered166.select_config(cfg,Path(fleet["sole_next_observer"]["path"]),fake_ref,fleet,proof)==(selected,path),"normal projected schedule was not repeatable")
    out=work/"native";reports=work/"reports";evidence.ensure_dir(out);evidence.ensure_dir(reports)
    stamp=dt.datetime.now(dt.timezone.utc).replace(microsecond=0);tag=stamp.strftime("%H%M%S");day=stamp.strftime("%Y%m%d")
    fdir=out/f"root{tag}-live166167170-{day}-v1";rdir=reports/f"cycle{tag}-live166167170-19-{day}-v1";rd=rdir/"after-recovered166"
    for p in (fdir,rdir,rd):evidence.ensure_dir(p)
    prior_ref=fleet["effective_status_receipts"]["166"];prior=evidence.checked(prior_ref)
    # Use the original real held archive inode, sidecar and batch fixture with a manager envelope confined to this test.
    prior_time=evidence.utc(prior["after_status"]["sampled_at_utc"])
    finished=int(prior_time.timestamp()*1e6)+10_000_000
    synthetic=copy.deepcopy(term);synthetic["manager_terminal"]["__REALTIME_TIMESTAMP"]=str(finished)
    fixture_terminal=put(work/"terminal-clock.json",synthetic)
    c=SimpleNamespace(recovered166=dict(proof,terminal=fixture_terminal),now=prior_time+dt.timedelta(seconds=15))
    with patch("delivery_eta.prepare",return_value={"total_millis":600000}):
        after,archive=recovered166.forecast(c,prior["after_status"],prior)
    need(after["estimated_remaining_millis"]==595000 and archive==term["local_archive"] and after["phase"]=="verification","delivery clock or archive changed")
    status_ref=put(rd/"epoch-166.receipt.json",dict(prior,previous_receipt=prior_ref,before_etag=prior["after_etag"],before_sha256=prior["after_sha256"],
        before_status=prior["after_status"],after_status=after,after_sha256=hashlib.sha256(status.body(after)).hexdigest(),after_etag="c"*32,
        archive_sample=archive,producer_invocation_id=None,current_repair_owner="/root",recovered166_local_commit=termref))
    real_report=evidence.checked(fleet["authenticated_status_audit"])
    report=dict(real_report,sampled_at_utc=stamp.strftime("%Y-%m-%dT%H:%M:%SZ"),receipts=dict(real_report["receipts"],**{"166":status_ref}))
    repref=put(rd/"COMPLETED.json",report)
    participating={k:fleet[k] for k in ("owner","observer","original_disk_guard_recovery_workers","actual_executing_replays","actual_active_bootstraps",
                                         "actual_active_private_diagnostics","epochs","all_active_status_reports_authenticated_readback","authenticated_status_count")}
    accepted=dict(participating,recorded_unix_seconds=int(stamp.timestamp()),sampled_at_utc=report["sampled_at_utc"],authenticated_status_audit=repref,
                  effective_status_receipts=report["receipts"],recovered166_local_commit=termref)
    forest=copy.deepcopy(accepted);forest[recovered.FIELD].pop("166");forest["actual_executing_replays"]=[r for r in forest["actual_executing_replays"] if r["epoch"]!=166]
    fixed=SimpleNamespace(recovered166=proof,fleet=fleet,recovered166_history=None,next_cfg=projected)
    recovered166.install(forest,fixed)
    need(forest[closure.FIELD]==termref and forest["historical_recovered166_worker"]==fleet[recovered.FIELD]["166"] and
         [r for r in forest["epochs"] if r["epoch"]==166][0]["no_live_producer_claimed"],"missing accepted terminal fleet")
    validation=runpy.run_path(str(fit_program))["validate"]
    provider=evidence.checked(evidence.bound(work.parent/"whole-fit.json"))
    hypothetical=copy.deepcopy(provider)
    hypothetical["required_available_memory_bytes"]+=hypothetical["joined_resident_lower_bounds"]["166"]
    hypothetical["available_memory_bytes"]=max(hypothetical["available_memory_bytes"],hypothetical["required_available_memory_bytes"])
    del hypothetical["replacements"]["166"],hypothetical["population"][closure.UNIT],hypothetical["joined_resident_lower_bounds"]["166"]
    hypothetical.update(closed_recovered166=proof)
    hypothetical["bookings"]["166"]["measurement"]="two complete stopped-tree walks"
    testref=dict(path="/fixture/closed-fleet",sha256="c"*64)
    hypothetical["fleet"]=testref
    need(validation(hypothetical,forest,testref,termref)==hypothetical["complete_required_HOME_bytes"]+(16<<20),"publication retained floor changed")
    rejected("closed-rss-credit",lambda:validation(dict(hypothetical,joined_resident_lower_bounds={"166":1}),forest,testref,termref))
    rejected("unpriced-participant",lambda:validation(dict(hypothetical,population={}),forest,testref,termref))
    rejected("underfunded-event",lambda:validation(dict(hypothetical,available_HOME_bytes=hypothetical["complete_required_HOME_bytes"]),forest,testref,termref))
    fleet_ref=put(fdir/event.FLEET_NAME,forest)
    changes=event.Changes()
    def verify(f,report,terminal):return retry10_event.status_evidence(f,report,terminal,archive)
    try:
        projected=event.accepted(out,reports,termref,changes,lambda r:r,stamp.timestamp(),closure.FIELD,verify)
        need(projected==dict(fleet=fleet_ref,report=repref,status=status_ref),"event does not bind all 19 and recovered status")
        need(event.accepted(out,reports,termref,changes,lambda _:None,stamp.timestamp(),closure.FIELD,verify) is None,"superseded fleet admitted")
        rejected("other-terminal-event",lambda:event.accepted(out,reports,lr,changes,lambda r:r,stamp.timestamp(),closure.FIELD,verify))
        rejected("uncorrected-replay-readback",lambda:verify(forest,dict(report,receipts=real_report["receipts"]),termref))
        rejected("foreign-archive-size",lambda:retry10_event.status_evidence(forest,report,termref,dict(archive,size=archive["size"]+1)))
        state=work/"private-submission";evidence.ensure_dir(state);calls=[]
        fn=lambda f,s:(calls.append(f) or {"local_fixture":True})
        action=lambda:event.submit(state,termref,projected,Path("/fixture/socket"),fn,lambda _:None,retry10_event.UNIT,retry10_event.LAUNCH,"d"*64)
        need(action()=="submitted" and action()=="already-submitted-or-uncertain" and calls==[fleet_ref],"duplicate fixture submission")
    finally:changes.close()
    need(event.manager(retry10_event.UNIT)["ActiveState"]=="inactive" and not (retry10_event.STATE/"INTENT.json").exists(),"actual publication actor appeared")
    return dict(native_fixture=termref,positive_projected_config=evidence.bound(path),joined_report=projected,negative_controls=checks,
                frozen_source_inode=archive["inode"],submitted_once_in_fixture=True,remote_mutations=0,production_terminal=False)
