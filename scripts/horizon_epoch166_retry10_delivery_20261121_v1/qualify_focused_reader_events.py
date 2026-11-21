"""Verify that a focused-diagnostic closure selects the admitted publisher for each original archive."""
import itertools
import sys
from pathlib import Path

here = Path(__file__).resolve().parent
sys.path[:0] = [str(here), str(here.parent/"horizon_epoch166_delivery_20261121_v1")]
import publication_recovery as recovery
import retry10_event as pub
import terminal_event as event


def check(ref, mode):
    doc, actual = event.document(Path(ref["path"]), mode)
    event.need(ref == actual, "fixture receipt changed")
    return doc


def qualify(manifest, digest, work):
    raw, ref = event.document(manifest, 0o400)
    event.need(manifest == event.R/"incident-replay-fit-20261121-v1/FIVE_V13_PUBLICATION_CONTROLLERS.json" and
               ref["sha256"] == digest and set(raw["epochs"]) == {"166", "167", "168", "170", "172"} and
               raw["canonical_writes"] == raw["unit_changes"] == 0,
               "unregistered controller handoff")
    previous = event.R/"publication-events-preadmission-recovery-20261121-v1/FIVE_SOURCE_CURRENT_EVENTS_QUALIFIED.json"
    previous_suite, previous_ref = event.document(previous, 0o400)
    event.need(previous_ref["sha256"]=="e82e0b07f6bd5bc48babb315824865a05e73d1753996a44bd7630d100c3e677f",
               "wrong preceding four-event handoff")
    v12 = check(previous_suite["qualified"], 0o400)["result"]
    missing = work/"absent-agent.sock"
    event.need(not missing.exists(), "fixture socket exists")
    prices = check(raw["capacity"],0o400)
    event.need(raw["capacity"]["sha256"] == "7c106882ea39d756afe6fa5beab8c8a87041b7b9dc8ce4a6e878f7c172c9d7df",
               "different capacity registration")
    rows = {}
    for epoch in event.PUBLICATION_EPOCHS:
        before = pub.current_reader(epoch)
        prior = pub.five_source_reader(epoch)
        current = pub.focused169_reader(epoch)
        event.need(current.delivery == prior.delivery == before.delivery and current.unit == prior.unit == before.unit and
                   current.authority.FIELD == prior.authority.FIELD == before.authority.FIELD, "crossed epoch owner")
        former = {}
        for p, package in ((before,"event-tools-current"),(prior,"event-tools-five-v1")):
            programs, pf = event.document(p.delivery/package/"programs.json",0o444)
            former[str(p.launch)]=dict(programs=pf, fit=pub.bound_fit(p,programs))
        item = raw["epochs"][str(epoch)]
        event.need(item["epoch"]==epoch and item["provider"]==prices["epochs"][str(epoch)]["executable"],"crossed capacity")
        programs={"run-committed.sh":item["launcher"],"publication-fit":item["provider"]}
        fit = pub.bound_fit(current, programs)
        capacity = prices["epochs"][str(epoch)]
        provider_seal = check(capacity["seal"], 0o444)
        event.need(provider_seal["destination"] == str(current.fit.parent) and any(
            m["name"] == current.fit.name and m["mode"] == "0555" and m["sha256"] == fit for m in provider_seal["members"]
        ), "provider outside qualified deployment")
        controller = check(item["controller"],0o444)
        binary = event.member(current.launch.with_name("controller"),0o555)[1]
        event.need(controller["destination"]==str(current.launch.parent) and all(
            any(m["name"]==Path(r["path"]).name and m["sha256"]==r["sha256"] for m in controller["members"])
            for r in (programs["run-committed.sh"],binary)), "incomplete controller seal")
        old = recovery.manager(current.unit)
        event.need(recovery.unoccupied(old),"production receiver already exists")
        launched = recovery.launch(current, dict(fleet={"path":"/fixture/fleet","sha256":"a"*64},provider_sha256=fit), missing)
        event.need(launched["pre_manager_refusal"] and recovery.manager(current.unit)==old, "fixture reached a manager")
        rows[epoch]=dict(prior=former,programs=programs,controller=item["controller"],controller_binary=binary,provider_seal=capacity["seal"])
    crossed = 0
    for a,b in itertools.permutations(rows,2):
        for name in rows[b]["programs"]:
            mixed=dict(rows[a]["programs"], **{name:rows[b]["programs"][name]})
            try:
                pub.bound_fit(pub.focused169_reader(a),mixed)
            except event.Rejected:
                crossed+=1
            else:
                raise RuntimeError("accepted another epoch's executable")
    event.need(crossed==24,"incomplete crossed program controls")
    event.need(len(v12["joined_terminal_status"]) == 53 and
               {row["epoch"] for row in v12["joined_terminal_status"]} == set(rows), "original status matrix changed")
    for row in v12["joined_terminal_status"]:
        epoch=row["epoch"]
        report=check(row["report"],0o600)
        candidate=dict(observer=report["observer"],effective_status_receipts=report["receipts"])
        receipt=check(row["status"],0o600)
        profile=pub.focused169_reader(epoch)
        terminal=receipt[profile.authority.FIELD]
        source=check(terminal,0o600)["local_archive"]
        event.need(pub.status_evidence(candidate,report,terminal,source,profile)==row["status"],"changed committed epoch status")
    event.need(169 not in event.PUBLICATION_EPOCHS and 169 not in event.report_labels(),"diagnostic became a publication")
    return dict(manifest=ref,prior=previous_ref,epochs=rows,refused_crossed=crossed,
                original_terminal_statuses=len(v12["joined_terminal_status"]),production_dispatches=0,r2_writes=0)
