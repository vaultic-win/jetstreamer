"""Qualify the 172 event's five-source price and its registered earlier submission."""
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import sys
import time
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
import focused169_full172_event as route
import full172_event
import qualify_full172_event as qa
import publication_recovery as recovery
import retry10_event as publication
import terminal_event as event

P = route.profile()
PACKAGE = "event-tools-focused169"


def programs():
    root = event.R/"incident-replay-fit-20261121-v1"
    handoff, ref = event.document(root/"FIVE_V13_PUBLICATION_CONTROLLERS.json",0o400)
    capacity, cap = event.document(root/"FOCUSED169_FIVE_PUBLICATION_CAPACITY.json",0o400)
    need = event.need
    need(cap["sha256"]=="7c106882ea39d756afe6fa5beab8c8a87041b7b9dc8ce4a6e878f7c172c9d7df" and handoff["capacity"]==cap,
         "different diagnostic capacity")
    row=handoff["epochs"]["172"]
    old=qa.read(row["previous"],0o400)
    need(row["predecessor_controller"]==old["controller"] and row["provider"]==capacity["epochs"]["172"]["executable"],
         "crossed 172 controller registration")
    bindings={"run-committed.sh":row["launcher"],"publication-fit":row["provider"]}
    publication.bound_fit(P,bindings)
    for program,authority in [(P.launch,row["controller"]),(P.fit,capacity["epochs"]["172"]["seal"])]:
        seal=qa.read(authority,0o444)
        need(seal["destination"]==str(program.parent) and any(m["name"]==program.name and m["sha256"]==bindings[program.name]["sha256"] for m in seal["members"]),
             "different sealed diagnostic price or controller")
    return bindings,ref,cap


def migrate(work, result):
    root=work/"prior-attempt";state=root/"event-state"
    state.mkdir(mode=0o700,parents=True)
    original=result["original_terminal"]
    proof=[row["proof"] for row in result["projected_groups"] if row["proof"]]
    earlier,latest=proof[:2]
    terminal=lambda:{"terminal":original}
    authority=SimpleNamespace(inspect=terminal,retire=terminal,FIELD=P.authority.FIELD,T=P.authority.T)
    profile=P._replace(delivery=root,authority=authority)
    prior=full172_event.profile()
    previous_manifest=prior.delivery/"event-tools-current/programs.json"
    previous, verified=event.document(previous_manifest,0o444)
    old_fit=publication.bound_fit(prior,previous)
    old_package=root/"event-tools-current"
    old_package.mkdir(mode=0o700)
    old_programs=old_package/"programs.json";old_programs.write_bytes(previous_manifest.read_bytes());old_programs.chmod(0o444)
    current=root/PACKAGE;current.mkdir(mode=0o700)
    manifest=current/"programs.json";manifest.write_text(json.dumps(result["programs"]));manifest.chmod(0o444)
    old=dict(recovery_schema=recovery.VERSION,boot=recovery.boot(),prior=None,terminal=original,**earlier,unit=P.unit,
             controller=str(prior.launch),provider_sha256=old_fit,ssh_socket=str(root/"absent"),observed_unix_seconds=int(time.time()))
    event.once(state/"INTENT.json",old);_,intent=event.document(state/"INTENT.json",0o400)
    denied=recovery.launch(prior,old,root/"absent")
    assert denied["pre_manager_refusal"]
    event.once(recovery.path_for(state,0,"launcher"),dict(attempt=intent,result=denied))
    calls=[]
    def launch(pr, attempt, _):
        assert pr==profile and attempt["fleet"]==latest["fleet"] and attempt["controller"]==str(P.launch)
        qa.fixture_admission(root,original,attempt,result["programs"],"d"*32)
        calls.append(attempt)
        return dict(returncode=0,pre_manager_refusal=False)
    with patch.object(route,"profile",return_value=profile),patch.object(publication,"HERE",current), \
         patch.object(event,"accepted",return_value=latest),patch.object(event,"agents",return_value=root/"absent"), \
         patch.object(recovery,"launch",launch):
        records=[]
        for _ in range(2):
            output=io.StringIO()
            with redirect_stdout(output):route.main()
            records.append(json.loads(output.getvalue()))
    submission,sr=event.document(state/"SUBMISSION.json",0o400)
    _,preserved=event.document(state/"INTENT.json",0o400)
    retry=event.document(recovery.path_for(state,0,"retryable"),0o400)[0]
    assert intent==preserved and retry["reason"]=="pre-manager-refusal" and len(calls)==1 and records[0]==records[1]
    assert submission["fleet"]==latest["fleet"] and submission["admission"]==records[0]["admission"]
    return dict(prior_manifest=verified,prior_intent=preserved,prior_manager_refusal=denied,submission=sr,launch_count=len(calls))


if __name__=="__main__":
    assert __debug__ and sys.flags.isolated and os.geteuid()==0 and len(sys.argv)==2
    with patch.object(qa,"P",P),patch.object(qa,"programs",programs):
        if sys.argv[1]=="namespace":
            result=qa.namespace(PACKAGE)
        else:
            directory=Path(sys.argv[1])
            result=qa.qualify(directory,publication.focused169_reader)
            result["v12_prior_to_v13"]=migrate(directory,result)
        print(json.dumps(result,sort_keys=True))
