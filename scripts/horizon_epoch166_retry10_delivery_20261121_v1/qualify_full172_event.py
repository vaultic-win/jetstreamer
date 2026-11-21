"""Exercise the full-172 event with the original archive and five-outcome cadence fixtures."""
import copy
import json
import os
from itertools import combinations
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import full172_event
import publication_recovery as recovery
import retry10_event as publication
import terminal_event as event

P = full172_event.profile()
CADENCE = P.delivery / "five-cadence-fixture-stage-v2/b3dca83620184a448a894e0f137cc3e0/QUALIFIED.json"
CAPACITY = event.R / "incident-replay-fit-20261121-v1/FIVE_TERMINAL_PUBLICATION_CAPACITY.json"


def read(ref, mode):
    body, seen = event.document(Path(ref["path"]), mode)
    event.need(seen == ref, "fixture reference changed")
    return body


def write(path, body):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open("x") as out:
        os.fchmod(out.fileno(), 0o600)
        json.dump(body, out, sort_keys=True)
    return event.document(path, 0o600)[1]


def programs():
    capacity, ref = event.document(CAPACITY, 0o400)
    assert ref["sha256"] == "c6188c635e858d17c4d5cbf41f8985fbb0f6fabe01c9f637a879f54e087aea51"
    held, handoff = event.document(P.delivery / "HELD_PUBLICATION_QUALIFIED.json", 0o400)
    assert handoff["sha256"] == "99e74c3c8b7ce841426098a0c630539b32647eee7b2d697cb7a80c4837a1ca9e"
    bindings = {}
    for program, seal_ref in [(P.launch, held["controller"]), (P.fit, capacity["epochs"]["172"]["seal"])]:
        member = event.member(program, 0o555)[1]
        seal = read(seal_ref, 0o444)
        assert str(program.parent) == seal["destination"]
        assert any(m["name"] == program.name and m["sha256"] == member["sha256"] for m in seal["members"])
        bindings[program.name] = member
    assert capacity["epochs"]["172"]["executable"] == bindings[P.fit.name]
    assert publication.bound_fit(P, bindings) == bindings[P.fit.name]["sha256"]
    return bindings, handoff, ref


def refused(call):
    try:
        call()
    except event.Rejected as error:
        return str(error)
    raise AssertionError("accepted crossed evidence")


def absent():
    term = P.authority.T / "TERMINAL_SUCCESS.json"
    try:
        P.authority.inspect()
    except FileNotFoundError as error:
        assert Path(error.filename) == term
    else:
        raise AssertionError("original terminal already exists")
    native = subprocess.run([P.delivery/"terminal-tools/terminal172", "inspect"], capture_output=True, timeout=45)
    native.check_returncode()
    outcome = json.loads(native.stdout)
    assert outcome["epoch"] == 172 and outcome["outcome"] == "awaiting-original-node-exit"
    assert (outcome["node_alive"] or outcome["worker_alive"]) and outcome["resource_credit_bytes"] == 0
    timer = P.authority.shared["manager"](P.authority.TIMER)
    P.authority.guard.expected_timer(timer)
    before = recovery.manager(P.unit)
    assert recovery.unoccupied(before)
    return dict(terminal=str(term), native=outcome, original_guard=timer, manager=before)


def namespace(package="event-tools-current"):
    bindings, handoff, cap = programs()
    assert event.document(P.delivery/package/"programs.json",0o444)[0] == bindings
    result = absent()
    state = P.delivery/"event-state"
    assert not list(state.iterdir())
    for directory in [P.delivery, state]:
        with tempfile.TemporaryFile(dir=directory) as handle:
            handle.write(b"172 publication event"); handle.flush(); os.fsync(handle.fileno())
    assert recovery.admissions(P, {"sha256": "0"*64}) == (set(), [])
    socket = event.agents()
    unit = Path("/proc/self/cgroup").read_text().strip().split("/")[-1]
    fields = "Id,InvocationID,ProtectHome,ProtectSystem,ReadWritePaths,CPUQuotaPerSecUSec,MemoryMax,MemorySwapMax,TasksMax,NoNewPrivileges"
    show = subprocess.check_output(["systemctl","show",unit,"-p",fields],text=True,timeout=20)
    rows = dict(line.split("=",1) for line in show.splitlines())
    assert rows["InvocationID"] == os.environ["INVOCATION_ID"] and rows["ReadWritePaths"] == str(P.delivery)
    assert [rows[k] for k in ("ProtectHome","ProtectSystem","CPUQuotaPerSecUSec","MemoryMax","MemorySwapMax","TasksMax","NoNewPrivileges")] == ["read-only","strict","500ms","268435456","0","32","yes"]
    return dict(absent=result, socket=str(socket), service=rows, programs=bindings, held=handoff, capacity=cap)


def check_case(work, label, base, report, group, archive, clock_terminal):
    runtime, reports = work/label/"runtime", work/label/"reports"
    directory = runtime / Path(base["observer"]["path"]).stem.removeprefix("sample-")
    case = reports / directory.name.replace("root","cycle",1).replace("-live166167170-","-live166167170-19-")
    ref = write(event.completion_report_dir(case,group)/"COMPLETED.json",report)
    fields = {}
    for epoch in group:
        key = event.report_labels()[epoch]+"_local_commit"
        fields[key] = read(report["receipts"][str(epoch)],0o600)[key]
    keys = ("owner", "observer", "recorded_unix_seconds", "sampled_at_utc",
            "all_active_status_reports_authenticated_readback", "authenticated_status_count")
    fleet = {k: base[k] for k in keys}
    fleet.update(fields, effective_status_receipts=report["receipts"], authenticated_status_audit=ref)
    fleet_ref = write(directory/event.FLEET_NAME,fleet)
    changes = event.Changes()
    try:
        def check(fleet, report, terminal):
            return publication.status_evidence(fleet,report,terminal,archive,P)
        def accept(term, head):
            return event.accepted(runtime,reports,term,changes,head,base["recorded_unix_seconds"],P.authority.FIELD,check)
        proof = accept(clock_terminal,lambda r:r)
        if 172 in group:
            assert proof == dict(fleet=fleet_ref,report=ref,status=report["receipts"]["172"])
            assert accept(clock_terminal,lambda _:None) is None
            refused(lambda: accept(dict(clock_terminal,sha256="0"*64),lambda r:r))
            refused(lambda: publication.status_evidence(fleet,report,clock_terminal,dict(archive,inode=0),P))
        else:
            assert proof is None
        return dict(group=list(group), proof=proof,report=ref)
    finally:
        changes.close()


def fixture_admission(root, original, intent, bindings, iid):
    terminal = read(original,0o400)
    a = terminal["local_archive"]
    folder = root/("run-"+iid)
    folder.mkdir()
    event.once(folder/"capacity.json",dict(terminal=original,invocation_id=iid,boot_id=recovery.boot(),
                fleet=intent["fleet"],provider=bindings[P.fit.name]))
    event.once(folder/"admission.json",dict(epoch=172,invocation_id=iid,unit=P.unit,schema="horizon-epoch172-committed-publication-admission-v1",
                operation="current-reader-sync-retain-local",publication_authorized=True,terminal_sha256=original["sha256"],
                transaction_id=terminal["transaction_id"],archive_bytes=a["size"],archive_sha256=a["sha256"],archive_inode=a["inode"],
                archive_device=a["device"],capacity=event.document(folder/"capacity.json",0o400)[1],boot_id=recovery.boot()))


def fixture_dispatch(work, original, proof, bindings):
    root = work/"dispatch"
    state = root/"event-state"
    state.mkdir(mode=0o700,parents=True)
    seen = []
    profile = P._replace(delivery=root,authority=SimpleNamespace(inspect=lambda:dict(terminal=original)))
    fit = bindings["publication-fit"]["sha256"]
    def launch(profile, intent, socket):
        assert intent["terminal"] == original and intent["fleet"] == proof["fleet"] and intent["controller"] == str(P.launch)
        seen.append(intent)
        fixture_admission(root,original,intent,bindings,"e"*32)
        return dict(returncode=0,pre_manager_refusal=False)
    class NoWait:
        def wait(self):
            raise AssertionError("unexpected wait in fixture dispatch")
    with patch.object(recovery.event,"agents",return_value=work/"unused-socket"),patch.object(recovery,"launch",launch):
        def invoke():return recovery.service(profile,state,original,fit,lambda:proof,NoWait())
        first=invoke()
        assert first==invoke() and first["disposition"]=="native-sync-admission" and len(seen)==1
    submission, sr = event.document(state/"SUBMISSION.json",0o400)
    assert submission["admission"] == first["admission"] and submission["unit"] == P.unit and submission["terminal"] == original
    return dict(launch_count=len(seen), admitted=first,submission=sr)


def qualify(work, peer_profile=publication.five_source_reader):
    bindings, held, cap = programs()
    denied = {}
    for epoch in (166,167,168,170):
        other = peer_profile(epoch)
        for name, prog in [(P.launch.name,other.launch),(P.fit.name,other.fit)]:
            crossed = dict(bindings,**{name:event.member(prog,0o555)[1]})
            denied[f"{epoch}/{name}"] = refused(lambda: publication.bound_fit(P,crossed))
    cadence, cr = event.document(CADENCE,0o600)
    assert cr["sha256"]=="a5ff0f41a934b1eb8a1b53a5f378eb0f02e39a3384de8eb07940d5f9c22ba2a8"
    original = cadence["singleton_fixtures"]["172"]
    terminal = read(original,0o400)
    assert original["sha256"]=="576b31cba182daf0f56e89fe299d7941ef77253eccb3c97365d316058443640b"
    fixture = next(c for c in cadence["fixture_status_and_fleet_passes"] if len(c["closed"])==5)
    all_report = read(fixture["report"],0o600)
    clock = read(all_report["receipts"]["172"],0o600)[P.authority.FIELD]
    clocked = read(clock,0o600)
    detached = copy.deepcopy(clocked)
    assert int(detached["manager_terminal"].pop("__REALTIME_TIMESTAMP")) > 0 and detached == terminal
    archive = terminal["local_archive"]
    base = read(cadence["base_fleet"],0o600)
    existing = read(base["authenticated_status_audit"],0o600)
    full = [check_case(work,str(i),base,read(c["report"],0o600),c["closed"],archive,clock)
            for i,c in enumerate(cadence["fixture_status_and_fleet_passes"])]
    projections = []
    for size in range(6):
        for group in combinations(sorted(event.report_labels()),size):
            if group: read(cadence["projections"][str(group)],0o444)
            # Project only the active/inactive selection. Each referenced status is the actual
            # row from the same five-completion fixture or its authenticated live baseline.
            rows = dict(existing["receipts"])
            rows.update({str(e):all_report["receipts"][str(e)] for e in group})
            report = dict(existing,receipts=rows)
            projections.append(check_case(work,"projection-"+str(len(projections)),base,report,group,archive,clock))
    positive = [c for c in projections if c["proof"]]
    assert len(full)==28 and len(positive)==16 and len(projections)==32
    original_absent = absent()
    result = recovery.launch(P,dict(fleet=positive[0]["proof"]["fleet"],provider_sha256=bindings[P.fit.name]["sha256"]),work/"unavailable-socket")
    assert result["pre_manager_refusal"] and recovery.manager(P.unit)==original_absent["manager"]
    dispatch = fixture_dispatch(work, original, positive[0]["proof"], bindings)
    return dict(held=held,capacity=cap,cadence=cr,programs=bindings,original_terminal=original,clock_terminal=clock,
                absent=original_absent,actual_launcher_preflight=result,crossed_programs=denied,
                original_cadence_cases=full,projected_groups=projections,dispatcher=dispatch,production_dispatches=0,r2_writes=0)


if __name__=="__main__":
    assert __debug__ and sys.flags.isolated and os.geteuid()==0
    if sys.argv[1:] == ["namespace"]:
        print(json.dumps(namespace(),sort_keys=True))
    else:
        assert len(sys.argv)==2
        print(json.dumps(qualify(Path(sys.argv[1])),sort_keys=True))
