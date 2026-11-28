"""Seal and qualify the cold epoch 168 receiver from committed sources and its real preparation."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import sys

RUNTIME = Path("/var/lib/jetstreamer/horizon_runtime_data")
ROOT = RUNTIME / "survivor172-cadence-20261122-v1"
RUN = RUNTIME / "epoch168-retry2-rebook-20261122-v1"
OLD = ROOT / "tools-cold170-retry13-v2"
TERMINAL = ROOT / "tools-cold170-retry13-terminal-v1"
TARGET = ROOT / "tools-cold168-retry2-v1"
OPERATOR = ROOT / "cold168-status-installer-v1"
TAG = "COLD168_RETRY2_V1_STATUS_"
GENERATION = "retry2-168-generation.json"
BASE_MODULE = ROOT / "retry13-170-switch-v2/handoff_cold167.py"
OLD_SEAL = "f1b4781788205dbc065f5b116577c2e263e523f65e19cd658c31a9ae7e86fdb4"
TERMINAL_SEAL = "f7dbd841e18a7d56ae76bcd85fd4b096a1a20ce6e2057e13536d6c3f10dd2f74"
SEALER_SHA = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3"
QUAL = ROOT / (TAG+"QUALIFIED.json")
SUITES = ("qualify.py", "qualify_cold167.py", "qualify_cold167_cadence.py",
          "qualify_cold166.py", "qualify_cold170.py", "qualify_cold170_commit.py", "qualify_cold168.py")


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def ref(path):
    return dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest())


def pinned(path, digest):
    value = ref(path)
    need(value["sha256"] == digest, "changed original " + str(path))
    return value


def enrollment():
    return dict(prepared=pinned(RUN/"PREPARED.json","dd1b2296e8cd987eccf90053b999d647cd28c09a43279493fd625c719ed0388a"),
                guard_qualification=pinned(RUNTIME/"epoch168-cold-guard-20261122-v2/GUARD_QUALIFIED.json",
                                         "bab2140873334dfbab487be91cf044a31a000cbdec525075fe1ea4a086198e2b"),
                successor_root=pinned(RUN/"SUCCESSOR_ROOT.json","ec909d6701ce7dcbee72da319bf0179ba375e1cf6e284aa29686e1dd0a3cbecc"))


SUCCESSORS = {
    3: dict(old=2, old_date='20261122', old_seal='8c06411819ee01049d5e799756b078e62fa0f6109a8afebf4deb34790d1dee5d',
            old_entry='dc0f98d1b468c2568abc63c723167e47529ec5f8f03b683421c77468184db690',
            root='a3042cdfc0bbe51408f032a1ee33e2f33d635060f77e4db260f10c18224c86d4',
            failure='a3353dfdbcf5de9320f22229134c9bdcaa70abb40aca0e85dd1ad315c4740643'),
    4: dict(old=3, old_date='20261123', old_seal='2b36ded26d4e244c166c1f3623d8f125f558b94fb1a17555b96c361d5cb3cfd2',
            old_entry='d8823404a5dcf35965fb5b519569dd8fc5ede733cea215a582aa5669d8b9eb98',
            root='713e94750dd3d430c2f54c1ccb2af7ed708dec802af5cbf210ee4963a992d0f4',
            failure='cf8ef71b5b000cc4138f726d019c59a107b9b3d45f741b0b4802a6f4f31f1d21'),
}


def successor_enrollment(attempt, prepared_sha, guard_sha):
    reg=SUCCESSORS[attempt]
    old=RUNTIME/f"epoch168-retry{reg['old']}-rebook-{reg['old_date']}-v1"
    root=pinned(RUN/'SUCCESSOR_ROOT.json',reg['root'])
    failure=pinned(old/'RELEASED_NODE_STARTUP_FAILURE_20261123.json',reg['failure'])
    need(json.loads(Path(root['path']).read_bytes())['previous_start_failure']==failure,'different 168 predecessor')
    return dict(successor_root=root, **{f"failed_retry{reg['old']}":failure},
                prepared=pinned(RUN/'PREPARED.json',prepared_sha),
                guard_qualification=pinned(RUNTIME/f'epoch168-cold-guard-20261123-v{attempt}/GUARD_QUALIFIED.json',guard_sha))


def configure_successor(attempt):
    global RUN, OLD, TERMINAL, TARGET, OPERATOR, TAG, GENERATION, OLD_SEAL, TERMINAL_SEAL, QUAL
    reg=SUCCESSORS[attempt]
    RUN=RUNTIME/f'epoch168-retry{attempt}-rebook-20261123-v1'
    OLD=TERMINAL=ROOT/f"tools-cold168-retry{reg['old']}-v1"
    OLD_SEAL=TERMINAL_SEAL=reg['old_seal']
    TARGET=ROOT/f'tools-cold168-retry{attempt}-v1'
    OPERATOR=ROOT/f'cold168-retry{attempt}-status-installer-v1'
    TAG=f'COLD168_RETRY{attempt}_V1_STATUS_'
    GENERATION=f'retry{attempt}-168-generation.json'
    QUAL=ROOT/(TAG+'QUALIFIED.json')


def git(shared, *args):
    return shared["output"]("/usr/sbin/runuser","-u","sol","--","/usr/bin/git","-C",shared["REPO"],*args)


def seal(c, shared, dest, stage, files):
    c["ensure_dir"](stage)
    for name, content in files.items():
        shared["write_new"](stage/name, content)
    need({p.name for p in stage.iterdir()} == set(files), "foreign staged package member")
    plan = ROOT/(dest.name+"-seal-plan.json")
    c["durable"](plan,dict(schema="jetstreamer-sealed-deployment-plan-v1",destination=str(dest),
        members=[dict(name=k, mode=0o444,source=str(stage/k),sha256=ref(stage/k)["sha256"]) for k in sorted(files)]))
    if not dest.exists():
        shared["output"](shared["SEALER"],plan,"--plan-sha256",ref(plan)["sha256"],"--self-sha256",SEALER_SHA)
    result=ref(dest/"deployment-seal-receipt.json")
    installed=c["checked"](result)
    need(installed["plan_sha256"]==ref(plan)["sha256"] and installed["destination"]==str(dest)
         and installed["sealer_sha256"]==SEALER_SHA
         and all((dest/k).read_bytes()==b for k,b in files.items()),"different sealed package")
    return result


def prepare(c, shared, commit, enrolled, attempt):
    generation_name = f"retry{attempt}"
    predecessor_key = f"failed_retry{attempt-1}"
    prior_programs=c["checked"](pinned(TERMINAL/"deployment-seal-receipt.json",TERMINAL_SEAL))
    programs={r["name"]:r["sha256"] for r in prior_programs["members"]}
    files={}
    for name,sha in programs.items():
        pinned(TERMINAL/name,sha)
        if attempt > 2 and re.fullmatch(r'retry[234]-168-generation\.json',name):
            continue
        if name.endswith(".json"):
            files[name]=(TERMINAL/name).read_bytes()
        else:
            src=(f"scripts/horizon_incident_replay_fit_20261121_v1/{name}" if name=="cold170_commit.py"
                 else f"{shared['SRC']}/{name}")
            files[name]=git(shared,"show",f"{commit}:{src}")
    for name in ("cold168_status.py","qualify_cold168.py"):
        files[name]=git(shared,"show",f"{commit}:{shared['SRC']}/{name}")
    files[GENERATION]=(json.dumps(enrolled,indent=2,sort_keys=True)+"\n").encode()
    package=seal(c,shared,TARGET,ROOT/f"cold168-{generation_name}-status-source-v1",files)
    generation=ref(TARGET/GENERATION)
    entry=ref(TARGET/"status_cycle.py")
    if not QUAL.exists():
        qa=ROOT/f"cold168-{generation_name}-status-qa-v1"
        c["ensure_dir"](qa)
        suites={n:json.loads(shared["output"]("/usr/bin/python3","-IB",TARGET/n,qa,timeout=150)) for n in SUITES}
        recent=suites["qualify_cold168.py"]
        terminal=suites["qualify_cold170_commit.py"]
        base=suites["qualify.py"]
        rosters={tuple(r) for r in recent["measured_populations"]}
        need(recent["prepared"]==enrolled["prepared"] and recent["guard"]==enrolled["guard_qualification"]
             and recent["successor_root"]==enrolled["successor_root"] and recent["held_and_promoted_identity_checked"]
             and recent["conditional_fixture_writes"]==1 and recent["remote_writes"]==0
             and {(167,168,170,172),(166,167,168,170,172),(167,168,172)} <= rosters
             and terminal["conditional_fixture_writes"]==2 and terminal["physical_writes"]==0
             and terminal["fixture_replay_row_removed"] and terminal["local_commit_still_pending_guard"]
             and len(set(base["conditional_epochs"]))==20 and base["bytes_written_to_R2"]==0
             and suites["qualify_cold166.py"]["counted_native_workers"]==3
             and suites["qualify_cold170.py"]["measured_lanes"]==4,"incomplete 168 receiver qualification")
        need(json.loads(shared["output"]("/usr/bin/python3","-IB",TARGET/"status_cycle.py","--check-entry"))==package,
             "unexpected receiver production entry")
        c["durable"](QUAL,dict(schema=f"horizon-168-{generation_name}-v1-status-qualified-v1",epoch=168,package=package,
            **({predecessor_key:enrolled[predecessor_key]} if attempt>2 else {}),
            entry=entry,source_commit=commit,generation=generation,guard=enrolled["guard_qualification"],
            successor_root=enrolled["successor_root"],prepared=enrolled["prepared"],suites=suites))
    q=c["read_ref"](QUAL)
    need(q["source_commit"]==commit and q["package"]==package and q["entry"]==entry
         and q["generation"]==generation and q["prepared"]==enrolled["prepared"],"foreign existing qualification")
    return ref(QUAL)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode",choices=("seal-operator","prepare","seal-handoff"))
    parser.add_argument("reference",help="published account-updates commit")
    generation=parser.add_mutually_exclusive_group()
    generation.add_argument("--retry3",dest="attempt",action="store_const",const=3)
    generation.add_argument("--retry4",dest="attempt",action="store_const",const=4)
    parser.set_defaults(attempt=2)
    parser.add_argument("--prepared-sha")
    parser.add_argument("--guard-sha")
    args=parser.parse_args()
    attempt=args.attempt
    if attempt>2:
        configure_successor(attempt)
    need(__debug__ and os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode,"use root python3 -IB")
    pinned(BASE_MODULE,"7f189ae92d13bca515099267852c1551fa43f159387eee7af5ec48839933260d")
    pinned(OLD/"deployment-seal-receipt.json",OLD_SEAL)
    pinned(OLD/"status_cycle.py",SUCCESSORS[attempt]["old_entry"] if attempt>2 else "c33a5af976a225d3fe5957e698ec70fc41df19d4932727122c44dc48a93162b1")
    shared=runpy.run_path(str(BASE_MODULE))
    c=runpy.run_path(str(OLD/"status_cycle.py"))
    commit=args.reference
    need(re.fullmatch("[a-f0-9]{40}",commit),"invalid source commit")
    git(shared,"merge-base","--is-ancestor",commit,"origin/account-updates")
    name=Path(__file__).name
    blob=git(shared,"show",f"{commit}:{shared['SRC']}/{name}")
    need(blob==Path(__file__).read_bytes(),"operator differs from published source")
    if args.mode=="seal-operator":
        return seal(c,shared,OPERATOR,ROOT/(f"cold168-retry{attempt}-status-installer-source-v1" if attempt>2 else "cold168-status-installer-source-v1"),{name:blob})
    need(Path(__file__).resolve()==OPERATOR/"stage_cold168.py","use the sealed 168 handoff operator")
    sr=c["read_ref"](OPERATOR/"deployment-seal-receipt.json")
    row,=sr["members"]
    need(sr["sealer_sha256"]==SEALER_SHA and sr["destination"]==str(OPERATOR) and row["name"]==Path(__file__).name
         and row["sha256"]==ref(Path(__file__))["sha256"],"operator seal mismatch")
    if args.mode=="seal-handoff":
        need(attempt>2,"use the original retry2 handoff deployment")
        files={n:git(shared,"show",f"{commit}:{shared['SRC']}/{n}") for n in
               ("handoff_cold168.py","qualify_handoff_cold168.py")}
        return seal(c,shared,ROOT/f"cold168-retry{attempt}-status-switch-v1",ROOT/f"cold168-retry{attempt}-status-switch-source-v1",files)
    if attempt>2:
        need(all(isinstance(h,str) and re.fullmatch("[a-f0-9]{64}",h) for h in (args.guard_sha,args.prepared_sha)),
             "supply qualified successor prepared and guard digests")
        enrolled=successor_enrollment(attempt,args.prepared_sha,args.guard_sha)
    else:
        enrolled=enrollment()
    return prepare(c,shared,commit,enrolled,attempt)


if __name__=="__main__":
    print(json.dumps(main(),sort_keys=True))
