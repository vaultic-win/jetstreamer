"""Bind the accepted first interval to a disjoint copy of the proven 162 operator."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy
import stat
import subprocess

HERE = Path(__file__).resolve().parent
RT = Path("/var/lib/jetstreamer/horizon_runtime_data")
HOME = Path("/home/sol/.jetstreamer-private")
OLD = RT / "epoch162-first-hourly-completion-20261127-v2"
BASE = RT / "epoch162-second-replay-20261128-v1"
PKG = BASE / "issued-split-v1"
INPUT = HOME / "epoch162-second-hourly-20261128-v1"
OLD_ALIAS = "/run/horizon-162-first-hourly-completion-v2"
ALIAS = "/run/horizon-162-second-replay-v1"
GATE = BASE / "static/hold-162-second"
GATE_HASH = "1e139ba412b6c4624012ac30bf6f7e59629244f729ef5d863df19e0d3f3168b6"
GATE_REV = "f7e904bb5ae7cef7271bf31a5289e11b75e9be16"
GATE_SRC = "993cc6908f89d7970cbea3ad63e204d25146c8bdf2d66a29046db497ac322e42"
GUARD = OLD / "static/guard"
GUARD_SHA = "5be30fba437e03fc26f009247714986dfdc6670426650532b5ec166d67fc9183"
TERMINAL_SHA = "445b05009592b381506701162673494fe3d6deb3851a33adade0f4e44d6a64ad"
TERMINAL = OLD / "SPLIT162_FIRST_DERIVED_SEGMENT_VERIFIED.json"
OLD_SEAL = "ca5ac887bdb0ca18b607966df05e890dbbc0ba3f73fb1112c4717ab97dc9415e"
WITNESS = INPUT / "TERMINAL_BANK_WITNESS.json"
WITNESS_SHA = "0ea17b4d98a2c70e88da101424d2829659e1f56dfb049eea210b607e9074965c"
SEALER = Path("/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment")
SEALER_SHA = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3"
REF = "horizon_epoch162_split_scratch"
G = 1 << 30


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def digest(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def reference(p):
    return dict(path=str(p), sha256=digest(p))


def load(p, expected):
    need(digest(p) == expected, "different input " + str(p))
    return json.loads(p.read_bytes())


def bind(r):
    return load(Path(r["path"]), r["sha256"])


def exact(text, before, after):
    need(text.count(before) == 1, "unexpected template " + repr(before))
    return text.replace(before, after)


def native_scope():
    old = load(HOME / "epoch162-local-capped-20261127.6qaa2Qgr/LOCAL_OPERATOR_HANDOFF.json",
               "daceecc4a7f4f6502c43fbcf989da229d561098deb2cccf95b2067f7185d047e")
    first = load(TERMINAL, TERMINAL_SHA)
    prep = bind(first["next_bootstrap_preparation"])
    boot = bind(prep["bootstrap"]["verified_local_custody"])
    manifest = bind(first["typed_manifest"])
    history = first["validated_derived_segment"]
    snap = Path(boot["destination"])
    names = Path(prep["checkpoint_names"]["path"])
    target = load(WITNESS, WITNESS_SHA)
    need(first["next_bootstrap_identity_continuous"] and history["derived_manifest"] == manifest
         and manifest["terminal"]["slot"] == boot["snapshot_slot"] == 69991076
         and manifest["terminal"]["bank_hash"] == prep["bootstrap"]["bank_hash"]
         and manifest["terminal"]["accounts_hash"] == prep["bootstrap"]["account_hash"]
         and prep["replay_positions"] == [69991077, 69998119] and prep["position_count"] == 7043
         and target["bank"]["slot"] == 69998119 and target["accounts_hash"] == prep["target"]["accounts_hash"]
         and target["bank"]["bank_hash"] == prep["target"]["bank_hash"]
         and target["source"]["generation"] == prep["target"]["generation"]
         and digest(names) == prep["checkpoint_names"]["sha256"]
         and names.read_text().splitlines() == [snap.name,Path(target["source"]["name"]).name], "checkpoint continuity")
    original = Path(old["bootstrap"]["path"])
    def new_path(value):
        return (value.replace(str(HOME / OLD.name), str(HOME / BASE.name)).replace(OLD_ALIAS, ALIAS)
                .replace(original.name, snap.name).replace("=69991076", "=69998119").replace("hold-162-completion","hold-162-second"))
    profile=old["profile"]
    rows=[]
    for r in profile["readonly_projections"]:
        src=Path(r["source"]); view=new_path(r["readonly_view"])
        if src == original:
            st=snap.stat(); evidence=boot["file"]
            need(snap.resolve()==snap and stat.S_ISREG(st.st_mode) and st.st_nlink==1
                 and (st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns)==(evidence["device"],evidence["inode"],evidence["size"],evidence["mtime_ns"])
                 and evidence["size"]==1783799300 and evidence["sha256"]==prep["bootstrap"]["archive_sha256"], "snapshot custody")
            src=snap
        elif view.endswith("/canonical-hashes.txt"):
            src=names
        elif view.endswith("/hold-162-second"):
            rows.append(dict(source=str(GATE),readonly_view=view,sha256=GATE_HASH)); continue
        elif view.endswith("/barrier"):
            rows.append(dict(source=str(BASE/"barrier"),readonly_view=view,role="invocation-bound held producer")); continue
        else:
            rows.append(dict(r,readonly_view=view));continue
        st=src.stat()
        rows.append(dict(source=str(src),readonly_view=view,identity=[st.st_dev,st.st_ino,st.st_size,st.st_ctime_ns,st.st_mtime_ns]))
    actual=[new_path(x) for x in profile["actual_node_argv"]]
    need(actual[-1]=="--qualification-end-slot=69998119" and len(actual)==9 and str(snap.name) in actual[4], "wrong native route")
    return dict(schema="horizon-private-162-second-native-contract-v1",previous=reference(TERMINAL),
        previous_typed_manifest=first["typed_manifest"],preparation=first["next_bootstrap_preparation"],
        first_slot=69991077,last_slot=69998119,position_count=7043,bootstrap=prep["bootstrap"],terminal=prep["target"],
        node=old["node"],capped_worker=old["capped_worker"],first_hourly_gate=dict(path=str(GATE),sha256=GATE_HASH),
        first_hourly_guard=dict(path=str(GUARD),sha256=GUARD_SHA),original_donor=old.get("donor"),
        profile=dict(actual_node_argv=actual,main_argv=[ALIAS+"/hold-162-second"],
                     environment={k:new_path(v) for k,v in profile["environment"].items()},readonly_projections=rows),
        producer_ram=62*G,guard_ram=G,tmpfs_bytes=36*G,mutable_image_bytes=3*G,control_bytes=64<<20,
        producer_cpu_micros=2000000,guard_cpu_micros=1000000,
        first_segment_materialized=False,canonical_publication_authorized=False)


def adapt(name, old, scope_hash):
    text=old.replace("162-first-hourly-completion-20261127-v2","162-second-replay-20261128-v1")
    if name=="layout.py":
        text=exact(text,'HANDOFF = SUPPORT / "LOCAL_OPERATOR_HANDOFF.json"','HANDOFF = BASE / "SCOPE.json"')
        text=exact(text,'daceecc4a7f4f6502c43fbcf989da229d561098deb2cccf95b2067f7185d047e',scope_hash)
        text=exact(text,'DONOR = BASE /','DONOR = RT / "'+OLD.name+'" /')
        text=exact(text,'GATE = BASE / "static/hold-162-completion"','GATE = BASE / "static/hold-162-second"')
        text=exact(text,'GUARD = BASE / "static/guard"','GUARD = Path("'+str(GUARD)+'")')
        text=exact(text,'RuntimeMaxSec=6300','RuntimeMaxSec=14400')
        return exact(text,'HOME_IMAGE = 8 * G','HOME_IMAGE = 3 * G')
    if name=="status162.py":
        text=text.replace('"current_private162_split_completion"','"current_private162_second_hourly"').replace("split162_provider.json","second162_provider.json")
        text=exact(text,'members[f.name]["sha256"]','members["status162.py" if f == source else f.name]["sha256"]')
        anchor='    registered = [r for r in fleet["actual_active_private_diagnostics"]'
        text=exact(text,anchor,'''    first = fleet.get("current_private162_split_completion")
    l.need(first and first["phase"] == "terminal" and first["producer_invocation_id"] == "e08ac6700a714ea0bf2d08a40516fc7e"
           and first["held_owner"]["sha256"] == "f98a831d6e5d020c298679a58cc8487c57681e0f8c43d7a1791b6ae8a2e2bae6",
           "first split no longer in custody")
    l.bound(l.scope()["previous"])
'''+anchor)
        # An unpublished old row cannot already identify a newly held actor.
        # The writer may install the new actor on its next scheduled sample.
        return text
    if name=="launch.py":
        text=text.replace('"split162_provider"','"second162_provider"').replace('"split162_reader"','"second162_reader"')
        text=text.replace('"split162_provider.json"','"second162_provider.json"')
        text=exact(text,'reader = program.parent / "status162.py"','reader = program.parent / "second162_status.py"')
        text=exact(text,'    check_169(spec, q)','    l.need(q["second_162_predecessor"] == l.scope()["previous"], "different first interval custody")')
        return text
    if name=="terminal_bank.py":
        text=exact(text,'/home/sol/.jetstreamer-private/epoch162-v156-capped-shrink-20261127.v1/checkpoint-v1/TERMINAL_BANK_WITNESS.json',str(WITNESS))
        text=exact(text,'6089633fc4f78a962c89a28fd738c076e1aa8621ec81f766c22a09b2c8a3d792',WITNESS_SHA)
        return text.replace('69991076','69998119').replace('canonical_accounts_hash_from_snapshot_identity','accounts_hash')
    if name=="close.py":
        start=text.index('    check = runpy.run_path(str(HERE / "stock_prefix.py"))')
        end=text.index('    checksum = l.digest(archive)',start)
        text=text[:start]+'''    manifest_path = Path(str(archive) + ".segment.json")
    before_manifest = l.identity(manifest_path)
    l.need(stat.S_ISREG(manifest_path.lstat().st_mode) and 0 < before_manifest[2] <= (1 << 20), "invalid manifest")
    raw = manifest_path.read_bytes()
    manifest = json.loads(raw)
    l.need(l.identity(manifest_path) == before_manifest and manifest["epoch"] == 162
           and (manifest["output_slot_start"],manifest["output_slot_count"]) == (69991077,7043)
           and manifest["bootstrap"]["slot"] == 69991076 and manifest["terminal"]["slot"] == 69998119,
           "unexpected second interval")
'''+text[end:]
        text=exact(text,'first_bucket=stock["encoded_slot_stream_sha256"],\n                matching_slots=[stock["first"], stock["last"]],',
                   'typed_manifest=manifest, manifest_sha256=__import__("hashlib").sha256(raw).hexdigest(),')
        text=exact(text,'    l.need(l.identity(archive) == before,','    l.need(manifest["archive_sha256"] == checksum and l.identity(archive) == before,')
        anchor='        backing = Path(read["kernel_backing"])'
        text=exact(text,anchor,'''        typed=read["typed_manifest"]
        previous=l.bound(l.scope()["previous"])["validated_derived_segment"]["derived_manifest"]
        bank=typed["terminal"]
        l.need(typed["worker_executable_sha256"]==l.scope()["capped_worker"]["sha256"]
               and all(typed["bootstrap"][key]==previous["terminal"][key] for key in
                       ("slot","bank_hash","accounts_hash","last_blockhash","capitalization","transaction_count","tick_height","slot_complete"))
               and [str(bank["slot"]),bank["bank_hash"],bank["accounts_hash"],bank["last_blockhash"],str(bank["capitalization"]),
                    str(bank["transaction_count"]),str(bank["tick_height"]),str(bank["slot_complete"]).lower()]==witness["checkpoint"]
               and bank["write_count"]==witness["observed_writes"] and bank["next_write_version"]==witness["observed_next_write_version"],
               "second manifest differs from its predecessor or native terminal")
'''+anchor)
        return text.replace('checkpoint slot=69991076','checkpoint slot=69998119')
    raise ValueError(name)


def seal(stage_contents,dest,save):
    members=[dict(name=name,source=str(p),sha256=digest(p),mode=mode) for name,(p,mode) in stage_contents.items()]
    plan=dict(schema="jetstreamer-sealed-deployment-plan-v1",destination=str(dest),members=members)
    plan_ref=save(BASE/(dest.name+"-plan.json"),plan)
    need(digest(SEALER)==SEALER_SHA,"different deployment sealer")
    if not dest.exists():
        subprocess.run([str(SEALER),plan_ref["path"],"--plan-sha256",plan_ref["sha256"],"--self-sha256",SEALER_SHA],check=True,stdout=subprocess.DEVNULL)
    receipt=dest/"deployment-seal-receipt.json"; sealed=load(receipt,digest(receipt))
    need(sealed["destination"]==str(dest) and sealed["plan_sha256"]==plan_ref["sha256"],"different existing seal")
    return reference(receipt)


def prepare(gate,commit):
    old_op=load(OLD/"issued-split-v1/deployment-seal-receipt.json",OLD_SEAL)
    local=runpy.run_path(str(OLD/"issued-split-v1/layout.py")); save=local["save"]
    need(os.getuid()==0 and __debug__ and gate.is_file() and digest(gate)==GATE_HASH,"wrong second compiled gate")
    BASE.mkdir(exist_ok=True,mode=0o700)
    need(BASE.resolve()==BASE and BASE.stat().st_uid==0 and BASE.stat().st_mode & 0o077==0 and BASE.stat().st_dev==HOME.stat().st_dev,"unsafe destination")
    checkout=HERE.parents[1]
    git=["/usr/bin/git","-c","safe.directory="+str(checkout),"-C",str(checkout)]
    remote=subprocess.check_output([*git,"rev-parse","origin/account-updates"],text=True).strip()
    subprocess.run([*git,"merge-base","--is-ancestor",commit,remote],check=True)
    files=[HERE/"second_interval.py",HERE/"second_price.py",HERE/"second_wire.py"]
    gate_src="scripts/horizon_epoch166_bounded_reproduction/gate.rs"
    subprocess.run([*git,"merge-base","--is-ancestor",GATE_REV,commit],check=True)
    need(hashlib.sha256(subprocess.check_output([*git,"show",GATE_REV+":"+gate_src])).hexdigest()==GATE_SRC,
         "different compiled gate source")
    for p in files:
        tracked=subprocess.check_output([*git,"show",commit+":"+str(p.relative_to(checkout))])
        need(tracked==p.read_bytes(),"unpublished source "+str(p))
    stage=BASE/"second-source"
    stage.mkdir(mode=0o700,exist_ok=True)
    need(stage.resolve()==stage and stage.stat().st_uid==0 and stage.stat().st_mode & 0o077==0,"unsafe source directory")
    static=stage/"hold-162-second"
    if not static.exists(): save(static,gate.read_bytes(),0o555)
    need(digest(static)==GATE_HASH,"changed gate")
    gate_seal=seal({static.name:(static,0o555)},BASE/"static",save)
    scope=native_scope()
    custody=bind(scope["bootstrap"]["verified_local_custody"])
    need(digest(Path(custody["destination"]))==scope["bootstrap"]["archive_sha256"], "bootstrap payload recheck failed")
    scope["gate_deployment"]=gate_seal
    scope["source_commit"]=commit
    sr=save(BASE/"SCOPE.json",scope,0o400)
    dest={}
    for member in old_op["members"]:
        name=member["name"]
        if name=="stock_prefix.py": continue
        path=OLD/"issued-split-v1"/name
        need(digest(path)==member["sha256"],"changed old operator member")
        new=adapt(name,path.read_text(),sr["sha256"]);compile(new,name,"exec")
        dest[name]=stage/name
        if not dest[name].exists(): save(dest[name],new.encode(),0o444)
        need(dest[name].read_text()==new,"different prepared member "+name)
    for name in ("second_price.py","second_wire.py"):
        dest[name]=stage/name
        if not dest[name].exists(): save(dest[name],(HERE/name).read_bytes(),0o444)
        need(dest[name].read_bytes()==(HERE/name).read_bytes(),"changed route helper")
    origin=stage/"ORIGIN.json"
    observed=remote if not origin.exists() else json.loads(origin.read_bytes())["observed_remote"]
    subprocess.run([*git,"merge-base","--is-ancestor",commit,observed],check=True)
    save(origin,dict(commit=commit,observed_remote=observed,gate_commit=GATE_REV,gate_source_sha256=GATE_SRC,
                     first_terminal=reference(TERMINAL),scope=sr,
                     original_operator=reference(OLD/"issued-split-v1/deployment-seal-receipt.json"),
                     merged_inputs={str(p.relative_to(checkout)):digest(p) for p in files}))
    dest[origin.name]=origin
    op=seal({name:(p,0o444) for name,p in dest.items()},PKG,save)
    return dict(scope=sr,operator=op,reader=reference(PKG/"status162.py"),wire=reference(PKG/"second_wire.py"),capacity=reference(PKG/"second_price.py"),
                enrollment=str(BASE/"SPLIT162_ENROLLMENT.json"),producer="horizon-qualify-162-second-replay-20261128-v1.service",
                first_interval=reference(TERMINAL),root_issues_cadence=True,launch_authorized=False)


if __name__=="__main__":
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("gate",type=Path)
    ap.add_argument("commit")
    arguments=ap.parse_args()
    print(json.dumps(prepare(arguments.gate,arguments.commit),indent=2,sort_keys=True))
