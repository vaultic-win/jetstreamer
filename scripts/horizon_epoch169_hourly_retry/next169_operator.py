"""Prepare the next private 169 interval from the matched 73,252,243 Bank and its compact producer."""
import argparse
import ast
from copy import deepcopy
import json
import os
from pathlib import Path
import runpy
import stat
import subprocess
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import adjacent_inputs as prior
from compact_adjacent_operator import published

need, bind, reference, digest, one = prior.need, prior.bind, prior.reference, prior.digest, prior.shared.exact
BASE = prior.RT/"epoch169-from-73252243-20261128-v1"
RUN = prior.PRIVATE/BASE.name
PKG = BASE/"operator-48-v1"
UNIT = "horizon-qualify-169-from-73252243-20261128-v1.service"
ALIAS = "/run/horizon-169-from-73252243-v1"
FIELD = "current_private169_from_73252243"
FIRST, LAST = 73_252_244, 73_259_077
IID = "2daf0b7662df43f883288b9a8d684c51"
OLD = prior.BASE
OLD_PKG = OLD/"operator-48-v1"
ROOTS = prior.PRIVATE/"next-170-169-bootstrap-20261128.lIpsC5N8"
STAGE = prior.PRIVATE/"epoch169-after-73252243-20261128.qD3vU8QW"
NATIVE = "e0b78fd9c7fd879c64f41d882038a8b89cf12f5f"

def pinned(path, sha):
    return dict(path=str(path),sha256=sha)

INTERFACE = pinned(OLD/"INTERFACE_48.json","f026dcb7ec477936c55ccc558cae4580254d91d4c7d0e7ba5c23a69308dc245e")
HISTORY = pinned(OLD/"split-v1/TERMINAL.json","bf33ef2742e8121dc5a8a5371fe60af05aeee2264ab02a39ee10f85225d3c440")
HELD = pinned(OLD/"split-v1/HELD_OWNER.json","982212feb73474a5a9033e9fbab6fd4722d3d0efa0d0dd21969a237dc72975ac")
GRANT = pinned(OLD/"split-v1/GRANT.json","374a5d05373ed34a6c2710d544273d948d33789e339ef2f9df865a5301573c30")
LEASE = pinned(OLD/"split-v1/LEASE.json","bfb8836a87291ce91ad967868d16848982ae1c355c534b7b7ec5df253da04158")
CUSTODY = pinned(ROOTS/"epoch-169-input/BOOTSTRAP_CUSTODY.json","2f14031b351b0d98471e65fc47c90a09b7889fcbf69aee60910d25da61da5ad6")
META = (pinned(ROOTS/"GENERATION_73252243.json","f2c30f1c76b403a49b9d49c26cb3d06d92ff065603151266bf82136394094800"),
        pinned(ROOTS/"GENERATION_73259077.json","23cc35b1706b634fca3ddad223dfa77fd5ed38a78751a842d84956bd9212427e"))
BANKS = (pinned(prior.WITNESSES[1],"9bc319b1337578813ec86a110829a122e1e850ac21d838c15d7797d44375a1da"),
         pinned(STAGE/"adjacent-banks/results/BANK_73259077.json","60682c16a9414510b0395eefc14e52f2b97cbe9537bfa47c8cb1e5ccd51b2237"))
TERMINAL_READ = pinned(STAGE/"adjacent-banks/TERMINAL_READ_COMPLETE.json","637418d8194e91107bfd2e1a851dcb35e668c578641f7e5d1adf05e5467b0872")
VALIDATION = pinned(BASE/"static-proof-v1/NATIVE_GUARD_VALIDATED.json","97cd762db46f56f29d1cb4c3c9a47033d0aca560fa97d241f71ac70c4df9fa40")
SEAL = pinned(BASE/"static-v1/deployment-seal-receipt.json","120f6aa2c4e00a07a6885d0a7bea667f6d2c8d7fe08603ed09e9225d72a3caa4")
GATE = pinned(BASE/"static-v1/hold","8fc4adf047722b4cbf5cbc15f1de05b8c62213e692e12e178287e952f8624b49")
GUARD = pinned(BASE/"static-v1/guard","6140967206f1e577292b5e802b4e4531f23db7fdb43e7fb713166d0e20f0c8da")
GENERATIONS = (1634787432461408,1634787430542781)
SIZES = (2_099_738_379,2_104_050_325)
G = 1<<30


def history():
    info=bind(INTERFACE)
    model=bind(info["scope"])
    end,held,grant,lease=map(bind,(HISTORY,HELD,GRANT,LEASE))
    package=bind(info["provider"])
    need(info["unit"]==held["producer_unit"]==prior.UNIT and info["provider"]["sha256"]=="1de56dbca41160ff7ceef9a58ca13b81599ff1812fc584ca53b11f00b5c43475"
         and package["destination"]==str(OLD_PKG) and model["last_slot"]==FIRST-1 and model["position_count"]==7025
         and end["private_checkpoint_matched"] and not end["complete_epoch"] and not end["canonical_writes"]
         and not end["resource_credit_bytes"] and end["held"]==grant["held"]==HELD and end["grant"]==GRANT
         and held["producer_invocation_id"]==grant["iid"]==IID and grant["profile"]==lease["profile"]
         and lease["profile"]["producer_memory_max"]==model["quota"]["producer_ram"]==48*G
         and model["quota"]["scratch"]==44*G and model["quota"]["guard_ram"]==G and model["quota"]["home_output"]==4*G
         and model["quota"]["home_control"]==64<<20 and end["pid1"]["MESSAGE_ID"]=="7ad2d189f7e94e70a38c781354912448",
         "foreign compact invocation, cap, grant or terminal")
    output=end["archive"]
    typed=output["typed_manifest"]
    image=Path(end["image_path"])
    s=image.lstat()
    need(end["image"]==held["mounts"]["image"]==[s.st_dev,s.st_ino,s.st_size] and s.st_size==4*G and s.st_nlink==1
         and s.st_uid==0 and not s.st_mode & 0o222 and stat.S_ISREG(s.st_mode) and image.resolve()==image
         and output["sha256"]==typed["archive_sha256"]=="5e3cb1f4e8c6eb768544e51a4afe0fd2b73eca744f068cd776edbc9a4500176f"
         and output["bytes"]==1_924_893_119 and output["manifest_sha256"]=="c266d07c3b9b18d6d151e20cfe5f8ecd853a1a799ed097a5285e325538d74bec"
         and typed["epoch"]==169 and (typed["output_slot_start"],typed["output_slot_count"])==(73_245_219,7025)
         and typed["runtime"]["runtime_profile"]=="solana-v1.5.6" and typed["runtime"]["runtime_revision"]=="01e4d0a1e9917701d1a148e1043b0ccf545c27f1"
         and typed["worker_executable_sha256"]==model["capped_worker"]["sha256"]
         and end["terminal_bank"]["observed_writes"]==typed["terminal"]["write_count"]
         and end["terminal_bank"]["observed_next_write_version"]==typed["terminal"]["next_write_version"],"different retained archive or manifest")
    return info,model,end,typed


def inputs():
    meta=list(map(bind,META));banks=list(map(bind,BANKS))
    check=bind(TERMINAL_READ);custody=bind(CUSTODY)
    names=[]
    for i,(slot,generation,size) in enumerate(zip((FIRST-1,LAST),GENERATIONS,SIZES)):
        m,b=meta[i],banks[i]
        bank,raw=b["bank"],b["raw_archive_readback"]
        name=f"snapshot-{slot}-{b['accounts_hash']}.tar.zst"
        need(b["source"]==m and b["snapshot_version"]=="1.2.0" and not b["new_snapshot_files"] and Path(m["name"]).name==name
             and b["slot"]==bank["slot"]==slot and bank["epoch"]==169 and bank["slot_complete"] and bank["max_tick_height"]==bank["tick_height"]
             and m["bucket"]=="mainnet-beta-ledger-us-ny5" and m["size"]==raw["bytes"]==size and int(m["generation"])==generation
             and m["storage_url"]==f"gs://{m['bucket']}/{m['name']}#{generation}"
             and all(m[k]==raw[k] for k in ("md5_hash","crc32c_hash")), "different generation, complete Bank or archive")
        names.append(name)
    path=Path(custody["destination"]);f=custody["file"];s=path.lstat()
    need(path==ROOTS/"epoch-169-input"/names[0] and path.resolve()==path and s.st_nlink==1 and stat.S_ISREG(s.st_mode)
         and [f[k] for k in ("device","inode","size","mtime_ns","uid","mode")]==[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_uid,stat.S_IMODE(s.st_mode)]
         and f["uid"]==1001 and f["mode"]==0o600 and f["size"]==SIZES[0] and custody["snapshot_slot"]==FIRST-1
         and custody["versioned_uri"]==meta[0]["storage_url"]==custody["remote_object"]["versioned_uri"] and custody["generation"]==GENERATIONS[0]
         and f["sha256"]==banks[0]["raw_archive_readback"]["sha256"] and f["md5_base64"]==meta[0]["md5_hash"]
         and f["crc32c_base64"]==meta[0]["crc32c_hash"] and check["witness"]==BANKS[1] and check["exit"]==0
         and check["source"]==meta[1] and check["raw_archive_readback"]==banks[1]["raw_archive_readback"]
         and check["pid1"]["INVOCATION_ID"]==banks[1]["invocation_id"],"different bootstrap inode or remote terminal read")
    return path,names,meta,banks


def build_scope(revision, save):
    info,old,end,typed=history()
    snap,names,meta,banks=inputs()
    bank=typed["terminal"]; raw=banks[0]["bank"]
    need(bank["accounts_hash"]==banks[0]["accounts_hash"] and all(bank[k]==raw[k] for k in prior.BANK_FIELDS)
         and end["terminal_bank"]["source"]==BANKS[0]["path"],"predecessor terminal differs from restored Bank")
    seal=bind(SEAL);proof=bind(VALIDATION)
    need(proof["seal"]==SEAL and proof["guard"]==GUARD and proof["hold"]==GATE and not proof["production_started"]
         and seal["destination"]==str(BASE/"static-v1") and bind(reference(BASE/"static-v1/SOURCE.json"))["source_commit"]==NATIVE
         and [(c["name"],c["exit"]) for c in proof["cases"]]==[("exact",0),("foreign-unit",1),("previous-unit",1),("other-root",1),("oversize",1),("low-floor",1)]
         and all(digest(Path(r["path"]))==r["sha256"] for r in (GATE,GUARD,old["node"],old["capped_worker"])), "unqualified route binaries")
    cert=save(BASE/"checkpoints.txt",("\n".join(names)+"\n").encode())
    source=save(BASE/"SOURCE_PACKET.json",dict(schema="horizon-169-from-73252243-source-v1",first_slot=FIRST,last_slot=LAST,
        position_count=LAST-FIRST+1,source_commit=revision,previous_interface=INTERFACE,previous_terminal=HISTORY,previous_held=HELD,
        previous_grant=GRANT,previous_lease=LEASE,previous_manifest_sha256=end["archive"]["manifest_sha256"],
        checkpoint_names=cert,pinned_gcs_metadata=META,bootstrap_custody=CUSTODY,full_bank_witnesses=BANKS,
        terminal_stream_completion=TERMINAL_READ,native_guard_validation=VALIDATION,native_source=NATIVE,
        r2_mutations=False,archive_publication_authorized=False),0o400)
    profile=deepcopy(old["profile"])
    fresh=[]
    sources=old["profile"]["readonly_projections"]
    old_name=Path(bind(old["bootstrap"]["witness"])["source"]["name"]).name
    for row in sources:
        target=row["readonly_view"].replace(prior.ALIAS,ALIAS).replace(str(prior.RUN),str(RUN))
        projected=Path(target)
        if row.get("role"):
            need(projected==Path(ALIAS)/"barrier" and row["source"]==str(OLD/"barrier"),"different invocation gate")
            fresh.append(dict(source=str(BASE/"barrier"),readonly_view=target,role=row["role"]))
            continue
        path=Path(row["source"])
        if projected.name==old_name:
            path=snap;target=str(Path(ALIAS)/names[0])
        elif projected.name=="canonical-hashes.txt":
            path=Path(cert["path"])
        elif projected.name=="hold":
            path=Path(GATE["path"])
        else:
            need(prior.identity(path)==row["identity"],"changed retained ledger input "+str(path))
        fresh.append(dict(source=str(path),readonly_view=target,identity=prior.identity(path)))
    need(len(fresh)==10 and sum("/compact-indexes/" in r["readonly_view"] for r in fresh)==3
         and digest(next(Path(r["source"]) for r in fresh if r["readonly_view"].endswith("/genesis.tar.bz2")))==old["genesis_sha256"],
         "incomplete ledger projections")
    def relocate(v):
        return v.replace(prior.ALIAS,ALIAS).replace(str(prior.RUN),str(RUN)).replace(old_name,names[0])
    profile["main_argv"]=list(map(relocate,profile["main_argv"]))
    profile["actual_node_argv"]=list(map(relocate,profile["actual_node_argv"]))
    need(profile["actual_node_argv"][-1]=="--qualification-end-slot=73252243","unknown command boundary")
    profile["actual_node_argv"][-1]=f"--qualification-end-slot={LAST}"
    profile["environment"]={k:relocate(v) for k,v in profile["environment"].items()}
    profile["readonly_projections"]=fresh
    return dict(schema="horizon-169-following-compact-private-v1",unit=UNIT,source_commit=revision,native_source=NATIVE,first_slot=FIRST,last_slot=LAST,
             position_count=LAST-FIRST+1,genesis_sha256=old["genesis_sha256"],node=old["node"],capped_worker=old["capped_worker"],
             node_package=old["node_package"],first_hourly_gate=GATE,first_hourly_guard=GUARD,guard_deployment=SEAL,
             native_guard_validation=VALIDATION,previous=HISTORY,previous_held=HELD,previous_grant=GRANT,previous_lease=LEASE,previous_scope=info["scope"],
             previous_interface=INTERFACE,previous_archive_sha256=end["archive"]["sha256"],previous_manifest_sha256=end["archive"]["manifest_sha256"],
             previous_bank=bank,source_packet=source,checkpoint_names=cert,
             bootstrap=dict(verified_local_custody=CUSTODY,witness=BANKS[0],generation=GENERATIONS[0],sha256=banks[0]["raw_archive_readback"]["sha256"]),
             terminal=dict(witness=BANKS[1],bank=banks[1]["bank"],accounts_hash=banks[1]["accounts_hash"],generation=GENERATIONS[1]),
             quota=old["quota"],reduced_memory_qualification=info["reduced_memory_qualification"],profile=profile,
             canonical_publication_authorized=False,resource_credit_bytes=0)


def members(scope_hash):
    info,_,_,_=history()
    result={}
    for m in bind(info["provider"])["members"]:
        n=m["name"]
        if not n.endswith(".py"):
            continue
        p=OLD_PKG/n
        need(p.parent==OLD_PKG and digest(p)==m["sha256"],"changed predecessor operator source")
        text=p.read_text().replace("from-73245218","from-73252243")
        if n=="layout.py":
            text=one(text,info["scope"]["sha256"],scope_hash)
            text=one(text,info["guard"]["sha256"],GUARD["sha256"])
            text=one(text,'RT / "epoch169-hourly-retry-20261128-v4" / "START_INTENT.json"',f'Path({LEASE["path"]!r})')
            text=one(text,"d1837511edc09d506d6ba851d94b53ba5d5c67df6390bd0df36c8624443f35fa",LEASE["sha256"])
        elif n=="status169.py":
            text=text.replace("adjacent169_provider.json","next169_provider.json")
            text=one(text,'FIELD = "current_private169_adjacent_hourly"',f'FIELD = "{FIELD}"')
            start=text.index('    predecessor = fleet.get(');stop=text.index('    registered = [',start)
            text=text[:start]+'''    predecessor = fleet.get("current_private169_adjacent_hourly")
    model = l.scope()
    end = l.bound(model["previous"])
    held = l.bound(model["previous_held"])
    grant = l.bound(model["previous_grant"])
    l.need(predecessor and predecessor["phase"] == "terminal" and predecessor["unit"]["Id"] == held["producer_unit"]
           and predecessor["producer_invocation_id"] == held["producer_invocation_id"] == grant["iid"] == "2daf0b7662df43f883288b9a8d684c51"
           and predecessor["held_owner"] == model["previous_held"] == end["held"] == grant["held"]
           and predecessor["terminal"] == end["pid1"] and end["grant"] == model["previous_grant"]
           and end["private_checkpoint_matched"] and not end["resource_credit_bytes"] and not end["canonical_writes"],
           "missing accepted preceding epoch 169 interval")
'''+text[stop:]
        elif n=="terminal_bank.py":
            text=one(text,BANKS[0]["path"],BANKS[1]["path"])
            text=one(text,BANKS[0]["sha256"],BANKS[1]["sha256"])
            text=one(text,'TARGET = 73252243',f'TARGET = {LAST}')
        elif n=="launch.py":
            text=text.replace("ADJACENT169_ENROLLMENT","NEXT169_ENROLLMENT").replace("adjacent169_","next169_")
            text=text.replace("horizon-169-adjacent-fleet-price-v1","horizon-169-next-fleet-price-v1").replace("adjacent_169_","next_169_")
        elif n=="close.py":
            text=text.replace("169-adjacent-readback","169-next-readback").replace("(73245219,7025)","(73252244,6834)")
            text=text.replace('manifest["bootstrap"]["slot"] == 73245218','manifest["bootstrap"]["slot"] == 73252243')
            text=text.replace('manifest["terminal"]["slot"] == 73252243','manifest["terminal"]["slot"] == 73259077')
            text=text.replace('checkpoint slot=73252243','checkpoint slot=73259077')
        ast.parse(text,filename=n)
        result[n]=text.encode()
    need(set(result)=={"layout.py","close.py","terminal_bank.py","launch.py","status169.py"},"incomplete operator")
    return result


def prepare(revision):
    published(revision,[Path(__file__).resolve(),HERE/"adjacent_inputs.py",HERE/"compact_adjacent_operator.py",HERE.parent/"horizon_epoch162_split_scratch/second_interval.py"])
    repo=HERE.parents[1]
    subprocess.run(["git","-c","safe.directory="+str(repo),"-C",str(repo),"merge-base","--is-ancestor",NATIVE,"origin/account-updates"],check=True)
    need(os.geteuid()==0 and BASE.stat().st_uid==0 and not BASE.stat().st_mode & 0o077 and BASE.resolve()==BASE
         and BASE.stat().st_dev==prior.PRIVATE.stat().st_dev,"unsafe successor receipts")
    old=runpy.run_path(str(OLD_PKG/"layout.py"))
    save=old["save"]
    model=build_scope(revision,save)
    sr=save(BASE/"SCOPE_48.json",model,0o400)
    files=members(sr["sha256"])
    ns={"__name__":"fixture"}
    exec(compile(files["layout.py"],"layout.py","exec"),ns)
    need(ns["PKG"]==PKG and ns["RUN"]==RUN and ns["UNIT"]==UNIT and ns["DONOR"]==Path(LEASE["path"]) and ns["DONOR_SHA"]==LEASE["sha256"]
         and ns["sources"]()==model["profile"]["readonly_projections"] and ns["profile"](44)==old["profile"](44)==bind(GRANT)["profile"],
         "wrong compact profile or sources")
    bank={"__name__":"fixture"}
    exec(compile(files["terminal_bank.py"],"terminal_bank.py","exec"),bank)
    passed=bank["fixture"]()
    fixture=save(BASE/"NATIVE_CONTRACT_CHECK.json",dict(source=revision,scope=sr,previous=HISTORY,profile=ns["profile"](44),
        main_argv=ns["producer_argv"](44,model,model["profile"]["readonly_projections"]),terminal_validation=passed),0o400)
    stage=BASE/"operator-48-source"
    stage.mkdir(mode=0o700,exist_ok=True)
    need(stage.resolve()==stage and stage.stat().st_uid==0 and not stage.stat().st_mode & 0o077,"unsafe staging")
    targets={}
    for name,body in files.items():
        save(stage/name,body)
        targets[name]=stage/name,0o444
    origin=stage/"ORIGIN.json"
    save(origin,dict(source_commit=revision,native_source=NATIVE,scope=sr,fixture=fixture,prior_operator=bind(INTERFACE)["provider"],
        custody=CUSTODY,history=HISTORY,terminal_bank=BANKS[1],guard_deployment=SEAL))
    targets[origin.name]=origin,0o444
    seal=prior.shared.seal(targets,PKG,save,BASE)
    return save(BASE/"INTERFACE_48.json",dict(field=FIELD,unit=UNIT,first_slot=FIRST,last_slot=LAST,scope=sr,provider=seal,
        reader=reference(PKG/"status169.py"),guard=GUARD,gate=GATE,guard_validation=VALIDATION,source_packet=model["source_packet"],
        previous=HISTORY,previous_held=HELD,previous_grant=GRANT,previous_lease=LEASE,previous_interface=INTERFACE,
        bootstrap=model["bootstrap"],terminal=model["terminal"],profile=model["quota"],reduced_memory_qualification=model["reduced_memory_qualification"]),0o400)


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare",metavar="PUBLISHED_REVISION")
    args=parser.parse_args()
    if args.prepare:
        print(json.dumps(prepare(args.prepare),sort_keys=True))
    else:
        hist=history();received=inputs()
        classes=members("0"*64)
        print(json.dumps(dict(positions=LAST-FIRST+1,previous=HISTORY,inputs=received[1],operator_members=sorted(classes))))
