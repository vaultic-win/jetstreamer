"""Bind the normal v1.5.6 entry for the private interval between two NY5 snapshots."""
import os
from pathlib import Path
import stat
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "horizon_epoch162_split_scratch"))
import second_interval as shared

need, load, digest, reference, bind = shared.need, shared.load, shared.digest, shared.reference, shared.bind
RT = Path("/var/lib/jetstreamer/horizon_runtime_data")
PRIVATE = Path("/home/sol/.jetstreamer-private")
BASE = RT / "epoch169-from-73245218-20261128-v1"
RUN = PRIVATE / BASE.name
PRIOR = RT / "epoch169-hourly-retry-20261128-v4"
TEMPLATE = RT / "epoch162-third-replay-20261128-v1/operator-v1"
TEMPLATE_SEAL = "15489f1bbffde4a9ae7723220089e76d88f107a54a98ce115de96dcfd88dbc3c"
SOURCE = PRIVATE / "epoch169-hourly-following-20261128.zkF2gkYX"
PACKAGE = Path("/usr/local/lib/jetstreamer/horizon-independent169-singleton-package-20261109-v1")
UNIT = "horizon-qualify-169-from-73245218-20261128-v1.service"
ALIAS = "/run/horizon-169-from-73245218-v1"
FIELD = "current_private169_adjacent_hourly"
OLD_IID = "89f12725fa804408958878cb5cb8ca55"
PREVIOUS = PRIOR / "results/TERMINAL.json"
OLD_SHA = "9c651de5f079ef6aef3227ad95546e3faeb83aab01bf5158a3968594bc3f4c93"
OLD_HELD = dict(path=str(PRIOR/"HELD_GATE.json"),sha256="428f0e607f670eae3691499a84167dd0784ab3e481052c5269532ccf62f3c2a5")
ENTRY = BASE / "FOCUSED_ENTRY.json"
ENTRY_SHA = "a892be901bd6f3506792371be576db8b273a682b74e43ba2fd496c4780a5b331"
SLOTS = (73_245_218,73_252_243)
GENERATIONS = (1634787429412044,1634787432461408)
SIZES = (2099011600,2099738379)
BANK_SHAS = ("efc2ae722219e63dddb7a672d0f82654f92a6e1410ec39e03931a68d83e65d13",
             "9bc319b1337578813ec86a110829a122e1e850ac21d838c15d7797d44375a1da")
WITNESSES = [SOURCE/"adjacent-banks/results"/f"BANK_{slot}.json" for slot in SLOTS]
GUARD_VALIDATION = BASE/"static-proof-v1/NATIVE_GUARD_VALIDATED.json"
GUARD_SHA = "cf43a0e522cd84fe93780f7437ee1cb9a5f5139cb9e645679b7f30166c5e5fa1"
HOLD_SHA = "df0864c03e34e1baab85da94ac3d344d7cc3a8a19ba73891f8eb4d901081b60a"
SOURCE_NATIVE = "6aecfdacac92c7271eb7e530c70a323515ab5c33"
BANK_FIELDS = ("slot","bank_hash","last_blockhash","capitalization","transaction_count","tick_height","slot_complete")
G = 1 << 30
M = 1 << 20


def identity(path):
    s = path.lstat()
    need(path.resolve(strict=True) == path and stat.S_ISREG(s.st_mode) and s.st_nlink == 1,
         "unexpected file at " + str(path))
    return [s.st_dev,s.st_ino,s.st_size,s.st_ctime_ns,s.st_mtime_ns]


def validation():
    entry = load(ENTRY,ENTRY_SHA)
    history = load(PREVIOUS,OLD_SHA)
    manifest = bind(entry["predecessor_manifest"])
    audit = bind(entry["predecessor_validation"])
    archive = identity(Path(audit["archive"]))
    prior = load(PRIOR/"SCOPE.json","f74d0b1dd33abe2b03705f3c69af3a74b27784bb293f69aff1f913fecf24ddb5")
    need(entry["runtime"] == "solana-v1.5.6" and entry["revision"] == "01e4d0a1e9917701d1a148e1043b0ccf545c27f1"
         and entry["positions"] == SLOTS[1]-SLOTS[0] and (entry["first"]-1,entry["last"]) == SLOTS
         and entry["bootstrap_open_intentionally_absent"] and not entry["replay_executed"]
         and history["invocation_id"] == OLD_IID and history["unit"] == prior["producer_unit"]
         and history["grant_sha256"] == digest(PRIOR/"GRANT.json") and bind(OLD_HELD)["invocation_id"] == OLD_IID
         and history["private_span"] and history["disposition"] == "completed-private-span"
         and not history["canonical_publication_authorized"] and history["resource_credit_bytes"] == 0
         and archive == [history["archive"][k] for k in ("device","inode","size","ctime_ns","mtime_ns")]
         and archive[2] == audit["archive_bytes"] == 1893471148 and audit["epoch"] == manifest["epoch"] == 169
         and audit["validation"] == "pass" and audit["archive_sha256"] == manifest["archive_sha256"]
         and audit["worker_executable_sha256"] == manifest["worker_executable_sha256"] == prior["worker"]["sha256"]
         and audit["runtime_profile"] == manifest["runtime"]["runtime_profile"] == "solana-v1.5.8"
         and audit["terminal_slot"] == manifest["output_slot_start"] + manifest["output_slot_count"]-1 == SLOTS[0]
         and manifest["terminal"] == entry["expected_restored_bank"], "different accepted preceding interval")
    names = Path(entry["checkpoint_list"]["path"])
    need(digest(names) == entry["checkpoint_list"]["sha256"] and names.read_text().splitlines() == entry["checkpoint_names"]
         and len(entry["checkpoint_names"]) == 2, "different checkpoint names")
    source = bind(entry["source"])
    banks = []
    for i,(slot,generation,size) in enumerate(zip(SLOTS,GENERATIONS,SIZES)):
        witness = load(WITNESSES[i],BANK_SHAS[i])
        metadata = source["snapshots"][i]
        observed = load(Path(metadata["evidence"]),metadata["evidence_sha256"])
        raw, bank = witness["raw_archive_readback"], witness["bank"]
        need(witness["source"] == observed and witness["slot"] == bank["slot"] == metadata["slot"] == slot
             and int(observed["generation"]) == generation and metadata["source"] == observed["storage_url"]
             and metadata["etag"] == observed["etag"] and raw["bytes"] == observed["size"] == metadata["size"] == size
             and raw["md5_hash"] == observed["md5_hash"] == metadata["md5"]
             and raw["crc32c_hash"] == observed["crc32c_hash"] == metadata["crc32c"]
             and bank["epoch"] == 169 and bank["slot_complete"] and bank["tick_height"] == bank["max_tick_height"]
             and Path(observed["name"]).name == entry["checkpoint_names"][i] == f"snapshot-{slot}-{witness['accounts_hash']}.tar.zst",
             "witness and authenticated NY5 source differ")
        banks.append(witness)
    need(all(banks[0]["bank"][k] == manifest["terminal"][k] for k in BANK_FIELDS)
         and banks[0]["accounts_hash"] == manifest["terminal"]["accounts_hash"],"adjacent bootstrap Bank differs")
    custody = bind(entry["input_custody"])
    snap = Path(custody["private_file"])
    s = snap.lstat()
    need(snap == SOURCE/"input"/entry["checkpoint_names"][0] and identity(snap)[:3] ==
         [custody["final"][k] for k in ("dev","ino","bytes")] and s.st_mtime_ns == custody["final"]["mtime"]
         and s.st_uid == custody["final"]["uid"] == 1001 and stat.S_IMODE(s.st_mode) == custody["final"]["mode"] == 0o600
         and custody["source"] == source["snapshots"][0]["source"] and int(custody["generation"]) == GENERATIONS[0]
         and custody["sha256"] == banks[0]["raw_archive_readback"]["sha256"] and custody["size"] == SIZES[0]
         and all(custody[k] == source["snapshots"][0][k] for k in ("md5","crc32c","etag")), "changed bootstrap custody")
    proof = load(GUARD_VALIDATION,"b0de1c5bb426ef457d73221baa309f8a038b3a907edc2321f6813006a3242641")
    need(proof["seal"] == reference(BASE/"static-v1/deployment-seal-receipt.json") and
         proof["seal"]["sha256"] == "617b0249e7c29548a592526f22dbc4833440e5185f092a2871a348be5329150c"
         and bind(proof["seal"])["destination"] == str(BASE/"static-v1")
         and proof["hold"] == reference(BASE/"static-v1/hold") and proof["hold"]["sha256"] == HOLD_SHA
         and proof["guard"] == reference(BASE/"static-v1/guard") and proof["guard"]["sha256"] == GUARD_SHA
         and [(v["name"],v["exit"]) for v in proof["cases"]] ==
             [("exact",0),("foreign-unit",1),("other-root",1),("oversize",1)],"different qualified guard or gate")
    return entry, prior, banks, proof, snap, names


def scope(revision):
    entry, prior, banks, proof, snap, names = validation()
    node, worker = (PACKAGE/n for n in ("jetstreamer-node","jetstreamer-historical-worker-v1-5-6"))
    refs = [reference(p) for p in (node,worker)]
    need(entry["node_package"] == reference(PACKAGE/"SHA256SUMS") and [r["sha256"] for r in refs] ==
         ["a09b8e5aa9426beaf42e6b5f2a469a5a147436bab8b7bf79f268758b60aa2e65",
          "cf5fa883df75b23de82af52dc0e90c013f8e83397b445027e510a1137decc819"], "different v1.5.6 worker or node")
    inputs = bind(prior["inputs"])
    rows = []
    for index in inputs["indexes"]:
        path = Path(index["path"])
        fid = identity(path)
        need(fid == [index[k] for k in ("device","inode","size","ctime_ns","mtime_ns")]
             and path.parent.name in ("168","169") and path.parent.parent.name == "compact-indexes",
             "retained compact index changed")
        rows.append(dict(source=str(path), readonly_view=str(RUN/"ledger/compact-indexes"/path.parent.name/path.name),identity=fid))
    need(len(rows) == 3,"wrong compact-index set")
    genesis = PRIVATE/"epoch169-focused-diagnostic-20261117-v1/v158/genesis.tar.bz2"
    need(digest(genesis) == "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945","different genesis")
    for path, dest in ((genesis,RUN/"ledger/genesis.tar.bz2"),(node,Path(ALIAS)/node.name),
                       (worker,Path(ALIAS)/worker.name),(snap,Path(ALIAS)/snap.name),
                       (names,Path(ALIAS)/"canonical-hashes.txt"),(Path(proof["hold"]["path"]),Path(ALIAS)/"hold")):
        rows.append(dict(source=str(path),readonly_view=str(dest),identity=identity(path)))
    rows.append(dict(source=str(BASE/"barrier"),readonly_view=ALIAS+"/barrier",role="invocation-bound held producer"))
    argv = [ALIAS+"/"+node.name,"169",str(RUN/"ledger"),"--verify","--snapshot-archive="+ALIAS+"/"+snap.name,
            "--epoch-hashes="+ALIAS+"/canonical-hashes.txt","--horizon-output="+str(RUN/"ledger/epoch-169.diagnostic.jet"),
            "--replay-scratch="+str(RUN/"scratch"),"--qualification-end-slot="+str(SLOTS[1])]
    env = dict(JETSTREAMER_HISTORICAL_WORKER_V1_5_6=ALIAS+"/"+worker.name,
               JETSTREAMER_PRIVATE_RUN_ROOT=str(RUN/"private"),JETSTREAMER_ALLOW_CANDIDATE_RUNTIME="1",
               JETSTREAMER_EPOCH_ISOLATION="0",JETSTREAMER_HISTORICAL_INITIALIZE_TIMEOUT_SECS="900",TMPDIR=str(RUN),
               SOLANA_RAYON_THREADS="2",RAYON_NUM_THREADS="2",TOKIO_WORKER_THREADS="2",RUST_LOG="info,solana_metrics=off")
    return dict(schema="horizon-private-169-adjacent-native-contract-v1",unit=UNIT,source_commit=revision,
                native_source=SOURCE_NATIVE,first_slot=SLOTS[0]+1,last_slot=SLOTS[1],position_count=SLOTS[1]-SLOTS[0],
                genesis_sha256=digest(genesis),node=refs[0],capped_worker=refs[1],node_package=reference(PACKAGE/"deployment-seal-receipt.json"),
                first_hourly_gate=proof["hold"],first_hourly_guard=proof["guard"],guard_deployment=proof["seal"],
                native_guard_validation=reference(GUARD_VALIDATION),previous=reference(PREVIOUS),previous_held=OLD_HELD,
                previous_scope=reference(PRIOR/"SCOPE.json"),previous_manifest=entry["predecessor_manifest"],
                previous_validation=entry["predecessor_validation"],previous_bank=entry["expected_restored_bank"],
                focused_entry=reference(ENTRY),checkpoint_names=entry["checkpoint_list"],
                bootstrap=dict(verified_local_custody=entry["input_custody"],witness=reference(WITNESSES[0]),
                               generation=GENERATIONS[0],sha256=banks[0]["raw_archive_readback"]["sha256"]),
                terminal=dict(witness=reference(WITNESSES[1]),bank=banks[1]["bank"],accounts_hash=banks[1]["accounts_hash"],
                              generation=GENERATIONS[1]),quota=prior["quota"],
                profile=dict(main_argv=[ALIAS+"/hold"],actual_node_argv=argv,environment=env,readonly_projections=rows),
                canonical_publication_authorized=False,resource_credit_bytes=0)
