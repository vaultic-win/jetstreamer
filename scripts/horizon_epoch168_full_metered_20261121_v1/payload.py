#!/usr/bin/python3 -I
"""Build the full epoch 168 plan from the original sealed singleton and corrected worker."""
import hashlib
import json
from pathlib import Path
import stat

RUNTIME = Path("/var/lib/jetstreamer/horizon_runtime_data")
TREE = Path("/home/sol/.jetstreamer-private/epoch168-standard-lane-20261109-v1")
RUN = TREE / "full-metered-20261121-v1"
STATE = RUNTIME / "epoch168-full-metered-20261121-v1"
INPUTS = STATE / "inputs-v1"
ORIGINAL = Path("/usr/local/lib/jetstreamer/horizon-independent168-singleton-package-20261109-v1")
FULL172 = RUNTIME / "epoch172-full-replay-20261120-v1"
TERMINAL = RUNTIME / "epoch168-terminal-trace-20261121-v1"
DIAGNOSTIC = TREE / "replacement-local1-20261110-v1/trace-local3-20261120-v1"
BOOT = TREE / "private/destination-38f108e9d00d485f8ed68d9e7caaeb0a1570f35891271acc1ddc6e75b942e5ad/work/root-cohort-168-168/run-14201-1794247152158421923/inputs/snapshot-72575704-Grdro3ninCQfmShQL6ypGv2y1gUzhPPB7xbj9M4UHJnx.tar.zst"
NODE = "jetstreamer-node"
WORKER = "jetstreamer-historical-worker-v1-5-6"
MANIFEST = "preflight-168-v4.json"
NODE_SHA = "a09b8e5aa9426beaf42e6b5f2a469a5a147436bab8b7bf79f268758b60aa2e65"
WORKER_SHA = "b0219574172b54b251b4f2feda6285ca3b6bee5f2830a0d46e69ee8ea2275541"
MANIFEST_SHA = "27b7a803c39d7cf42407e46bc9fe5033761f471f668545460a1bcbde007ee196"
FP = "sha256:f5824f170325f9def8fe257fd542c9093f298419b1f558d4c35ddd1a6ae98011"
BOOT_SHA = "f1a8902dcb00eb59266a2f688d05f7d406af1999eb78956bfd0c46056571ad04"
GENESIS_SHA = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945"
UNIT = "horizon-qualify-168-full-metered-20261121-v1.service"
GUARD = "horizon-guard-168-full-metered-20261121-v1"
ALIASED_NODE = "/run/horizon-full168-metered/jetstreamer-node"
INDEX = [
    ("167/epoch-167-bafyreienhstqouv46ysqm2r5dqeixnhmil3qem77x76q5hicq4egi3uzhi-mainnet-slot-to-cid.index",104138613,114115538,14777203),
    ("168/epoch-168-bafyreigrdukjoi2647fzy7dbzbxcqygm54vogb6pbhhjhi6lowooruvnxa-mainnet-slot-to-cid.index",104141091,114115551,15210704),
    ("168/epoch-168-bafyreigrdukjoi2647fzy7dbzbxcqygm54vogb6pbhhjhi6lowooruvnxa-mainnet-cid-to-offset-and-size.index",104146058,114115552,4362826998),
]

def require(condition, message):
    if not condition:
        raise ValueError(message)

def digest(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()

def checked(path, expected):
    raw = path.read_bytes()
    require(len(raw) <= 1 << 20 and hashlib.sha256(raw).hexdigest() == expected, f"original evidence changed: {path}")
    return json.loads(raw)

def identity(path):
    m = path.lstat()
    require(path.resolve(strict=True) == path and stat.S_ISREG(m.st_mode), f"aliased source: {path}")
    return [m.st_dev, m.st_ino, m.st_size, m.st_mtime_ns, m.st_ctime_ns]

def retained(path, ino, size):
    i = identity(path)
    require(i[:3] == [64512, ino, size], f"retained input replaced: {path}")
    return {"path":str(path), "identity":i}

def member(seal, name, expected):
    rows = [m for m in seal["members"] if m["name"] == name]
    require(len(rows) == 1 and rows[0]["sha256"] == expected, f"native member not sealed: {name}")

def plan():
    terminal = checked(TERMINAL/"TERMINAL.json","29672efbaff97d23a9a9d45a824840cb2d4cf43c6f5e8427ed3b532b41a38de2")
    comparison = checked(TERMINAL/"metering/COMPARISON.json","26167ced2ed93e809c255cf2a62a3f0357472b3b9a3a061dc5f2823bf0e62cef")
    require(terminal["invocation"] == "c081016844dd40c5a78b594bf7ede73a"
            and terminal["state"]["ExecMainStatus"] == "1"
            and comparison["candidate_worker_sha256"] == WORKER_SHA
            and comparison["target_slot"] == 72_728_191 and comparison["independent_unsaturated_inner_meter_rows_matching"] == 9
            and comparison["candidate_source"] == "f07bab4fdcaeca7efcf189aa62a518eeda3f2f3b"
            and comparison["compare_source"] == "0509f74037d06c21a02913117649afa121540d0a"
            and comparison["terminal"]["sha256"] == "29672efbaff97d23a9a9d45a824840cb2d4cf43c6f5e8427ed3b532b41a38de2", "wrong terminal or metering evidence")
    partial = terminal["partial"]
    old = retained(Path(partial["path"]), partial["inode"], partial["length"])
    original = checked(ORIGINAL/"deployment-seal-receipt.json","3df223312376f4bbab6a672e1e2c5418102058fca12aedf689b99a02f1c2dce1")
    corrected = checked(FULL172/"inputs-v1/deployment-seal-receipt.json","08dcef00e30715113fd1e4150d16582f058f6474616f4b4ef8a2254d4a2cc0ef")
    member(original,NODE,NODE_SHA); member(original,MANIFEST,MANIFEST_SHA); member(corrected,WORKER,WORKER_SHA)
    manifest = checked(ORIGINAL/MANIFEST,MANIFEST_SHA)
    [e] = manifest["manifest"]["epochs"]
    [cp] = e["post_bootstrap_root_checkpoints"]
    require(manifest["manifest_fingerprint"] == FP and manifest["manifest"]["epoch_slots"] == 432000
            and e["epoch"] == 168 and e["publication_scope"] == "requested" and e["bootstrap"]["slot"] == 72_575_704
            and e["bootstrap"]["generation"] == 1634787413893700 and e["bootstrap"]["uri"].endswith("/"+BOOT.name)
            and cp["slot"] == 73_007_829 and cp["generation"] == 1634787450103391
            and cp["accounts_hash"] == "AgJkU9ZTLnhbCHK54yWFCG4N9sxbtLPRgkCZqwpdWF9R","wrong full epoch root gates")
    worker_env = checked(FULL172/"FULL_PAYLOAD.json", "c573f9f54962f1d489ca8208414d51aafe98e9b59483b52d79f4ffa43f0d0eca")["environment"].copy()
    worker_env.update(XDG_CONFIG_HOME=str(TREE/"config"),CLOUDSDK_CONFIG=str(TREE/"config/gcloud"),
        JETSTREAMER_PRIVATE_RUN_ROOT=str(RUN/"private"),JETSTREAMER_HISTORICAL_WORKER_V1_5_6=str(RUN/"runtime"/WORKER),
        JETSTREAMER_HISTORICAL_TRACE_EPOCH168="1")
    require(all("epoch172" not in v for v in worker_env.values()) and worker_env["JETSTREAMER_VERIFY_SNAPSHOTS"]=="1"
            and worker_env["JETSTREAMER_SKIP_SNAPSHOT_VERIFY"]=="0" and worker_env["JETSTREAMER_ENFORCE_ARCHIVE_HASH"]=="1",
            "inherited environment has foreign source or verification settings")
    binds = []
    for name,source_ino,diagnostic_ino,size in INDEX:
        source = retained(TREE/"output/compact-indexes"/name,source_ino,size)
        observed = retained(DIAGNOSTIC/"ledger/compact-indexes"/name,diagnostic_ino,size)
        binds.append({"source":source,"independent_trace_copy":observed,"target":str(RUN/"ledger/compact-indexes"/name)})
    snap = identity(BOOT)
    require(snap[:3] == [64512,104141334,e["bootstrap"]["size"]],"retained snapshot changed")
    return {"schema":"horizon-full-epoch168-metered-payload-v1","epoch":168,
        "range":[72_576_000,73_007_999],"root_checkpoint":cp,"bootstrap":e["bootstrap"],
        "bootstrap_file":{"path":str(BOOT),"identity":snap,"sha256":BOOT_SHA},
        "genesis":{**retained(TREE/"output/genesis.tar.bz2",103875385,20144),"sha256":GENESIS_SHA},
        "indexes":binds,"retained_terminal_partial":old,
        "members":{NODE:[str(ORIGINAL/NODE),NODE_SHA],WORKER:[str(FULL172/"inputs-v1"/WORKER),WORKER_SHA],
                   MANIFEST:[str(ORIGINAL/MANIFEST),MANIFEST_SHA]},
        "regular_node_argv":[str(RUN/"runtime"/NODE),"168",str(RUN/"ledger"),"--verify","--root-checkpoint-cohort",
                "--cohort-manifest="+str(RUN/"runtime"/MANIFEST),"--cohort-manifest-fingerprint="+FP,
                "--snapshot-archive="+str(BOOT)],"environment":worker_env,"producer_unit":UNIT,"guard_unit":GUARD,
        "whole_root":str(TREE),"whole_root_cap":309237645312,"producer_memory_max":73014444032,
        "producer_cpu_quota_percent":900,"resource_credit_bytes":0}

if __name__=="__main__":
    print(json.dumps(plan(),indent=2,sort_keys=True))
