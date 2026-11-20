"""Gate the fixed 141 retirement on live custody, verified recovery and present ownership."""
import hashlib
import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

BASE = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch172-full-replay-20261120-v1")
STATE = Path("/var/lib/jetstreamer/horizon_runtime_data/held141-collection-retirement-20261120-v1/state")
STREAM = BASE / "held141-stream-verifier-v1/evidence"
READER = BASE / "held141-restored-native-v1"
DERIVATIVE = Path("/usr/local/lib/jetstreamer/horizon-epoch141-original-input-20261023-v1")
S3_BUCKET = "solana-archive-with-accounts-data"
BODY_HASH = "7af478aec31809cebdeae761d44c19bb90bf06e15d2430813b3b0fe691e6a70b"
KEY = "node_02/objects/" + BODY_HASH + ".blob"
ETAG = '"6dce819ef64fab5759dd2b01ac936714-2831"'
BODY_BYTES = 189_943_475_031
LOGICAL = 539_418_911_425
UNIT = "horizon-held141-custody-stream-20261120-v1.service"
IID = "922889ef06ca488e939558298f1ad407"
COLLECTION = Path("/var/lib/jetstreamer-epoch141-ledger-retention-20261020-v3/results/collection.json")
COLLECTION_SHA = "569df15e8ce87beca8df0a800c85e616aaf252baeb365a7c92f35b8b39b4e937"
CUSTODY = Path("/home/sol/.jetstreamer-private/r2-holding-state-dev-samjohnson-v1/receipts/custody-435e917094c39e05a8df2ac97cbba71e8470261112dcc2be30fdf56a013c0688.json")
CUSTODY_SHA = "7578d7ce30c22e23a9da5f3e85801cde629a363857f922768e33e2a2a7cfbd0b"
QUAL_SHA = "fe59b3f3e91fd901cffdb060027f922631230ea0df90ead1ad369758d66e9c5d"
TABLE_SHA = "0a623fd77b45bc4ce501aed595e4a95fb68b34362de364a6a0bca2b293854477"
SOURCE = Path("/home/sol/.jetstreamer-private/epoch141-ledger-retention-20261020-v1/retained")
START_SHA = "f29f707dbe04b42dc47ab26f8d9dc3c211aa60ef9b1e5c7bd1b12e977ba40c77"


def require(ok, message):
    if not ok:
        raise ValueError(message)


def checked_read(path, digest=None):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as f:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_size <= 32 << 20,
                f"unexpected proof kind/size at {path}")
        data = f.read()
        after = os.fstat(fd)
        require(before.st_mtime_ns == after.st_mtime_ns and before.st_ctime_ns == after.st_ctime_ns
                and before.st_ino == path.lstat().st_ino, f"changing proof at {path}")
    actual = hashlib.sha256(data).hexdigest()
    require(digest is None or actual == digest, f"proof digest mismatch at {path}")
    return data, actual


def load(path, expected=None):
    return json.loads(checked_read(path, expected)[0])


def idrow(path):
    m = path.lstat()
    return [m.st_dev, m.st_ino, m.st_size, m.st_mtime_ns, m.st_ctime_ns,
            m.st_uid, m.st_gid, m.st_mode, m.st_nlink, m.st_blocks]


def static_facts():
    source = load(COLLECTION, COLLECTION_SHA)
    custody = load(CUSTODY, CUSTODY_SHA)
    start = load(STREAM / "START.json", START_SHA)
    require(source["retained_directory"] == str(SOURCE)
            and source["census"]["compressed_sha256"] == BODY_HASH
            and source["census"]["compressed_bytes"] == BODY_BYTES, "source binding")
    require(custody["object_key"] == KEY and custody["bucket"] == S3_BUCKET
            and custody["object_etag"] == ETAG.strip('"') and custody["remote_sha256_readback"] is True
            and custody["length"] == BODY_BYTES and custody["sha256"] == BODY_HASH, "custody binding")
    require(start["bucket"] == S3_BUCKET and start["expected_sha256"] == BODY_HASH
            and start["object_bytes"] == BODY_BYTES and start["unit_invocation"] == IID and start["object_key"] == KEY and start["etag"] == ETAG
            and start["collection_sha256"] == COLLECTION_SHA and start["custody_sha256"] == CUSTODY_SHA
            and start["home_device"] == os.stat("/home/sol").st_dev == start["evidence_device"], "stream identity")
    checked_read(STREAM.parent / "verify.py", "4e6470461b297aad3dce86e4e0e19e52d9363ed4b4951fa981260bb91377d35a")
    checked_read(STREAM.parent / "verifier", start["verifier_sha256"])
    launch = load(STREAM.parent / "qualification/QUALIFIED_LAUNCH.json", "a4e3c11292db405faeb30e4f328d7916b20d2b6ab48ae25840922a5d5fe2931c")
    require(launch["unit"] == UNIT and launch["tests_passed"] == 11 and launch["clippy_passed"] is True, "streamer qualification")
    qual = load(READER / "READER_QUALIFICATION.json", QUAL_SHA)
    for flag in ("real_ledger_readonly_reopened_at_separate_database_path",
                 "new_inode_synthetic_tar_restored_and_read_by_same_native_binary",
                 "known_full_target_derivative_reopened_in_current_rust_reader"):
        require(qual[flag] is True, flag)
    for ref in qual["verified_inputs"]:
        checked_read(Path(ref["path"]), ref["sha256"])
    proof = load(READER / "derivative/result.json")
    require(proof["slots"] == 18283 and proof["complete_original_entry_bundle_read"] is True,
            "original-entry bundle proof")
    seal = load(DERIVATIVE / "deployment-seal-receipt.json")
    expected = {r["name"]: r for r in seal["members"]}
    require(seal["destination"] == str(DERIVATIVE)
            and expected["index.json"]["sha256"] == proof["index_sha256"]
            and expected["original-entries.data"]["sha256"] == proof["data_sha256"],
            "original-entry deployment witness")
    identities = {}
    for name, inode in (("original-entries.data",100539636),("index.json",100539635)):
        path = DERIVATIVE / name
        row = idrow(path)
        require(row[0] == start["home_device"] and row[1] == inode and row[2] == expected[name]["bytes"]
                and row[5:9] == [0, 0, stat.S_IFREG | 0o444, 1]
                and row[4] < int(qual["at"] * 10**9), "original-entry data changed since full native read")
        identities[name] = row
    canonical = source["census"]["collection"]
    local = load(BASE / "held141-local-census-v2/ALL_MEMBERS.json", TABLE_SHA)
    content = {r["name"]: (r["bytes"], r["sha256"]) for r in canonical["files"]}
    require(len(content) == len(local) == len(canonical["files"]) == 6094 and
            {name: (sig[2], sha) for name, sig, sha in local} == content and
            sum(v[0] for v in content.values()) == LOGICAL, "original vs local member census")
    return canonical["files"], identities, start


def check_remote_receipt(release, members, start):
    final = load(STREAM / "COMPLETE.json", release["complete_sha256"])
    require(all(final.get(k) == v for k,v in start.items()), "remote verifier start changed")
    result = final["verifier_result"]
    require(final["delivered_compressed_bytes"] == BODY_BYTES and final["verified"] >= final["started"]
            and result["compressed_bytes"] == BODY_BYTES and result["source_sha256"] == BODY_HASH
            and result["collection_receipt_sha256"] == COLLECTION_SHA and result["files"] == 6094
            and result["verified_member_bytes"] == LOGICAL and result["restored_bytes"] == 0
            and result["staged_directory"] is None and result["remote_mutations"] is False,
            "incomplete end-to-end remote verification")
    got = load(STREAM / "VERIFIED_MEMBERS.json", final["verified_member_table_sha256"])
    require(got == members, "remote vs original full member table")
    # The successful Rust child exit precedes COMPLETE. Also bind PID 1's
    # successful unit close, including after GC of the completed transient unit.
    fields = subprocess.check_output(["systemctl","show",UNIT,"-p",
        "ActiveState,SubState,LoadState,MainPID,ControlPID,InvocationID,Result,ExecMainStatus,Job"], text=True,timeout=20)
    native = dict(line.split("=",1) for line in fields.splitlines())
    require(native["MainPID"] == native["ControlPID"] == "0" and not native["Job"]
            and native["InvocationID"] in ("", IID) and native["Result"] == "success" and native["ExecMainStatus"] == "0"
            and native["ActiveState"] in ("inactive","active") and native["SubState"] in ("dead","exited"), "custody reader still owns input")
    journal = subprocess.check_output(["journalctl","-q","--no-pager","-o","json","_PID=1",
        "UNIT="+UNIT,"INVOCATION_ID="+IID,"MESSAGE_ID=7ad2d189f7e94e70a38c781354912448"],text=True,timeout=30)
    notices=[json.loads(line) for line in journal.splitlines() if line]
    require(any(v.get("MESSAGE") == UNIT + ": Deactivated successfully." and v.get("_PID")=="1"
                and v.get("UNIT")==UNIT and v.get("INVOCATION_ID")==IID
                and v.get("MESSAGE_ID")=="7ad2d189f7e94e70a38c781354912448"
                and int(v["__REALTIME_TIMESTAMP"]) >= int(final["verified"] * 1_000_000) for v in notices),
            "missing native success for pinned custody invocation")
    return final, native


def remote_head():
    import boto3
    from botocore.config import Config
    endpoint=urlsplit(os.environ["HORIZON_S3_ENDPOINT"])
    require(endpoint.scheme=="https" and endpoint.hostname and endpoint.path.strip("/")==S3_BUCKET
            and not any((endpoint.query,endpoint.fragment,endpoint.username,endpoint.password)), "R2 origin binding")
    s3=boto3.client("s3",endpoint_url=endpoint._replace(path="").geturl(),region_name="auto",
        aws_access_key_id=os.environ["HORIZON_ACCESS_KEY_ID"],aws_secret_access_key=os.environ["HORIZON_SECRET_ACCESS_KEY"],
        config=Config(signature_version="s3v4",s3={"addressing_style":"path"},connect_timeout=15,read_timeout=30,retries={"max_attempts":2}))
    result=s3.head_object(Bucket=S3_BUCKET,Key=KEY,IfMatch=ETAG)
    require(result["ResponseMetadata"]["HTTPStatusCode"]==200 and result["ETag"]==ETAG and result["ContentLength"]==BODY_BYTES, "fresh R2 custody identity")
    return {"key":KEY,"etag":ETAG,"bytes":BODY_BYTES,"method":"authenticated conditional HEAD"}


def main():
    if sys.argv[1:] == ["--inspect"]:
        members, ids, _ = static_facts()
        print(json.dumps({"epoch":141,"members":len(members),"derivative":ids,
                          "complete_present":(STREAM/"COMPLETE.json").is_file(),"mutation":False}))
        return
    require(len(sys.argv)==3 and sys.argv[1] in ("before-capture","after-capture"), "invalid gate mode")
    phase=sys.argv[1];release=load(STATE/"ROOT_RELEASE.json",sys.argv[2])
    require(release["owner"]=="/root" and release["operation"]=="retire-local-held141-collection"
            and release["source"]==str(SOURCE) and release["member_table_sha256"]==TABLE_SHA, "owner release")
    package=Path(__file__).parent
    artifact=load(package/"artifact-proof.json",release["artifact_proof_sha256"])
    seal=load(package/"deployment-seal-receipt.json",release["deployment_seal_sha256"])
    require(artifact["source_commit"] == release["source_commit"] and artifact["source_in_account_updates"] is True
            and artifact["release_sha256"] == release["binary_sha256"] and seal["destination"] == str(package),
            "source or sealed artifact differs from release")
    members, derivative, start=static_facts()
    final,native=check_remote_receipt(release,members,start);head=remote_head()
    checker=Path(__file__).with_name("consumer_gate.py")
    checked_read(checker,release["consumer_gate_sha256"])
    arg=[sys.executable,"-IB",str(checker)]
    if phase=="after-capture":arg.append("--after-capture")
    # The census needs no cloud credentials. Do not pass them into the process
    # that parses installed operator commands and unit definitions.
    result=subprocess.run(arg,env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","LC_ALL":"C"},check=False,stdout=subprocess.PIPE, timeout=300)
    census=json.loads(result.stdout)
    clear=result.returncode==0 and census.get("clear") is True
    receipt={"phase":phase,"release_sha256":sys.argv[2],"at":time.time(),"native":native,
             "complete_sha256":release["complete_sha256"],"verified_member_table_sha256":final["verified_member_table_sha256"],
             "derivative":derivative,"custody":head,"consumer_census":census,"clear":clear}
    name=STATE/f"gate-{phase}-{time.time_ns()}.json"
    with name.open("x") as f:
        json.dump(receipt,f);f.flush();os.fsync(f.fileno())
    dfd=os.open(STATE,os.O_DIRECTORY);os.fsync(dfd);os.close(dfd)
    require(clear, f"reader census blocked: {census.get('reasons')}; details in {name}")
    print(json.dumps({"phase":phase,"receipt":str(name),"clear":True}),flush=True)


if __name__=="__main__":
    main()
