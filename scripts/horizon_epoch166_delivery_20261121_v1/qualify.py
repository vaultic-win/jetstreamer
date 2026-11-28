#!/usr/bin/python3 -I
"""Run as root with the two compiled binaries in a private qualification interval."""
import contextlib
import copy
import fcntl
import importlib.util
import json
import os
import runpy
from pathlib import Path
import shutil
import subprocess
import sys

here = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("receiver", here / "receiver.py")
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)
retry10 = "--retry10" in sys.argv[5:]
metered168 = "--metered168" in sys.argv[5:]
peers = {"--cold167": (167, "horizon-publish-167-cold-source-index-committed.service"),
         "--cold168": (168, "horizon-publish-168-cold-retry4-committed.service"),
         "--cold170": (170, "horizon-publish-170-cold-retry13-committed.service"),
         "--source167": (167, "horizon-publish-167-source-index-committed.service"),
         "--retry170": (170, "horizon-publish-170-retry10-committed.service"),
         "--full172": (172, "horizon-publish-172-full-committed.service")}
cold = {"--cold167": r.COLD167, "--cold168": r.COLD168, "--cold170": r.COLD170}
peer = next((flag for flag in peers if flag in sys.argv[5:]), None)
if peer:
    sys.argv.remove(peer)
    number, publication_unit = peers[peer]
    live_root, original_sha, _, producer = cold[peer] if peer in cold else r.PEERS[number]
elif metered168:
    sys.argv.remove("--metered168")
    live_root, original_sha, producer = r.METERED_ROOT, r.METERED_LIVE, r.METERED
    publication_unit = "horizon-publish-168-metered-committed.service"
elif retry10:
    sys.argv.remove("--retry10")
    binding = runpy.run_path(str(here / "receive.py"))
    live_root, original_sha = binding["BASE"], binding["LIVE"]
    producer = r.Producer(166, binding["UNIT"], binding["IID"])
    publication_unit = "horizon-publish-166-retry10-committed.service"
else:
    live_root, original_sha, producer = r.ROOT, r.LIVE_SHA, r.ORIGINAL
    publication_unit = "horizon-publish-166-committed.service"
native, generator, work, fixture = map(Path, sys.argv[1:5])
fixture.mkdir(mode=0o700)
os.chown(fixture, *r.OWNER)
who = dict(user=r.OWNER[0], group=r.OWNER[1], extra_groups=())
encode58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def decoded_hash(s):
    i = 0
    for c in s:
        i = i * 58 + encode58.index(c)
    return i.to_bytes(32, "big").hex()

def put(path, value, mode):
    path.write_text(json.dumps(value))
    path.chmod(mode)

live_mode = 0o400 if peer in cold else 0o600
raw_live = (live_root/"LIVE.json").read_bytes()
assert r.sha(raw_live) == original_sha
live = json.loads(raw_live)
epoch = producer.epoch
real_fingerprint = live["manifest_fingerprint"].split(":")[1]
terminal_hash = "0297738fbe936f2a420f581164a059a3212707b53c02218279601c14501b7723"
fixture_cmd = ["fixture"]
if metered168 or peer:
    fixture_cmd = ["fixture-epoch", str(epoch)]
    witness = live["independent_boundary"]
    data = Path(witness["path"]).read_bytes()
    assert r.sha(data) == witness["sha256"]
    terminal_hash = decoded_hash(json.loads(data)["terminal_blockhash"])
with generator.open("rb") as gen:
    gen_path = f"/proc/self/fd/{gen.fileno()}"
    actual = json.loads(subprocess.check_output([gen_path, *fixture_cmd, str(fixture), real_fingerprint,
             decoded_hash(live["bootstrap"]["accounts_hash"]), decoded_hash(live["checkpoint"]["accounts_hash"]),
             terminal_hash],
             **who, pass_fds=(gen.fileno(),)))
batch = Path(actual["path"])
out = fixture/"output"
archive = out/f"epoch-{epoch}.jet"
sidecar = out/f"epoch-{epoch}.jet.sha256"
watched = fixture/"watched"
watched.mkdir(mode=0o700)
os.chown(watched,*r.OWNER)
def d(p):
    m = p.stat()
    return {"path":str(p),"device":m.st_dev,"inode":m.st_ino}
live["output"], live["private_batch_receipts"] = d(out), d(batch.parent)
authority = work/"authority"
authority.mkdir(mode=0o700)
live_path = authority/"LIVE.json"
put(live_path, live, live_mode)
live_hash = r.sha(live_path.read_bytes())
terminal = {"schema":f"terminal{epoch}-success-v1","epoch":epoch,"live":{"path":str(live_path),"sha256":live_hash},
    "source_admission":live["admission"],f"terminal_{epoch}_disposition":"node-published-local-cohort",
    "producer_invocation_id":producer.invocation_id, "producer_unit":producer.unit,
    "manager_terminal":{"_PID":"1","_BOOT_ID":live["boot_id"].replace("-",""),"UNIT":producer.unit,
    "INVOCATION_ID":producer.invocation_id,"MESSAGE_ID":"7ad2d189f7e94e70a38c781354912448"},
    "local_archive":{**d(archive),"size":archive.stat().st_size,"sha256":actual["sha256"]},
    "transaction_id":actual["transaction_id"],"committed_receipt":{"path":str(batch),"sha256":r.sha(batch.read_bytes())},
    "resource_credit_bytes":0,"reservation_ending_bytes":0,
    "archive_publication_authorized":False,"new_producer_authorized":False,"canonical_r2_verified":False}
term_path=authority/"TERMINAL_SUCCESS.json"
put(term_path,terminal,0o400)
lock=batch.parents[3]/f"locks/epoch-{epoch}.lock"
probe=here/"probe.py"
result=work/"consumer.json"
native_sha=r.sha(native.read_bytes()); probe_sha=r.sha(probe.read_bytes())
def run():
    return r.receive(authority,live_hash,r.inode(lock.stat()),watched,native,native_sha,probe,probe_sha,[str(result)],producer)
negatives={}
def denied(name, action, expected):
    try:
        action()
    except (OSError,ValueError,subprocess.SubprocessError) as e:
        if expected not in str(e):
            raise RuntimeError(f"{name}: unexpected failure {e}") from e
        negatives[name] = str(e)
    else:
        raise RuntimeError(f"{name}: unexpectedly admitted")
def no_probe():
    assert not result.exists(), "consumer executed on denied input"
# The real manager success is intentionally pending. The private manager envelope exercises
# the post-authority receiver. Only the production writer and native publisher create the pair.
term_path.rename(authority/"unavailable")
denied("missing-terminal",run,"TERMINAL_SUCCESS.json")
(authority/"unavailable").rename(term_path)
wrong=copy.deepcopy(terminal);wrong["committed_receipt"]["sha256"]="ff"*32
put(term_path,wrong,0o400);denied("wrong-receipt-digest",run,"terminal archive, sidecar or receipt changed")
wrong=copy.deepcopy(terminal);wrong["producer_invocation_id"]="ff"*16
put(term_path,wrong,0o400);denied("wrong-producer",run,"terminal authority or original producer differs")
if retry10 or metered168 or peer:
    wrong=copy.deepcopy(terminal)
    wrong.update(producer_invocation_id=r.ORIGINAL.invocation_id, producer_unit=r.ORIGINAL.unit)
    wrong["manager_terminal"].update(INVOCATION_ID=r.ORIGINAL.invocation_id,UNIT=r.ORIGINAL.unit)
    put(term_path,wrong,0o400);denied("predecessor-producer",run,"terminal authority or original producer differs")
if peer in cold:
    live_path.chmod(0o600)
    denied(f"writable-cold{epoch}-witness", run, "unsafe authority")
    live_path.chmod(live_mode)
    previous = r.METERED if epoch == 168 else r.PEERS[epoch][3]
    wrong = copy.deepcopy(terminal)
    wrong.update(producer_unit=previous.unit, producer_invocation_id=previous.invocation_id)
    wrong["manager_terminal"].update(UNIT=previous.unit, INVOCATION_ID=previous.invocation_id)
    put(term_path, wrong, 0o400)
    previous_label = {167: "old167-source-index", 168: "old168-metered", 170: "old170-retry10"}[epoch]
    denied(previous_label, run, "terminal authority or original producer differs")
if epoch == 172:
    for label, unit, iid in [
        ("old172-hourly-trace", "horizon-qualify-172-trace-hourly-20261120-v1.service", "5a691c24655a4ff489531d8d7cc50254"),
        ("old172-metered", "horizon-qualify-172-metered-hourly-20261120-g3.service", "e601435f204e427795f67e57c70b07b5"),
    ]:
        wrong = copy.deepcopy(terminal)
        wrong.update(producer_unit=unit, producer_invocation_id=iid)
        wrong["manager_terminal"].update(UNIT=unit, INVOCATION_ID=iid)
        put(term_path, wrong, 0o400)
        denied(label, run, "terminal authority or original producer differs")
if peer:
    other = r.PEERS[170 if epoch == 167 else 167][3]
    wrong = copy.deepcopy(terminal)
    wrong.update(producer_unit=other.unit, producer_invocation_id=other.invocation_id)
    wrong["manager_terminal"].update(UNIT=other.unit, INVOCATION_ID=other.invocation_id)
    put(term_path, wrong, 0o400)
    denied("other-peer", run, "terminal authority or original producer differs")
    # Rebind both hashes so that this check specifically reaches the schema gate.
    original_live_bytes = live_path.read_bytes()
    wrong_live = {**live, "schema": f"horizon-{epoch}-live-to-terminal-witness-v1"}
    put(live_path, wrong_live, live_mode)
    live_hash = r.sha(live_path.read_bytes())
    wrong = copy.deepcopy(terminal)
    wrong["live"]["sha256"] = live_hash
    put(term_path, wrong, 0o400)
    denied("old-live-schema", run, "terminal authority or original producer differs")
    live_path.write_bytes(original_live_bytes)
    live_hash = r.sha(original_live_bytes)
put(term_path,terminal,0o400)
with lock.open("rb") as held:
    fcntl.flock(held, fcntl.LOCK_EX|fcntl.LOCK_NB)
    denied("other-owner-holds-epoch",run,"temporarily unavailable")

with archive.open("rb") as h:
    assert r.sha(h.read()) == actual["sha256"]
no_probe()
success=run()
observed=json.loads(result.read_bytes())
assert observed["sha256"]==success["sha256"] and observed["epoch_lock_held"]
result.unlink()
assert run()==success and json.loads(result.read_bytes())==observed
result.unlink()
if len(sys.argv) == 7 and sys.argv[5] == "--controller-test":
    # Qualify the controller while the generated cohort still has its original inode identities.
    subprocess.run([sys.argv[6], "--include-ignored", "--nocapture"], check=True)
elif len(sys.argv) > 5:
    runpy.run_path(str(here / "qualify_publisher.py"))["qualify"](
        r, Path(sys.argv[5]), work, authority, live_hash, terminal, out, lock,
        watched, native, native_sha, producer, publication_unit)
with contextlib.ExitStack() as stack:
    nf=r.inherited_program(stack,native,native_sha)
    deny=subprocess.run([f"/proc/self/fd/{nf}","admit",str(epoch),str(batch),"ff"*32,str(watched)],
                       **who,pass_fds=(nf,),capture_output=True)
    assert deny.returncode and b"fingerprint" in deny.stderr,deny.stderr
    negatives["wrong-native-fingerprint"]=deny.stderr.decode().strip()
sidecar.rename(out/"held-sidecar")
denied("partial-pair",run,f"epoch-{epoch}.jet.sha256")
(out/"held-sidecar").rename(sidecar)
os.chown(sidecar,0,0)
denied("wrong-file-owner",run,"wrong source owner")
no_probe()
try:
    r.watcher()
    with contextlib.ExitStack() as stack:
        r.authority(stack,live_root,original_sha,producer)
except FileNotFoundError as e:
    assert Path(e.filename)==live_root/"TERMINAL_SUCCESS.json"
    live_result="awaiting-original-terminal"
else:
    live_result="original-terminal-present-no-execution"
print(json.dumps({"native_receipt":actual,"fixture_directory":str(fixture),
    "fixture_scope":"one archive-writer slot and genuine native cohort commit; synthetic manager envelope",
    "source":success,"consumer":observed,"repeat_identical":True,"denials":negatives,
    "legacy_watcher_directory":str(r.LEGACY),"live":live_result,"canonical_writes":0},sort_keys=True))
