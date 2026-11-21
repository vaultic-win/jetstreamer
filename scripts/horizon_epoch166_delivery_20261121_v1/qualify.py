#!/usr/bin/python3 -I
"""Run as root with the two compiled binaries in a private qualification interval."""
import contextlib
import copy
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

here = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("receiver", here / "receiver.py")
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)
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

live = json.loads((r.ROOT/"LIVE.json").read_bytes())
real_fingerprint = live["manifest_fingerprint"].split(":")[1]
with generator.open("rb") as gen:
    gen_path = f"/proc/self/fd/{gen.fileno()}"
    actual = json.loads(subprocess.check_output([gen_path, "fixture", str(fixture), real_fingerprint,
             decoded_hash(live["bootstrap"]["accounts_hash"]), decoded_hash(live["checkpoint"]["accounts_hash"]),
             "0297738fbe936f2a420f581164a059a3212707b53c02218279601c14501b7723"],
             **who, pass_fds=(gen.fileno(),)))
batch = Path(actual["path"])
out = fixture/"output"
archive = out/"epoch-166.jet"
sidecar = out/"epoch-166.jet.sha256"
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
put(live_path, live, 0o600)
live_hash = r.sha(live_path.read_bytes())
terminal = {"schema":"terminal166-success-v1","epoch":166,"live":{"path":str(live_path),"sha256":live_hash},
    "source_admission":live["admission"],"terminal_166_disposition":"node-published-local-cohort",
    "producer_invocation_id":r.IID, "producer_unit":r.UNIT,
    "manager_terminal":{"_PID":"1","_BOOT_ID":live["boot_id"].replace("-",""),"UNIT":r.UNIT,
    "INVOCATION_ID":r.IID,"MESSAGE_ID":"7ad2d189f7e94e70a38c781354912448"},
    "local_archive":{**d(archive),"size":archive.stat().st_size,"sha256":actual["sha256"]},
    "transaction_id":actual["transaction_id"],"committed_receipt":{"path":str(batch),"sha256":r.sha(batch.read_bytes())},
    "archive_publication_authorized":False,"new_producer_authorized":False,"canonical_r2_verified":False}
term_path=authority/"TERMINAL_SUCCESS.json"
put(term_path,terminal,0o400)
lock=batch.parents[3]/"locks/epoch-166.lock"
probe=here/"probe.py"
result=work/"consumer.json"
native_sha=r.sha(native.read_bytes()); probe_sha=r.sha(probe.read_bytes())
def run():
    return r.receive(authority,live_hash,r.inode(lock.stat()),watched,native,native_sha,probe,probe_sha,[str(result)])
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
if len(sys.argv) > 5:
    import runpy
    runpy.run_path(str(here / "qualify_publisher.py"))["qualify"](
        r, Path(sys.argv[5]), work, authority, live_hash, terminal, out, lock,
        watched, native, native_sha)
with contextlib.ExitStack() as stack:
    nf=r.inherited_program(stack,native,native_sha)
    deny=subprocess.run([f"/proc/self/fd/{nf}","admit","166",str(batch),"ff"*32,str(watched)],
                       **who,pass_fds=(nf,),capture_output=True)
    assert deny.returncode and b"fingerprint" in deny.stderr,deny.stderr
    negatives["wrong-native-fingerprint"]=deny.stderr.decode().strip()
sidecar.rename(out/"held-sidecar")
denied("partial-pair",run,"epoch-166.jet.sha256")
(out/"held-sidecar").rename(sidecar)
os.chown(sidecar,0,0)
denied("wrong-file-owner",run,"wrong source owner")
no_probe()
try:
    r.watcher()
    with contextlib.ExitStack() as stack:
        r.authority(stack,r.ROOT,r.LIVE_SHA)
except FileNotFoundError as e:
    assert Path(e.filename)==r.ROOT/"TERMINAL_SUCCESS.json"
    live_result="awaiting-original-terminal"
else:
    live_result="original-terminal-present-no-execution"
print(json.dumps({"native_receipt":actual,"fixture_directory":str(fixture),
    "fixture_scope":"one archive-writer slot and genuine native cohort commit; synthetic manager envelope",
    "source":success,"consumer":observed,"repeat_identical":True,"denials":negatives,
    "legacy_watcher_directory":str(r.LEGACY),"live":live_result,"canonical_writes":0},sort_keys=True))
