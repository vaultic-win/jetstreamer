"""Exercise the controller's immutable admission through the native singleton fixture."""
import hashlib
import json
import os
from pathlib import Path
import sys

fixture, run = map(Path, sys.argv[1:3])
sys.path.insert(0, str(fixture))
import receiver

authority = fixture / "authority"
live_bytes = (authority / "LIVE.json").read_bytes()
live = json.loads(live_bytes)
epoch = live["epoch"]
source = Path(live["output"]["path"])
lock = Path(live["private_batch_receipts"]["path"]).parents[2] / f"locks/epoch-{epoch}.lock"
native = receiver.ROOT.parent / "epoch166-receiver-20261121-v1/receiver-v1/native"
consumer = Path(os.environ["HORIZON_166_QA_CONSUMER"])
def raw_sha(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()

os.environ.update(FIXTURE_AUTHORITY=str(authority), FIXTURE_LIVE_SHA=hashlib.sha256(live_bytes).hexdigest(),
                  FIXTURE_LOCK=json.dumps(receiver.inode(lock.stat())), FIXTURE_PUBLICATION=str(run))
manager = live["native"]["manager"]
producer = receiver.Producer(epoch, manager["Id"], manager["InvocationID"])
handoff = receiver.receive(authority, os.environ["FIXTURE_LIVE_SHA"], receiver.inode(lock.stat()),
                           source.parent / "watched", native, raw_sha(native), consumer, raw_sha(consumer),
                           ["prepare", sys.argv[3]], producer)
plan = json.loads((run / "current-reader-plan.json").read_bytes())
assert handoff["epoch"] == epoch and handoff["directory"] == str(source)
assert plan["maximum_archive_bytes"] == (source / f"epoch-{epoch}.jet").stat().st_size
assert plan["epoch_expectations"].keys() == {str(epoch)}
assert len(list((run / "receipts").iterdir())) == 0
