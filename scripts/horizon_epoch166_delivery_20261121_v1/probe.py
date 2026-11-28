#!/usr/bin/python3 -I
"""Local synchronous qualification consumer for the receiver descriptor contract."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sys

result, source = map(Path, sys.argv[1:])
h = json.loads(os.environ["HORIZON_SOURCE_HANDOFF"])
assert str(source) == h["directory"] and source.resolve(strict=True) == source
epoch = h["epoch"]
for name, key in [(f"epoch-{epoch}.jet", "archive_fd"), (f"epoch-{epoch}.jet.sha256", "sidecar_fd")]:
    expected = (source / name).lstat()
    observed = os.fstat(h[key])
    assert (expected.st_dev, expected.st_ino) == (observed.st_dev, observed.st_ino)
    assert fcntl.fcntl(h[key], fcntl.F_GETLEASE) == fcntl.F_RDLCK
sha = hashlib.sha256(os.pread(h["archive_fd"], 1 << 20, 0)).hexdigest()
assert sha == h["sha256"]
assert hashlib.sha256(os.pread(h["receipt_fd"], 32 << 20, 0)).hexdigest() == h["receipt_sha256"]
with open(f"/proc/self/fd/{h['epoch_lock_fd']}", "rb") as separate:
    try:
        fcntl.flock(separate, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        pass
    else:
        raise ValueError("source claim released before consumer finished")
result.write_text(json.dumps({"sha256":sha,"epoch_lock_held":True,"canonical_directory":str(source)}))
