"""Capture the end of the original epoch 172 input stream without claiming an archive."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

ROOT = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch172-current-delivery-20261121-v1")
LIVE_SHA = "4d4e760ba2d4cb53368cfc7c616044f789f82f66934499ad91e5797f41cf6dc2"
ORIGINAL = "0e17b745938546608b0bdc52815151d0"
LAST = 74735999
WINDOW = 4 << 20
STAMP = rb"\[(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z) INFO +jetstreamer::firehose\] "
LAST_LINE = re.compile(rb"^" + STAMP + rb"processed slot 74735999\r?$", re.M)
SUCCESS = re.compile(rb"^" + STAMP + rb"[^\r\n]*firehose finished successfully\.\r?$", re.M)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def markers(raw, base):
    # Only complete lines are eligible, including at a bounded read's left edge.
    if base:
        cut = raw.index(b"\n") + 1
        raw, base = raw[cut:], base + cut
    raw = raw[:raw.rfind(b"\n") + 1]
    last = list(LAST_LINE.finditer(raw))
    success = list(SUCCESS.finditer(raw))
    require(len(last) == len(success) == 1 and last[0].end() < success[0].start()
            and last[0][1] <= success[0][1], "missing or ambiguous terminal input records")
    start, end = last[0].start(), success[0].end() + 1
    return dict(offset=base + start, length=end-start, sha256=hashlib.sha256(raw[start:end]).hexdigest(),
                last_slot_utc=last[0][1].decode(), input_drained_utc=success[0][1].decode())


def capture():
    path = ROOT/"LIVE.json"
    raw = path.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == LIVE_SHA, "different original live witness")
    live = json.loads(raw)
    native = live["native"]
    require(native["manager"]["InvocationID"] == ORIGINAL and live["epoch_bounds"][-1] == LAST
            and live["epoch"] == 172, "different input or epoch")
    source = live["producer_log"]
    log = Path(source["path"])
    require(log.resolve(strict=True) == log, "noncanonical producer log")
    with os.fdopen(os.open(log, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK),"rb") as handle:
        meta = os.fstat(handle.fileno())
        require(stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and meta.st_nlink == 1
                and (meta.st_dev,meta.st_ino) == (source["device"],source["inode"]), "different producer log")
        base = max(0, meta.st_size-WINDOW)
        result = markers(os.pread(handle.fileno(),meta.st_size-base,base),base)
        require(os.path.samestat(meta,log.stat()) and hashlib.sha256(
            os.pread(handle.fileno(),result["length"],result["offset"])).hexdigest() == result["sha256"],
            "input evidence changed during capture")
    return dict(schema="horizon-172-original-input-finished-v1", epoch=172, last_slot=LAST,
                producer_invocation_id=ORIGINAL, live=dict(path=str(path),sha256=LIVE_SHA),
                admission=live["admission"], original_worker=live["first_protected_worker"],
                log=source, records=result, archive_accepted=False, resource_credit_bytes=0)


if __name__ == "__main__":
    print(json.dumps(capture(),sort_keys=True))
