"""Use the original native receiver with the preserved retry10 lock and live witness."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy
import signal
import sys

BASE = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch166-retry10-terminal-20261121-v1")
UNIT = "horizon-qualify-166-independent-recovery-20261121-v1.service"
IID = "3c220efd0d0740f59572a96447e83762"
LIVE = "d560fdc80612b6654a68c57470a26b77bd98535c30068c9008e6b70fa032165e"
LOCK = (64512, 93782040)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("native", type=Path)
    parser.add_argument("native_sha256")
    parser.add_argument("consumer", type=Path)
    parser.add_argument("consumer_sha256")
    parser.add_argument("args", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    path = Path(__file__).with_name("receiver.py")
    seal = path.parent / "deployment-seal-receipt.json"
    assert os.geteuid() == 0 and sys.flags.isolated and __debug__
    assert path.resolve(strict=True) == path and seal.resolve(strict=True) == seal
    assert all(p.stat().st_uid == 0 and not p.stat().st_mode & 0o222 for p in (path.parent, path, seal))
    proof = json.loads(seal.read_bytes())
    assert proof["destination"] == str(path.parent) and any(
        row["name"] == path.name and row["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
        for row in proof["members"])
    receiver = runpy.run_path(str(path))
    signal.signal(signal.SIGIO, signal.SIG_DFL)
    signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGIO})
    result = receiver["receive"](BASE, LIVE, LOCK, receiver["watcher"](), args.native,
                                 args.native_sha256, args.consumer, args.consumer_sha256, args.args, receiver["Producer"](166, UNIT, IID))
    print(json.dumps(result, sort_keys=True))

if __name__ == "__main__":
    main()
