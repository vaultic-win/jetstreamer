"""Generate a no-clobber epoch 167 source/assembly plan from the real stage inputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile

ROOT = Path("/var/lib/jetstreamer/horizon_runtime_data")
STATE = ROOT / "epoch167-assembly-20261127-v1"
OUTPUT = "/home/sol/.jetstreamer-private/epoch167-private-assembly-20261127-v1/output"
PREFIX = ROOT / "epoch167-retained-prefix-selection-20261127-v1/RESULT.stdout"
TAIL = Path("/home/sol/.jetstreamer-private/epoch167-standard-lane-20261109-v1/"
            "checkpoint-inputs-20261127-v1/tail-72509256-72582854-v1/output/"
            "epoch-167-checkpoint-tail-private.jet.segment.json")

def reference(path, uid):
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError(f"indirect evidence path {path}")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as file:
        before = os.fstat(file.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != uid or before.st_nlink != 1
                or before.st_mode & 0o022 or not 0 < before.st_size < 2 << 20):
            raise ValueError(f"unexpected evidence custody or size {path}")
        raw = file.read((2 << 20) + 1)
        after = path.stat()
    if ((before.st_dev, before.st_ino, before.st_mtime_ns, before.st_ctime_ns, before.st_size)
            != (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns, len(raw))):
        raise ValueError(f"evidence changed {path}")
    return {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest()}, json.loads(raw)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=("qualify", "assemble"))
    parser.add_argument("admission", type=Path)
    parser.add_argument("--qualification", type=Path)
    args = parser.parse_args()
    if (args.stage == "assemble") != (args.qualification is not None):
        parser.error("supply --qualification exactly for assembly")
    fit_ref, fit = reference(args.admission, 0)
    plan = {
        "schema": "horizon-167-checkpoint-assembly-plan-v1",
        "epoch": 167, "output_directory": OUTPUT, "publication_authorized": False,
        "minimum_home_free_bytes": fit["minimum_home_free_bytes"], "admission": fit_ref,
        "prefix_result": reference(PREFIX, 0)[0], "tail_manifest": reference(TAIL, 1001)[0],
        "tool_seal": reference(STATE / "tools/deployment-seal-receipt.json", 0)[0],
    }
    if args.qualification:
        plan["qualification"] = reference(args.qualification, 0)[0]
    raw = (json.dumps(plan, indent=2, sort_keys=True) + "\n").encode()
    sha = hashlib.sha256(raw).hexdigest()
    where = STATE / f"{args.stage}-{sha}.json"
    with tempfile.NamedTemporaryFile(dir=STATE, prefix=".pending-plan-") as temp:
        temp.write(raw)
        temp.flush()
        os.fchmod(temp.fileno(), 0o400)
        os.fsync(temp.fileno())
        try:
            os.link(temp.name, where)
        except FileExistsError:
            if where.read_bytes() != raw:
                raise
    directory = os.open(STATE, os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    print(json.dumps({"path": str(where), "sha256": sha}))

if __name__ == "__main__":
    main()
