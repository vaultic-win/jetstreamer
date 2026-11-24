"""Read-only cross-check of the captured V5u semantic completion."""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys


CHECKER_PACKAGE = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch145-semantic-continuity-20261121-v1/tools-v5u-completion")
CHECKER_SEAL = "2c7c17af975df4bf06debdb137c8b41ccc1962031f61bf0a21fd590a22ae6d60"
CHECKER_SHA = "e09d00824aa581868e7697771a47840cdd947b866c709d3f5c627b3cc8f0eca4"
CAPTURED = Path("/home/sol/.jetstreamer-private/epoch145-fresh-census-successor-20261124.2y0lxs6y/capture-v5u/SEMANTIC_COMPLETION.json")
STATE = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch145-guarded-export-20261121-v1/state")
IID = "8452dba9df42437b9874b35cb44d059f"
ARCHIVE = "/home/sol/.jetstreamer-private/epoch145-prefix-extract-funded-20261121-v1/epoch-145.jet"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def qualified_file(path, sha=None, mode=None):
    require(path.is_absolute() and path.resolve(strict=True) == path, f"indirect evidence {path}")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC), "rb") as file:
        before = os.fstat(file.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
                and before.st_nlink == 1 and not stat.S_IMODE(before.st_mode) & 0o022
                and (mode is None or stat.S_IMODE(before.st_mode) == mode)
                and 0 < before.st_size <= 128 << 10, f"unsafe evidence {path}")
        body = file.read(before.st_size + 1)
        after = os.fstat(file.fileno())
        named = path.lstat()
        require(len(body) == before.st_size and os.path.samestat(before, named)
                and before.st_ctime_ns == after.st_ctime_ns == named.st_ctime_ns,
                f"changing evidence {path}")
    require(sha is None or hashlib.sha256(body).hexdigest() == sha, f"changed evidence digest {path}")
    return body


def verify_capture(captured, observed):
    require(captured == observed, "captured semantic completion differs from sealed checker")
    require(observed["schema"] == "horizon-epoch145-v5u-semantic-completion-v1"
            and observed["invocation_id"] == IID and observed["archive"] == ARCHIVE
            and observed["archive_bytes"] == 105_610_995_833
            and observed["publication_authorized"] is observed["r2_mutations"] is False
            and observed["completion"]["path"] == str(STATE / IID / "complete.json")
            and observed["extraction"]["path"] == str(STATE / IID / "extraction-complete.json"),
            "foreign paid V5u completion")
    return dict(observed, archive_publication_authorized=False)


def inspect():
    path = CHECKER_PACKAGE / "check_completion.py"
    seal = json.loads(qualified_file(CHECKER_PACKAGE / "deployment-seal-receipt.json", CHECKER_SEAL, 0o444))
    member, = [row for row in seal["members"] if row["name"] == path.name and row["mode"] == "0444"]
    require(seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            and seal["destination"] == str(CHECKER_PACKAGE)
            and seal["remote_mutations"] is False and member["sha256"] == CHECKER_SHA,
            "foreign V5u checker deployment")
    qualified_file(path, CHECKER_SHA, 0o444)
    before = qualified_file(CAPTURED)
    observed = json.loads(subprocess.check_output(["/usr/bin/python3", "-IB", path], timeout=35))
    require(qualified_file(CAPTURED) == before, "captured receipt changed during V5u recheck")
    return verify_capture(json.loads(before), observed)


if __name__ == "__main__":
    try:
        require(os.geteuid() == 0 and sys.flags.isolated and sys.dont_write_bytecode and len(sys.argv) == 1,
                "run as root with an isolated interpreter and bytecode writes disabled")
        print(json.dumps(inspect(), sort_keys=True))
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as error:
        print(f"refused: {error}", file=sys.stderr)
        raise SystemExit(1)
