"""Write the held-owner receipt using the active V42 package and exact PID1 properties."""

import json
from pathlib import Path
import sys

WRITER = Path("/var/lib/jetstreamer/horizon_runtime_data/survivor172-cadence-20261122-v1")
WRITER_PACKAGE = WRITER / "tools-cold168-retry5-failed166-v42-entry146-r3"
WRITER_SEAL = "7400a14e6af29e19f9880afdc9976da4528cd607d1d77da54cd48be76b47e0db"


def main(path, sha256):
    import hashlib
    seal = WRITER_PACKAGE / "deployment-seal-receipt.json"
    if hashlib.sha256(seal.read_bytes()).hexdigest() != WRITER_SEAL:
        raise ValueError("different active V42 writer package")
    local = Path(__file__).resolve().parent
    sys.path[:0] = [str(local), str(WRITER_PACKAGE)]
    import successor170_status
    import status_cycle
    from evidence import bound, checked, need

    active = bound(WRITER / "FAILED166_CADENCE_V42_ACTIVE.json")
    ready = checked(checked(active)["ready"])
    need(ready["package"] == bound(seal) and status_cycle.CURRENT == WRITER_PACKAGE / "status_cycle.py"
         and Path(successor170_status.__file__) == local / "successor170_status.py",
         "different active V42 reader")
    report = successor170_status.enroll(vars(status_cycle), dict(path=path, sha256=sha256), active)
    print(json.dumps(report))


if __name__ == "__main__":
    main(*sys.argv[1:])
