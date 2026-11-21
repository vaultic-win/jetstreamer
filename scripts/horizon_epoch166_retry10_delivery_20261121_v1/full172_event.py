"""Publish the original full epoch 172 after authenticated status and fleet adoption."""
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import closure172
import retry10_event


def profile():
    root = closure172.T
    return retry10_event.Publication(
        172, root, root / "controller-tools/run-committed.sh", root / "capacity-tools/publication-fit",
        "horizon-publish-172-full-committed.service", closure172,
    )


if __name__ == "__main__":
    if len(sys.argv) != 1:
        sys.exit("usage: full172_event.py")
    retry10_event.main(profile(), recover=True)
