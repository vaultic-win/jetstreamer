"""Preserve the second-hour guard floor without charging its remaining tree twice."""

import json
from pathlib import Path
import sys

from derive143_bootstrap_retry import change, read_package
from derive143_shared_price_v20 import NEW as OLD
from derive143_v53 import member_plan


NEW = OLD.with_name("issued-price-v21")
SEAL = "58576edf27fc70c60a571e55586f7a597103b213db35931e12a3bfe326aae8d4"


def derive(stage, revision):
    files = read_package(OLD, SEAL)
    for name, count in (("capacity.py", 1), ("continuation_price.py", 1), ("successor_price.py", 3)):
        raw, mode = files[name]
        source = raw.decode()
        if source.count(str(OLD)) != count:
            raise ValueError("unexpected V20 self references for " + name)
        files[name] = (source.replace(str(OLD), str(NEW)).encode(), mode)

    raw, mode = files["continuation_price.py"]
    source = change(raw.decode(), '        hourly_floor = replacement["floor"]',
                    '        hourly_floor = 0  # The complete quote checks the already-installed candidate floor separately.')
    files["continuation_price.py"] = (source.encode(), mode)

    raw, mode = files["capacity.py"]
    source = change(raw.decode(), "    return merged\n", """    replacement = base["native"]["raw"]["replacement143"]
    if replacement:
        # The candidate's floor was calculated from the complete roster at
        # prestart. Validate it against current free space independently of the
        # current whole-roster commitment. Feeding it into the earlier sum adds
        # the same candidate and serial reservations again.
        installed = replacement["floor"]
        available = merged["available_home"]
        merged["epoch143_installed_guard_floor"] = installed
        merged["fits"] = merged["fits"] and available > installed
        merged["home_margin"] = min(merged["home_margin"], available - installed)
    return merged
""")
    files["capacity.py"] = (source.encode(), mode)
    metadata = json.loads(files["SOURCE.json"][0])
    metadata.update(revision=revision, prior_shared_price=dict(
        path=str(OLD / "deployment-seal-receipt.json"), sha256=SEAL))
    files["SOURCE.json"] = ((json.dumps(metadata, indent=2) + "\n").encode(), 0o444)
    return member_plan(files, stage, NEW)


if __name__ == "__main__":
    print(json.dumps(derive(Path(sys.argv[1]), sys.argv[2]), indent=2))
