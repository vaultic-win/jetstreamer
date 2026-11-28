"""Preserve the paid epoch 143 reservation when its corrected unit takes ownership."""

import json
from pathlib import Path
import sys

from derive143_bootstrap_retry import change, read_package
from derive143_v53 import member_plan
from derive143_shared_price_v21 import NEW as V21

OLD = V21.with_name("issued-price-v22")
NEW = OLD.with_name("issued-price-v23")
SEAL = "e8d13381e4089ab239c9dd1b2bf5025fc297ab1f9ba654e3fc8f1aeaf2c202ee"
OLD_UNIT = "horizon-qualify-143-second-hourly-20261128-v1.service"
UNIT = "horizon-qualify-143-second-hourly-20261128-v2.service"


def derive(stage, revision):
    files = read_package(OLD, SEAL)
    for name, count in (("capacity.py", 1), ("continuation_price.py", 1), ("successor_price.py", 3)):
        raw, mode = files[name]
        source = raw.decode()
        if source.count(str(OLD)) != count:
            raise ValueError("different V22 self references for " + name)
        files[name] = (source.replace(str(OLD), str(NEW)).encode(), mode)

    raw, mode = files["successor_price.py"]
    source = change(raw.decode(), f'hourly_unit = "{OLD_UNIT}"', f'hourly_unit = "{UNIT}"')
    files["successor_price.py"] = (source.encode(), mode)

    raw, mode = files["shared_hourly143.py"]
    source = raw.decode().replace("epoch143-second-hourly-20261128-v1", "epoch143-second-hourly-20261128-v2")
    source = source.replace("143-second-hourly-20261128-v1", "143-second-hourly-20261128-v2")
    source = change(source, 'RUN = Path("/home/sol/.jetstreamer-private") / SECOND.name',
                    'RUN = Path("/home/sol/.jetstreamer-private/epoch143-second-hourly-20261128-v1")')
    source = change(source, """    closure = closed(core, fleet)
    native = state(UNIT)
    if native["ActiveState"] == "failed":
        import runpy
        second = runpy.run_path(str(Path(__file__).with_name("second143_terminal.py")))["closed"](core)
        return dict(closure, second_released_terminal=second), None""", """    import runpy
    terminal = runpy.run_path(str(Path(__file__).with_name("second143_terminal.py")))["closed"](core)
    closure = dict(closed(core, fleet), second_released_terminal=terminal)
    native = state(UNIT)""")
    source = change(source, 'and actor["unit"] == UNIT and actor["closure"] == ACCEPTANCE and booking["tree"] == str(RUN),',
                    'and booking["failed_second_hourly"] == terminal\n'
                    '         and actor["unit"] == UNIT and actor["closure"] == ACCEPTANCE and booking["tree"] == str(RUN),')
    files["shared_hourly143.py"] = (source.encode(), mode)
    metadata = json.loads(files["SOURCE.json"][0])
    metadata.update(revision=revision, prior_shared_price=dict(
        path=str(OLD / "deployment-seal-receipt.json"), sha256=SEAL))
    files["SOURCE.json"] = ((json.dumps(metadata, indent=2) + "\n").encode(), 0o444)
    return member_plan(files, stage, NEW)


if __name__ == "__main__":
    print(json.dumps(derive(Path(sys.argv[1]), sys.argv[2]), indent=2))
