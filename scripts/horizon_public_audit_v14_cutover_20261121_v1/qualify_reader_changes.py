"""Qualify the pre-fence decision against the changed consumer and the old audit checkout."""
import json
from pathlib import Path
import runpy
import subprocess
import sys
from unittest.mock import patch


def qualify(package):
    module = runpy.run_path(str(package / "follow_boundary.py"))
    cut = module["cut"]
    functions = cut.__globals__
    source = Path("/home/sol/workspace/jetstreamer")
    audit = module["STATE"].parent / "source"
    old = "c7615174927d5f0d12a05eea2fcac9c0f368002b"
    new = "a2c01315b379a7ecf4ca2f84ba202b3112f2833f"
    changes = module["reader_changes"](source, new)
    assert len(changes) == 8 and "jetstreamer-horizon/src/archive/reader.rs" in changes
    assert module["reader_changes"](source, old) == []
    fetched = subprocess.check_output(["git", "-c", "safe.directory=" + str(audit), "-C", audit,
                                       "rev-parse", "refs/remotes/origin/account-updates"], text=True).strip()
    production_changes = module["reader_changes"](audit, fetched)
    record = {"range_start": 73, "pid": 123}
    with patch.dict(functions, durable_native=lambda reader: {"closed": True}, roster=lambda: [],
                    command=lambda *args: new, reader_changes=lambda repo, tip: module["reader_changes"](source, tip)), \
         patch.object(module["os"], "pidfd_open", side_effect=AssertionError("changed build opened a pidfd")):
        assert cut(record, {}, 0) is False
    print(json.dumps({"qualified_build": module["EQUIVALENT_BUILD"], "current_checkout": fetched,
                      "current_checkout_changes": production_changes, "changed_commit": new,
                      "changed_paths": changes, "equivalent_commit": old, "changed_reader_left_running": True}))


if __name__ == "__main__":
    qualify(Path(sys.argv[1]))
