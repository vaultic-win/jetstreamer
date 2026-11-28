"""Carry the issued V30 price forward with the corrected epoch 143 cadence writer."""

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from derive69 import NEW as WRITER
from derive143_bootstrap_retry import change, read_package
from derive143_held_retry import edit, NEW as PREVIOUS
from derive143_v53 import member_plan


PREVIOUS_SEAL = "c54571de8af0a25dc791d447534aa4513721818cbb47236fbf52f56cf54471c3"
DESTINATION = PREVIOUS.with_name("issued-price-v31")


def writer_paths(source):
    # Count both sealed packages on HOME. Only the second package can own the live writer.
    source = change(source, "    dirs.extend(booker/", f"    dirs.append(writer / {WRITER.name!r})\n    dirs.extend(booker/")
    source = change(source, "        following = active['new']",
                    "        following = active['new']\n"
                    "        writer_package = f'tools-cold168-retry5-failed166-v{version}-entry146'\n"
                    f"        if version == 69:\n            writer_package = {WRITER.name!r}")
    return change(source, "directory/f'tools-cold168-retry5-failed166-v{version}-entry146'/'status_cycle.py'",
                  "directory/writer_package/'status_cycle.py'")


def derive(stage, revision):
    files = read_package(PREVIOUS, PREVIOUS_SEAL)
    for name, expected in (("capacity.py", 1), ("continuation_price.py", 1), ("successor_price.py", 3)):
        def update_path(source):
            if source.count(str(PREVIOUS)) != expected:
                raise ValueError(f"unexpected self-reference count in {name}")
            return source.replace(str(PREVIOUS), str(DESTINATION))
        edit(files, name, update_path)
    edit(files, "following_peers.py", writer_paths)
    metadata = json.loads(files["SOURCE.json"][0])
    metadata.update(revision=revision, prior_shared_price=dict(
        path=str(PREVIOUS / "deployment-seal-receipt.json"), sha256=PREVIOUS_SEAL),
        registered_writer_v69=str(WRITER))
    files["SOURCE.json"] = ((json.dumps(metadata, indent=2) + "\n").encode(), 0o444)
    return member_plan(files, stage, DESTINATION)


if __name__ == "__main__":
    print(json.dumps(derive(Path(sys.argv[1]).resolve(), sys.argv[2]), indent=2))
