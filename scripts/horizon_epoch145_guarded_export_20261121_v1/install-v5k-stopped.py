#!/usr/bin/python3 -IB
"""Seal the read-only five-producer quote provider for the exact stopped V5k verifier."""
import json
import os
from pathlib import Path
import re
import runpy
import subprocess
import sys

FAMILY = Path("scripts/horizon_epoch145_guarded_export_20261121_v1")
PROVIDER = Path("scripts/horizon_incident_replay_fit_20261121_v1/post-stop-fit")
BASE = Path("/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1")
DONOR = BASE / "tools-homefloor-145-lease-build-v1"
DONOR_SHA = "ba47dd7987accfbb8471b845425dd56a9b9c2e3e2231601e277889e6444a30b5"
TARGET = BASE / "tools-homefloor-145-v5k-stopped-v1"


def main(commit):
    if not (os.geteuid() == 0 and sys.flags.isolated and __debug__ and re.fullmatch("[0-9a-f]{40}", commit)):
        raise ValueError("root isolated interpreter and exact merged commit required")
    here = Path(__file__).resolve().parent
    repo = here.parents[1]

    def git(*args):
        return subprocess.check_output(["/usr/sbin/runuser", "-u", "sol", "--", "/usr/bin/git", "-C", repo, *args])

    git("merge-base", "--is-ancestor", commit, "origin/account-updates")
    srcs = [FAMILY / Path(__file__).name, FAMILY / "install-v5j-post.py",
            FAMILY / "v5k_stopped.py", FAMILY / "test_v5k_stopped.py", PROVIDER]
    if git("diff", "--name-only", commit, "origin/account-updates", "--", *srcs):
        raise ValueError("superseded source")
    for path in srcs:
        if (repo / path).read_bytes() != git("show", f"{commit}:{path}"):
            raise ValueError(f"uncommitted source {path}")
    util = runpy.run_path(str(here / "install-v5j-post.py"))
    need, ref, item = (util[k] for k in ("require", "ref", "item"))
    seal = DONOR / "deployment-seal-receipt.json"
    need(ref(seal)["sha256"] == DONOR_SHA, "different sealed donor")
    source = BASE / ("stopped-v5k-sources-" + commit)
    source.mkdir(mode=0o700, exist_ok=True)
    need(source.resolve(strict=True) == source and source.stat().st_uid == 0
         and not source.stat().st_mode & 0o077, "unsafe staging directory")
    members = {}
    for row in json.loads(seal.read_bytes())["members"]:
        name = row["name"]
        need(Path(name).name == name and ref(DONOR / name)["sha256"] == row["sha256"], "changed donor")
        members[name] = item(name, DONOR / name, int(row["mode"], 8))
    for name, src, mode in (("post-stop-fit", PROVIDER, 0o555), ("v5k_stopped.py", FAMILY / "v5k_stopped.py", 0o444)):
        installed = util["write"](source / name, git("show", f"{commit}:{src}"))
        members[name] = item(name, installed, mode)
    provenance = util["record"](source / "source.json", {"source_commit": commit, "donor": ref(seal),
        "files": {str(k): ref(repo / k)["sha256"] for k in srcs}, "admission_authorized": False})
    members["v5k-stopped-source.json"] = item("v5k-stopped-source.json", provenance, 0o444)
    result = util["install"](TARGET, list(members.values()), source / "seal-plan.json")
    print(json.dumps({"provider": str(TARGET / "post-stop-fit"), "source": commit, "seal": result}, sort_keys=True))


if __name__ == "__main__":
    main(*sys.argv[1:])
