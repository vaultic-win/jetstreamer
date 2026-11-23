#!/usr/bin/python3 -IB
"""Seal the v5j handoff without changing the immutable verifier, unit, or holding state.

Run as root with an exact account-updates commit and the immutable admission review path.
The resulting tools-homefloor-145-handoff-v1/run-recovery accepts the original FLEET argument.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

BASE = Path("/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1")
ORIGINAL = BASE / "tools-homefloor-145-rejoin-v4"
TARGET = BASE / "tools-homefloor-145-handoff-v1"
REPO = Path("/home/sol/workspace/jetstreamer")
SEALER = Path("/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment")
SEALER_SHA = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3"
ORIGINAL_SHA = "ed0e272c1cf6df09bb19ff6049154cad9e55f21e96089f66e6f9e3d0f89da9cb"
REVIEW_SHA = "4b8963f5490bd9dba3d9d6db521b9e9e864a28108c7b79bbe420417eefaf82e6"
SOURCE = "scripts/horizon_epoch145_guarded_export_20261121_v1/"
PROVIDER = "scripts/horizon_incident_replay_fit_20261121_v1/"
FILES = {"run-recovery": SOURCE + "recovery_dispatch.py", "post-stop-fit": PROVIDER + "post-stop-fit",
         "homefloor_registrations.py": PROVIDER + "homefloor_registrations.py"}


def require(ok, error):
    if not ok:
        raise ValueError(error)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def git(*args):
    return subprocess.check_output(["runuser", "-u", "sol", "--", "git", "-C", REPO, *args])


def store(path, data):
    if not path.exists():
        # A temporary sibling permits a retry after power loss while staging.
        tmp = path.with_name("." + path.name + "." + str(os.getpid()))
        with tmp.open("xb") as f:
            f.write(data)
            f.flush()
            os.fchmod(f.fileno(), 0o400)
            os.fsync(f.fileno())
        try:
            os.link(tmp, path)
        except FileExistsError:
            pass
        finally:
            tmp.unlink()
    require(path.read_bytes() == data and path.lstat().st_uid == 0, f"different staged {path}")
    return {"path": str(path), "sha256": digest(data)}


def main():
    require(len(sys.argv) == 3 and os.geteuid() == 0 and sys.flags.isolated, "expected COMMIT ADMISSION_REVIEW")
    commit = sys.argv[1]
    require(re.fullmatch(r"[a-f0-9]{40}", commit), "use an exact commit")
    git("merge-base", "--is-ancestor", commit, "origin/account-updates")
    paths = [*FILES.values(), SOURCE + "test_recovery_dispatch.py", SOURCE + "install-recovery-dispatch.py"]
    require(not git("diff", "--name-only", commit, "origin/account-updates", "--", *paths),
            "newer dispatch sources on account-updates")
    require(git("show", commit + ":" + paths[-1]) == Path(__file__).read_bytes(), "different installer")
    review = Path(sys.argv[2]).read_bytes()
    require(digest(review) == REVIEW_SHA, "different original review")
    donor = (ORIGINAL / "deployment-seal-receipt.json").read_bytes()
    require(digest(donor) == ORIGINAL_SHA and digest(SEALER.read_bytes()) == SEALER_SHA, "different donor or sealer")
    stage = BASE / ("v5j-handoff-inputs-" + commit)
    stage.mkdir(mode=0o700, exist_ok=True)
    require(stage.resolve() == stage and stage.stat().st_uid == 0 and stage.stat().st_mode & 0o077 == 0,
            "untrusted staging area")
    members = {}
    for row in json.loads(donor)["members"]:
        name = row["name"]
        require(name == Path(name).name and digest((ORIGINAL / name).read_bytes()) == row["sha256"], "donor changed")
        members[name] = dict(name=name, source=str(ORIGINAL / name), mode=int(row["mode"], 8), sha256=row["sha256"])
    provenance = {}
    for name, src in FILES.items():
        data = git("show", commit + ":" + src)
        staged = store(stage / name, data)
        provenance[src] = staged["sha256"]
        members[name] = dict(name=name, source=staged["path"], sha256=staged["sha256"], mode=0o555)
    qualification_sources = {"source_commit": commit, "git_paths": provenance, "donor_seal_sha256": ORIGINAL_SHA,
                             "original_review_sha256": REVIEW_SHA}
    for name, data in [("admission-review.json", review), ("handoff-inputs.json", json.dumps(qualification_sources, sort_keys=True).encode())]:
        obj = store(stage / name, data)
        members[name] = dict(name=name, source=obj["path"], sha256=obj["sha256"], mode=0o444)
    plan = dict(schema="jetstreamer-sealed-deployment-plan-v1", destination=str(TARGET),
                members=[members[k] for k in sorted(members)])
    ref = store(stage / "plan.json", (json.dumps(plan, sort_keys=True) + "\n").encode())
    if not TARGET.exists():
        subprocess.run([SEALER, ref["path"], "--plan-sha256", ref["sha256"], "--self-sha256", SEALER_SHA], check=True)
    seal = (TARGET / "deployment-seal-receipt.json").read_bytes()
    evidence = json.loads(seal)
    require(evidence["plan_sha256"] == ref["sha256"] and evidence["destination"] == str(TARGET)
            and evidence["sealer_sha256"] == SEALER_SHA
            and {r["name"]: r["sha256"] for r in evidence["members"]} == {k: v["sha256"] for k, v in members.items()},
            "different installed package")
    print(json.dumps({"seal_sha256": digest(seal), "plan": ref, "commit": commit, "entrypoint": str(TARGET / "run-recovery")}))


if __name__ == "__main__":
    main()
