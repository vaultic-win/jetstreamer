"""Stage the corrected native48 actor or the original guarded 15-phase build operator."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

PACKAGE = Path(__file__).resolve().parent
REPO = PACKAGE.parents[1]
HOST = Path("/home/sol")
RUNTIME = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch163-native48-inodes-20261123-v1")
ACTOR = RUNTIME / "actor-source"
OPERATOR = RUNTIME / "operator"
OLD_OPERATOR = Path("/usr/local/lib/jetstreamer/horizon-native163-consumer15-operator-source-20261112-v3")
OLD_ACTOR = Path("/usr/local/lib/jetstreamer/horizon-epoch163-native48-input-source-20261112-v1")
OLD_EXEC = "/usr/local/lib/jetstreamer/horizon-native163-consumer15-operator-20261112-v1/run"
OPERATOR_INPUTS = {
    "main.rs": "81f9be7b602d9995d392fbe75758553bbf2c59dd3c6da479dc5f061c6045281b",
    "phase.rs": "68abd66f3d22cf358ebc9c35aa80218e326a413df3347db9df243dfc450b9770",
}
SEALER_SHA = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3"
INPUTS = json.loads((PACKAGE / "native48-build-inputs.json").read_bytes())


def require(value, error):
    if not value:
        raise ValueError(error)


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def bound(path):
    return {"path": str(path), "sha256": sha(path)}


def dump(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def compact_digest(value):
    return hashlib.sha256(json.dumps(value, separators=(",", ":")).encode()).hexdigest()


def snapshot():
    ref = INPUTS["protocol"]
    path = Path(ref["path"])
    require(sha(path) == ref["sha256"], "original protocol changed")
    return json.loads(path.read_bytes())


def seal_plan(output, destination, files):
    return {
        "schema": "jetstreamer-sealed-deployment-plan-v1",
        "destination": str(destination),
        "members": [{"source": str(output / name), "name": name, "sha256": digest,
                     "mode": 0o444} for name, digest in sorted(files.items())],
    }


def actor(stage, final):
    for name, rec in INPUTS["source_files"].items():
        src = REPO / rec["source"]
        require(sha(src) == rec["base_sha256"], f"{name} in the checkout differs")
        shutil.copyfile(src, stage / name)
    subprocess.run(["patch", "--batch", "--fuzz=0", "-p1", "-i", str(PACKAGE / "native48-profile.patch")],
                   cwd=stage, check=True)
    files = {p.name: sha(p) for p in stage.iterdir()}
    require(files == {name: row["sha256"] for name, row in INPUTS["source_files"].items()},
            "native48 actor-source reconstruction differed")
    dump(stage / "actor-source-plan.json", seal_plan(final, ACTOR, files))
    original = snapshot()
    for row in original["actual55_externs"]:
        path = Path(row["arg"].split("=", 1)[1])
        require(sha(path) == row["sha256"], f"changed cached dependency {path}")
    native = {arg.removeprefix("native=") for phase in original["phases"]
              for arg in phase["payload"] if arg.startswith("native=")}
    require(all(Path(path).is_dir() for path in native), "missing native dependency search directory")
    dump(stage / "dependencies.json", {"baseline": INPUTS["protocol"], "externs": original["actual55_externs"],
             "native_search_directories": sorted(native), "phases": [row["phase"] for row in original["phases"]]})


def checked_actor(actor_plan):
    files = {name: row["sha256"] for name, row in INPUTS["source_files"].items()}
    plan = json.loads(actor_plan.read_bytes())
    require(plan["schema"] == "jetstreamer-sealed-deployment-plan-v1" and
            plan["destination"] == str(ACTOR) and len(plan["members"]) == len(files) and
            {m["name"]: m["sha256"] for m in plan["members"]} == files and
            all(m["mode"] == 0o444 and sha(Path(m["source"])) == files[m["name"]] for m in plan["members"]),
            "wrong corrected actor plan or source")
    seal = ACTOR / "deployment-seal-receipt.json"
    receipt = json.loads(seal.read_bytes())
    require(receipt["schema"] == "jetstreamer-sealed-deployment-receipt-v1" and
            receipt["sealer_sha256"] == SEALER_SHA and
            receipt["plan_sha256"] == sha(actor_plan) and receipt["destination"] == str(ACTOR)
            and len(receipt["members"]) == len(files), "missing exact actor source seal")
    require({m["name"]: m["sha256"] for m in receipt["members"]} == files and
            all(m["mode"] == "0444" for m in receipt["members"]) and
            all(sha(ACTOR / name) == digest for name, digest in files.items()), "changed installed actor sources")
    return seal


def rebind_phases(original):
    for phase in original["phases"]:
        argv = phase["payload"]
        n = len(argv)
        require(compact_digest(argv) == phase["payload_sha256"] == phase["gate_plan"]["payload_sha256"]
                and phase["actor_argv"][-n:] == argv, "wrong original payload binding")
        changed = [str(ACTOR / Path(arg).name) if Path(arg).parent == OLD_ACTOR else arg for arg in argv]
        phase["payload"] = changed
        phase["payload_sha256"] = phase["gate_plan"]["payload_sha256"] = compact_digest(changed)
        phase["actor_argv"][-n:] = changed


def operator(stage, final, actor_plan, current_fleet=False):
    seal = checked_actor(actor_plan)
    original = snapshot()
    original["consumer_source_plan"] = bound(actor_plan)
    original["source_seal"] = bound(seal)
    rebind_phases(original)
    for name, digest in OPERATOR_INPUTS.items():
        src = OLD_OPERATOR / name
        require(sha(src) == digest, "operator predecessor changed")
        before, after = ((OLD_EXEC, str(OPERATOR / "run")) if name == "main.rs"
                         else (str(OLD_ACTOR), str(ACTOR)))
        text = src.read_text()
        require(text.count(before) == 1, "wrong number of operator source anchors")
        (stage / name).write_text(text.replace(before, after))
    dump(stage / "PROTOCOL.json", original)
    names = [*OPERATOR_INPUTS, "PROTOCOL.json"]
    if current_fleet:
        shutil.copyfile(PACKAGE / "consumer_capacity.rs", stage / "consumer_capacity.rs")
        subprocess.run(["patch", "--batch", "--fuzz=0", "-p1", "-i", str(PACKAGE / "current-operator.patch")],
                       cwd=stage, check=True)
        names.append("consumer_capacity.rs")
    members = {name: sha(stage / name) for name in names}
    dump(stage / "operator-source-plan.json", seal_plan(final, RUNTIME / "operator-source", members))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    a = sub.add_parser("actor")
    a.add_argument("output", type=Path)
    o = sub.add_parser("operator")
    o.add_argument("actor_plan", type=Path)
    o.add_argument("output", type=Path)
    o.add_argument("--current-fleet", action="store_true")
    args = parser.parse_args()
    output = args.output.absolute()
    parent = output.parent.resolve(strict=True)
    require(parent == output.parent and parent.stat().st_dev == HOST.stat().st_dev,
            "stage on the home filesystem at a canonical path")
    require(not os.path.lexists(output), "stage already exists")
    with tempfile.TemporaryDirectory(dir=parent) as tmp:
        stage = Path(tmp) / "stage"
        stage.mkdir(mode=0o700)
        if args.mode == "actor":
            actor(stage, output)
        else:
            operator(stage, output, args.actor_plan.resolve(strict=True), args.current_fleet)
        # Refuse even an empty directory created by a concurrent staging process.
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.renameat2(-100, os.fsencode(stage), -100, os.fsencode(output), 1):
            err = ctypes.get_errno()
            raise OSError(err, os.strerror(err), str(output))
    print(output)


if __name__ == "__main__":
    main()
