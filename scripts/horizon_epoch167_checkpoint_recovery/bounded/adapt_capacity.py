"""Stage the conservative held and guarded epoch 167 capacity provider."""

import argparse
import ast
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

PROVIDERS = Path("/var/lib/jetstreamer/horizon_runtime_data/incident-replay-fit-20261121-v1")
BASELINE = "tools-homefloor-170-full-metered-independent-v20-joint168-v31"
ROUTE = BASELINE + "-replace167-reserve"
ADDED = {
    "replacement167_capacity.py": 0o444,
    "terminal_joint168_capacity.py": 0o444,
    "bounded167-admission.py": 0o555,
}


HOLDING_SOURCES = {
    "Cargo.toml": "837f0659bd80eeedb2376127681e650321e40fb4dfb81a6611e7e773d626e887",
    "Cargo.lock": "bee4316a99586a2032c560e4689a64547c12c5c6f041a495cba6d6b8d3c951bf",
    "observer.rs": "023f1fe75233c446a7c6ad36067726f3ca86f5a9df264cc471a70a06418d24fe",
    "replay_price.rs": "101702e88c645737a27807b3eeb8a9fa0df1ddbe1542f603e8f9329647198e26",
}


def apply_patch(directory, name):
    patch = Path(__file__).with_name(name).resolve(strict=True)
    subprocess.run(['/usr/bin/patch', '--batch', '--forward', '--fuzz=0', '-p1', '--input', patch],
                   cwd=directory, check=True, stdout=subprocess.DEVNULL, timeout=30)


def holding_price(source, staging):
    with tempfile.TemporaryDirectory(prefix="holding-price-", dir=staging.parent) as location:
        work = Path(location)
        for name, expected in HOLDING_SOURCES.items():
            data = (source/name).read_bytes()
            if hashlib.sha256(data).hexdigest() != expected:
                raise ValueError(f"V31 holding source changed: {name}")
            (work/name).write_bytes(data)
        apply_patch(work, "v32_holding.patch")
        common = ["--offline", "--locked", "--target-dir", str(work/"target")]
        subprocess.run(["cargo", "test", *common], cwd=work, check=True,
                       stdout=subprocess.DEVNULL, timeout=120)
        subprocess.run(["cargo", "build", "--release", *common], cwd=work, check=True,
                       stdout=subprocess.DEVNULL, timeout=120)
        binary = work/"target/release/horizon-epoch185-holding-observer"
        (staging/"holding185-price").write_bytes(binary.read_bytes())


def stage(baseline_plan, staging, holding_source=None):
    plan = json.loads(baseline_plan.read_bytes())
    if (plan["schema"] != "jetstreamer-sealed-deployment-plan-v1"
            or Path(plan["destination"]) != PROVIDERS/BASELINE):
        raise ValueError("matching V31 capacity seal plan required")
    members = {}
    modes = {}
    seen = set()
    prior_holding = None
    for member in plan["members"]:
        name = member["name"]
        if name in seen or Path(name).name != name or name in ADDED:
            raise ValueError(f"foreign or duplicate V31 member {name}")
        seen.add(name)
        if name == "SHA256SUMS":
            continue
        data = Path(member["source"]).read_bytes()
        if hashlib.sha256(data).hexdigest() != member["sha256"]:
            raise ValueError(f"V31 member changed {name}")
        members[name] = data
        modes[name] = member["mode"]
        if name == "holding185-price":
            prior_holding = Path(member["source"]).resolve(strict=True)

    staging.mkdir(mode=0o700, exist_ok=False)
    for name, data in members.items():
        (staging/name).write_bytes(data)
    apply_patch(staging, "v31_reserve.patch")
    if prior_holding is None or modes["holding185-price"] != 0o555:
        raise ValueError("the V31 plan has no executable holding price")
    source = holding_source or prior_holding.parent.parent/"holding"
    holding_price(source, staging)
    callback = Path(__file__).with_name("replay167.py")
    (staging/"bounded167-admission.py").write_bytes(callback.read_bytes())
    modes.update(ADDED)

    if {path.name for path in staging.iterdir()} != set(modes):
        raise ValueError("capacity patch produced unexpected staged members")
    rows = []
    for name, mode in sorted(modes.items()):
        path = staging/name
        data = path.read_bytes()
        if name == "post-stop-fit" or path.suffix == ".py":
            ast.parse(data, filename=name)
        path.chmod(mode)
        rows.append(dict(source=str(path.resolve(strict=True)), name=name,
                         sha256=hashlib.sha256(data).hexdigest(), mode=mode))
    return dict(schema=plan["schema"], destination=str(PROVIDERS/ROUTE), members=rows)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("baseline_plan", type=Path)
    parser.add_argument("staging", type=Path)
    parser.add_argument("--holding-source", type=Path)
    args = parser.parse_args()
    print(json.dumps(stage(args.baseline_plan, args.staging, args.holding_source), indent=2))


if __name__ == "__main__":
    main()
