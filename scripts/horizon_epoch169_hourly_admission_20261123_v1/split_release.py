"""Build a reproducible operator deployment plan and its two V48 receiver plans."""
import argparse
import hashlib
import json
import os
import runpy
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = Path("/var/lib/jetstreamer/horizon_runtime_data")
SEALED = ROOT / "epoch169-hourly-admission-20261123-v1/sealed-v3"
CONTINUATION = HERE.parent/"horizon_epoch170_checkpoint_suffix"
CAMPAIGN = Path("/home/sol/.jetstreamer-private/epoch168-anza-reader-build-20261127.jMydZnTw/v2-20261127/campaign-price.py")
CAMPAIGN_SHA = "5bb2552e1bbe3fa52826be1c2c5b630ae8a243974d4a6ed11f9a52eacc4ce832"


def sha(p):
    with p.open("rb") as f:
        return hashlib.file_digest(f,"sha256").hexdigest()


def operator():
    if sha(CAMPAIGN)!=CAMPAIGN_SHA or sha(SEALED/"g4-producer.service")!="0cd2a78c8f67483be1af6f5fe63cbfb2b05a455fc6dfece4f9798f9ba1379fc4":
        raise ValueError("different checked auxiliary ledger or historical producer profile")
    files=[HERE / (name+".py") for name in ("actor","bindings","hourly","hourly_gate","prepare","watch",
           "scratch_mount","split_actor","split_booking","split_capacity","split_operator")]
    files += [CONTINUATION / (name+".py") for name in ("successor_price","continuation_price","assembly_reservation",
              "live_168_170_price","verification_reservation","rollover143")]
    witness = CAMPAIGN.with_name("witness-admission.py")
    closures = HERE.parent / "horizon_epoch162_split_scratch/terminal_ram.py"
    if sha(witness) != "95d400b2f5174c6cfb1618f184da76d402bff6fe23c824d5450717be61326b5d" or sha(closures) != "203fdea3bbe271973dbae87f33342f063b746e470d977eac44972ebc079cce16":
        raise ValueError("unregistered live residency or terminal provenance")
    files += [HERE.parent/"horizon_epoch162_split_price/peer162.py", CAMPAIGN, witness, closures, SEALED/"g4-producer.service"]
    members=[dict(name=p.name,source=str(p),sha256=sha(p),mode=0o444) for p in files]
    return dict(schema="jetstreamer-sealed-deployment-plan-v1",destination=str(SEALED.with_name("issued-split-v1")),members=members)


def receiver_plans(parent):
    if os.geteuid() != 0 or not parent.is_dir() or parent.resolve() != parent or parent.stat().st_dev != Path("/home/sol").stat().st_dev:
        raise ValueError("stage V48 receivers in an existing home-backed private directory as root")
    staging = Path(tempfile.mkdtemp(prefix="v48-receivers-",dir=parent))
    program = runpy.run_path(str(HERE / "derive48.py"))
    sealed = program["OPERATOR"] / "deployment-seal-receipt.json"
    spec = dict(path=str(sealed), sha256=sha(sealed))
    roots = {"writer": ROOT / "survivor172-cadence-20261122-v1" / program["OLD"],
             "booker": ROOT / "epoch143-first-hourly-20261127-v1/booking-price-v47"}
    plans = {}
    for name, old in roots.items():
        plan = program["stage"](old,staging / name,spec)
        target = staging / (name + "-plan.json")
        with target.open("x") as output:
            json.dump(plan,output,indent=2,sort_keys=True)
            output.write("\n")
            output.flush()
            os.fchmod(output.fileno(),0o400)
            os.fsync(output.fileno())
        plans[name] = dict(path=str(target),sha256=sha(target))
    return dict(operator=spec, **plans)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument("--stage-receivers", type=Path, metavar="DIRECTORY")
    args = parser.parse_args()
    plan = receiver_plans(args.stage_receivers) if args.stage_receivers else operator()
    print(json.dumps(plan,sort_keys=True,indent=2))
