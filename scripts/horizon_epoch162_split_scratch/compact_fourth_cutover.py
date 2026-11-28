"""Run V75's native cutover with its inherited epoch 167 assembly reader explicitly bound."""
import argparse
import fcntl
import importlib
import json
import os
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import compact_fourth_turnover as plan

SEAL = "07af8653b096670465378034fa47a95a55f1c3d49ddfd8690bf382680d180a17"


def main(revision, pending, apply):
    plan.writer.published(revision,[Path(__file__).resolve()])
    members = plan.writer.read_package(plan.V75,SEAL)
    bindings = {n:plan.compact.digest(plan.V75/n) for n in (
        "cutover75.py","transition_v75.py","transition_v74.py","assembly_cadence.py","status_cycle.py")}
    plan.need(os.geteuid() == 0 and __debug__ and all(name in members for name in bindings)
              and bindings["cutover75.py"] == "c0b7efff75e8861740658745c102c6a8bfac3c046b9616af06a7bc90cdb89b15"
              and bindings["transition_v75.py"] == "168d84fd6c5f120773abf0133af6ad0efedf57dfe8b9c275857fe080da926ae6",
              "different cutover package")
    sys.path.insert(0,str(plan.V75))
    # status_cycle establishes the sealed predecessors' import directories.
    importlib.import_module("status_cycle")
    current, prior = (importlib.import_module("transition_v"+str(v)) for v in (75,74))
    cutover = importlib.import_module("cutover75")
    plan.need(Path(current.__file__) == plan.V75/"transition_v75.py" and Path(prior.__file__) == plan.V75/"transition_v74.py"
              and Path(cutover.__file__) == plan.V75/"cutover75.py" and current.prior is prior
              and current.native_assignments is prior.native_assignments and not hasattr(current,"assembly")
              and Path(prior.assembly.__file__) == plan.V75/"assembly_cadence.py", "different inherited native reader")
    # The sealed V75 ready validator already calls prior.assembly.owner_binding().
    # Its cutover calls the identical reader through the shorter module name.
    current.assembly = prior.assembly
    proposal = cutover.doc(pending)
    head = proposal["fleet"]
    plan.need(pending.resolve(strict=True).parent == plan.BASE and proposal["old_owner"]["sha256"] == plan.ACTIVE
              and proposal["package"]["sha256"] == SEAL, "foreign pending writer")
    with cutover.BOOKING_LOCK.open("rb") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        fleet = cutover.doc(Path(head["path"]),head["sha256"])
        protected = cutover.endpoints(fleet)
        plan.need(protected["assembly167"] == current.assembly.owner_binding() == proposal["epoch167_assembly_owner"],
                  "another epoch 167 assembly owns the slot")
        if apply:
            return cutover.cutover(pending)
        return dict(package=proposal["package"],pending=plan.compact.reference(pending),
                    assembly=protected["assembly167"],qualified_native_endpoints=True)


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("revision")
    parser.add_argument("pending",type=Path)
    parser.add_argument("--apply",action="store_true")
    a=parser.parse_args()
    print(json.dumps(main(a.revision,a.pending,a.apply),sort_keys=True),flush=True)
