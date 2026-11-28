"""Register the boundary trace through the established epoch 271 observer."""

import importlib.util
from pathlib import Path

import diagnostic271_europe
from ordinary249.delivery248 import bound, props, ref

spec = importlib.util.spec_from_file_location(
    "epoch271_boundary_observer", diagnostic271_europe.__file__
)
observer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observer)
observer.UNIT = "horizon-qualify-271-boundary-trace-v297.service"
observer.PACKAGE = Path("/var/lib/jetstreamer/horizon271-boundary-replay-v297")
observer.RUN_ROOT = Path(
    "/home/ubuntu/.jetstreamer-private/qualification-271-boundary-trace-v297"
)
observer.REGISTRATION = observer.PACKAGE / "cadence-registration.json"

UNIT = observer.UNIT
PACKAGE = observer.PACKAGE
RUN_ROOT = observer.RUN_ROOT
configuration = observer.configuration
owns = observer.owns


def gate(plan):
    terminal_path = PACKAGE / "terminal.json"
    if not terminal_path.is_file():
        observer.gate(plan)
        return

    # The deployed fleet reader accepts the historical performance service
    # namespace for ordinary diagnostic claims. Carry the closed invocation
    # through the repair gate and native census using its original identity.
    registration, _ = observer.receipt()
    terminal = ref(terminal_path)
    closed = bound(terminal)
    assert closed["registration"] == registration and closed["epoch"] == 271
    owner = closed["producer"]
    assert owner["Id"] == UNIT and props(UNIT, list(owner)) == owner
    assert owner["ActiveState"] in {"failed", "inactive"} and owner["MainPID"] == "0"
    assert closed["timer_drained"]["ActiveState"] == "inactive"
    if UNIT not in plan["tracked_units"]:
        plan["tracked_units"].append(UNIT)
    repair = plan["gates"]["271"]
    for evidence in (registration, terminal, closed["trace"]):
        if evidence not in repair["evidence"]:
            repair["evidence"].append(evidence)
    repair["next_action"] = closed["next_action"]
