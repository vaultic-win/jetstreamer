"""Bind the bounded epoch 271 stake input trace to the existing diagnostic census."""

import importlib.util
from pathlib import Path

import diagnostic271_europe

spec = importlib.util.spec_from_file_location(
    "epoch271_stake_inputs_observer", diagnostic271_europe.__file__
)
observer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observer)
observer.UNIT = "horizon-perf-epoch271-stake-inputs@v307.service"
observer.PACKAGE = Path("/var/lib/jetstreamer/horizon271-stake-input-replay-v307")
observer.RUN_ROOT = Path(
    "/home/ubuntu/.jetstreamer-private/qualification-271-stake-inputs-v307"
)
observer.REGISTRATION = observer.PACKAGE / "cadence-registration.json"

UNIT = observer.UNIT
PACKAGE = observer.PACKAGE
RUN_ROOT = observer.RUN_ROOT
configuration = observer.configuration
owns = observer.owns


def gate(plan):
    observer.gate(plan)
    if observer.REGISTRATION.is_file() and not (PACKAGE / "terminal.json").is_file():
        plan["gates"]["271"]["next_action"] = (
            "Capture the stake reward inputs at slot 117072004 and reproduce the "
            "native reward maps before testing the canonical payout scale."
        )
