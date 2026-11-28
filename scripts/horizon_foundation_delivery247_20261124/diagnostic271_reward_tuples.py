"""Enroll the epoch 271 reward records replay in the existing diagnostic census."""

import importlib.util
from pathlib import Path

import diagnostic271_europe

spec = importlib.util.spec_from_file_location(
    "epoch271_reward_tuples_observer", diagnostic271_europe.__file__
)
observer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observer)
observer.UNIT = "horizon-perf-epoch271-reward-tuples@v299.service"
observer.PACKAGE = Path("/var/lib/jetstreamer/horizon271-reward-tuple-replay-v299")
observer.RUN_ROOT = Path(
    "/home/ubuntu/.jetstreamer-private/qualification-271-reward-tuples-v299"
)
observer.REGISTRATION = observer.PACKAGE / "cadence-registration.json"

UNIT = observer.UNIT
PACKAGE = observer.PACKAGE
RUN_ROOT = observer.RUN_ROOT
configuration = observer.configuration
gate = observer.gate
owns = observer.owns
