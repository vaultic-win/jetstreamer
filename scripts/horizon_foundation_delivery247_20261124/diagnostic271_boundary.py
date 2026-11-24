"""Register the boundary trace through the established epoch 271 observer."""

import importlib.util
from pathlib import Path

import diagnostic271_europe

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
gate = observer.gate
owns = observer.owns
