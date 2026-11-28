"""Issue the second 162 interval under the enrolled writer and the complete pre-funded roster."""
import argparse
import fcntl
import json
from pathlib import Path
import re
import runpy
import time

RT = Path("/var/lib/jetstreamer/horizon_runtime_data")
ROOT = RT/"epoch162-second-replay-20261128-v3"
OPERATOR = ROOT/"operator-v1"
WHOLE = RT/"epoch162-first-hourly-completion-20261127-v2/issued-price-v16"
PEER = "2cdcdf1611223595f51bc022ca626168afa27726ab767a59aae754238af7e606"
INTERFACE = "ff09a7c8a45f6135b64bb25ce7fdea65e78ea71331afd29503baf8c3ad393dcb"
PRICE_SEAL = "b4871c7897b1f00aa98f7dac351b00c7918961c3e7a29370c6e0b813529cd35d"
PRICE_HASH = "944b5ea2a8cffbfbcb1d0691e5d22816148e2e3a0ea95bcbf0de1aeed62e0af3"


def issue(mode, shared_pin):
    launch = runpy.run_path(str(OPERATOR/"launch.py"))
    layout = launch["l"]
    need = layout.need
    with launch["LOCK"].open("rb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        manifest, roster = layout.pinned(WHOLE/"deployment-seal-receipt.json", shared_pin)
        need(manifest["destination"] == str(WHOLE) and any(m["name"] == "second162_peer.py" and
             m["sha256"] == layout.digest(WHOLE/m["name"]) == PEER for m in manifest["members"]), "different shared 162 peer")
        wr = RT/"survivor172-cadence-20261122-v1"
        active_path = max(wr.glob("FAILED166_CADENCE_V*_ACTIVE.json"), key=lambda p:int(p.name.split("_V", 1)[1].split("_")[0]))
        active, writer = layout.pinned(active_path)
        ready = layout.bound(active["ready"])
        support, interface = layout.pinned(ROOT/"INTERFACE.json", INTERFACE)
        scope, scope_ref = layout.pinned(ROOT/"SCOPE.json", support["scope"]["sha256"])
        _, operator = layout.pinned(OPERATOR/"deployment-seal-receipt.json", support["provider"]["sha256"])
        need(ready["second162_reserved_scope"] == support["scope"] == scope_ref and ready["second162_reserved_provider"] == operator
             and ready["second162_reserved_reader"]["sha256"] == support["reader"]["sha256"]
             and ready["second162_reserved_predecessor"] == support["closure"] == scope["postguard_predecessor"]
             and scope["previous"] == support["immutable_predecessor"] and scope["native_guard_validation"] == support["guard_validation"],
             "different 162 enrollment or checkpoint lineage")
        price = ROOT/"second-price-v3/second_reserved_price.py"
        deployment, price_ref = layout.pinned(price.with_name("deployment-seal-receipt.json"), PRICE_SEAL)
        need(deployment["destination"] == str(price.parent) and any(m["name"] == price.name and
             m["sha256"] == layout.digest(price) == PRICE_HASH for m in deployment["members"]), "different lane price")
        spec = dict(schema="horizon-private-162-second-reserved-enrollment-v1", writer_active=writer, operator=operator,
                    donor=launch["file_ref"](layout.DONOR), capacity=launch["file_ref"](price), whole_roster=roster,
                    first_terminal=scope["previous"], price_deployment=price_ref, unreleased_predecessor=support["closure"],
                    guard_validation=support["guard_validation"], reserved_interface=interface)
        preview = layout.save(ROOT/("RESERVED_PREVIEW_"+str(time.time_ns())+".json"), dict(spec, preview=True), 0o400)
        quote = runpy.run_path(str(price))["quote"]("prestart", None, layout.profile(36), preview)
        observed = layout.save(ROOT/("RESERVED_NATIVE_PRICE_"+str(time.time_ns())+".json"), quote, 0o400)
        print(json.dumps(dict(price=observed, fits=quote["fits"], home=quote["home_margin"], ram=quote["ram_margin"],
                              guard_floor=quote["guard_floor"], writer=writer)), flush=True)
        if mode == "launch":
            launch["validate_quote"](quote, "prestart", None, preview)
            enrolled = layout.save(ROOT/"SPLIT162_ENROLLMENT.json", spec, 0o400)
            print(json.dumps(dict(enrolled=enrolled)), flush=True)
            print(json.dumps(launch["launch"]()), flush=True)


if __name__ == "__main__":
    args = argparse.ArgumentParser(__doc__)
    args.add_argument("mode", choices=("quote", "launch"))
    args.add_argument("shared_price_sha256")
    options = args.parse_args()
    if not re.fullmatch("[a-f0-9]{64}", options.shared_price_sha256):
        args.error("expected the exact shared price SHA-256")
    issue(options.mode, options.shared_price_sha256)
