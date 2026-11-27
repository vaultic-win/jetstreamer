"""Consume the original assembly and status events across the V46 to V47 writer handoff."""

from pathlib import Path
import json
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import watch143_reentry as original
from cutover41 import state
from evidence import bound, checked, need

V46 = "657c9965f71dbff5478308c1c6a703bb4732855c6ac3d4b6daaa4dfa67907f4f"
V47 = original.WRITER / "tools-cold168-retry5-failed166-v47-entry146"
LISTENER = dict(
    path=str(original.TARGET / "REENTRY_WATCH_ARMED.json"),
    sha256="accd593c5de9fbe4ad9dd061393678e36e51bff7ae96c4a1f825d3bcabffae64",
)


def resolve():
    prior = dict(path=str(original.ACTIVE), sha256=V46)
    active47 = original.WRITER / "FAILED166_CADENCE_V47_ACTIVE.json"
    report = checked(LISTENER)
    phase = checked(report["phase"])
    need(
        HERE == V47
        and phase["writer"] == prior
        and phase["hourly143"]["contract"] == original.EPOCH143.contract,
        "different 143 listener or phase",
    )
    if active47.exists():
        ref = bound(active47)
        version, directory, booker = 47, V47, original.TARGET / "booking-price-v47"
    else:
        ref = prior
        version, directory, booker = 46, original.WRITER_PACKAGE, original.BOOKER
    active = checked(ref)
    writer, ready = active["new"], checked(active["ready"])
    package = bound(directory / "deployment-seal-receipt.json")
    if version == 47:
        need(
            active["old"] == checked(prior)["new"]
            and ready["old_owner"] == prior
            and ready["retained_143_phase"] == report["phase"]
            and ready["retained_143_listener"] == LISTENER,
            "V47 did not inherit this 143 listener",
        )
    need(
        writer["program"] == str(directory / "status_cycle.py")
        and ready["package"] == package
        and ready["hourly_reader"] == bound(directory / "first_hourly143.py"),
        "wrong writer program or first-hourly receiver",
    )
    live = state(
        original.OBSERVER, "Id", "MainPID", "InvocationID", "ActiveState", "Job"
    )
    if (
        live["ActiveState"] != "active"
        or live["Job"]
        or live["MainPID"] != str(writer["pid"])
        or live["InvocationID"] != writer["invocation_id"]
    ):
        return None  # Single writer is moving; its committed activation or next observation wakes this listener.
    return ref, package, writer, booker, version


def activation_event(event, route):
    if (
        route[4] != 47
        or event.get("_SYSTEMD_INVOCATION_ID") != route[2]["invocation_id"]
    ):
        return False
    message = event.get("MESSAGE", "")
    return message.startswith('{"epoch143_writer_active":') and json.loads(message) == {
        "epoch143_writer_active": route[0]
    }


def main():
    phase_ref = checked(LISTENER)["phase"]
    phase = checked(phase_ref)
    if sys.argv[1:] == ["--check-entry"]:
        route = resolve()
        need(route is not None, "no active writer for the 143 listener")
        print(
            json.dumps(
                dict(
                    phase=phase_ref,
                    writer=route[0],
                    package=route[1],
                    version=route[-1],
                )
            )
        )
        return
    need(not sys.argv[1:], "unexpected listener arguments")
    # Subscribe first, then reconcile the durable assembly terminal. Events arriving
    # during package or writer turnover are replayed by systemd's journal.
    since = f"@{int(time.time()) - 1}"
    args = [
        "/usr/bin/journalctl",
        "-q",
        "--no-pager",
        "-o",
        "json",
        "--follow",
        "--no-tail",
        "--since",
        since,
        "-u",
        original.ASSEMBLY,
        "-u",
        original.OBSERVER,
    ]
    with subprocess.Popen(args, text=True, stdout=subprocess.PIPE) as journal:
        try:
            route = resolve()
            if (
                route
                and original.close_phase(phase_ref, phase)
                and original.start(route[0], route[1], route[3], route[4])
            ):
                return
            for line in journal.stdout:
                event = json.loads(line)
                route = resolve()
                if route and (
                    original.terminal_event(event, phase)
                    or original.observer_event(event, route[2])
                    or activation_event(event, route)
                ):
                    if original.close_phase(phase_ref, phase) and original.start(
                        route[0], route[1], route[3], route[4]
                    ):
                        return
            raise ValueError("143 native event stream ended")
        finally:
            journal.terminate()


if __name__ == "__main__":
    main()
