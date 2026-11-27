"""Hand the serial slot to closed epoch 186 lane M after 185 and the seventh 141 input."""

import ctypes
import json
import os
from pathlib import Path
import sys
import time

RT = Path("/var/lib/jetstreamer/horizon_runtime_data")
state = RT / "epoch186-closed-partial-rotation-20261127-v1"
tools = state / "tools"
sys.path.insert(0, str(tools))
import dispatch
import rotation as op

PRIOR = op.PREVIOUS / "SERIAL_RETURN.json"
SEVENTH = op.SEVEN / "ANZA_SERIAL_HANDBACK.json"


def wait_for_files(paths):
    # Install directory watches before testing the files. Handle direct writes and
    # atomic promotion. An already-recorded handback requires no wakeup.
    libc = ctypes.CDLL(None, use_errno=True)
    fd = libc.inotify_init1(os.O_CLOEXEC)
    if fd < 0:
        raise OSError(ctypes.get_errno(), "inotify_init1")
    try:
        for root in {p.parent for p in paths}:
            if (
                libc.inotify_add_watch(
                    fd,
                    os.fsencode(root),
                    0x00000008 | 0x00000080 | 0x00000002 | 0x00000004,
                )
                < 0
            ):
                raise OSError(ctypes.get_errno(), "inotify_add_watch")
        while True:
            try:
                if all(isinstance(op.read(p), dict) for p in paths):
                    return
            except (FileNotFoundError, json.JSONDecodeError):
                pass
            os.read(fd, 16384)
    finally:
        os.close(fd)


def main():
    run = os.environ["INVOCATION_ID"]
    target = state / "m"
    op.need(len(run) == 32, "missing native invocation")
    op.fixed(
        tools / "deployment-seal-receipt.json",
        "17f13c755f85cdb004261f5078ce6d421da444e8a7c04dc6c971a952754624a8",
    )
    op.fixed(
        state / "QUALIFIED_HANDOFF.json",
        "b7d1925a8c9828b061fd8440814e3d8395ce80a2613556e487eac8e5f9c57023",
    )
    arm = state / "sequence-evidence" / ("WATCH_" + run + ".json")
    op.save(
        arm,
        dict(
            invocation=run,
            observed=time.time(),
            expected=[str(PRIOR), str(SEVENTH)],
            lane="m",
            actions=["park", "retire"],
        ),
    )
    wait_for_files([PRIOR, SEVENTH])
    handoffs = op.serial_handoff()
    prior = op.bound(handoffs[0])
    seventh = op.bound(handoffs[1])
    p = op.bound(seventh["transfer"])
    c = op.bound(p["native_custody"])
    op.need(
        p["bytes"] == 2588354467
        and p["remote_whole_sha256_readback"]
        and c["remote_sha256_readback"]
        and c["local_source_revalidated"]
        and p["sha256"] == c["sha256"],
        "seventh authenticated proof changed",
    )
    op.need(
        op.bound(prior["park"])["native_custody"]
        == op.bound(prior["reclamation"])["native_custody"],
        "185 handback changed",
    )
    for name, row in seventh["units"].items():
        st = (
            op.consumers.states([name])[0]
            if row["current"]["LoadState"] != "not-found"
            else None
        )
        op.need(
            op.bound(row["terminal"])["success"]
            and (
                st is None
                or st["ActiveState"] == "inactive"
                and st["MainPID"] == st["ControlPID"] == "0"
                and not st["Job"]
            ),
            "seventh unit not drained",
        )
    op.save(
        state / "sequence-evidence" / ("TRIGGER_" + run + ".json"),
        dict(
            watch=op.ref(arm),
            receipts=handoffs,
            seventh_native=p["native_custody"],
            utc=time.time(),
        ),
    )
    # The actual dispatcher prices each phase and takes the campaign lock in its
    # normal entry. Restrict this event to M so 168 can be repriced immediately.
    park = dispatch.dispatch("park", "m")
    terminal = op.bound(park)
    op.need(
        terminal["success"]
        and op.bound(terminal["native_custody"])["remote_sha256_readback"],
        "lane M missing native custody",
    )
    retire = dispatch.dispatch("retire", "m")
    release = op.bound(retire)
    op.need(
        release["success"]
        and release["allocated_bytes_removed"] == 42990256128
        and not Path(op.source("m")["source"]).exists(),
        "missing measured lane M release",
    )
    out = state / "M_SERIAL_HANDBACK.json"
    if not out.exists():
        op.save(
            out,
            dict(
                utc=time.time(),
                return_to="campaign controller",
                source_lane="m",
                park=park,
                retirement=retire,
                measured_net_free_bytes=release["measured_net_free_bytes"],
                conservative_capacity_bytes=release["conservative_capacity_bytes"],
                allocated_bytes_removed=release["allocated_bytes_removed"],
                restore_peak=op.read(target / "expected.json")["single_copy_peak"],
                invocation=run,
                epoch168_reprice_pending=True,
                lane_n_dispatched=False,
            ),
        )
    print(json.dumps(op.ref(out)), flush=True)


if __name__ == "__main__":
    main()
