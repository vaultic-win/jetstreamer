"""Preserve the exact V52 hold stopped before the epoch 143 permit."""

import argparse
import fcntl
import json
import os
import stat
import subprocess
import time

from reconcile_failed143_gate import GUARD, LOCK, RT, RUN, UNIT
from reconcile_failed143_gate import digest, drained_namespace, journal, locate, move, need, put, ref

IID = "c643e4e61d0f4b7eb59448824c86bc59"
BOOKING = RT / "WRITER_BOOKING_FIRST_HOURLY_1795832015802833072.json"
BOOKING_SHA = "8ea92dafc87a4279910eb160d41660badcf2edc2e57a8412c43e9bbbdc42bfed"
ACTIVE_SHA = "ede08352a67056909967fa5961c1b19987ab894a8a46a0514e5613d9cc5e086b"
PLAN_SHA = "c765924fa4597bfa307921aab8bac8702e05e8784d841644d4addfd72c4e8707"
SCREEN_SHA = "959e6cb3b27175afb3d6aaa112bf3fe16daaa06c46f533588c86f8b7cb288e5a"
SAMPLES = {
    "d7322732251649dfab1b0cc776bf70b8": "c67d5c7c69a16af1d022bb7463b0941ddde7c4c1e46b690044b7e23d158e986d",
    "9a8923fef34e41f4a87bdeec2054d183": "7c8b5fc7a949d98c3fa5cf405225af9d3068d7a0639eac52ab1c769f9b8b8b4c",
}
FAILED = RT / f"failed-{IID}"
OLD_RUN = RUN.with_name(f"{RUN.name}.failed-{IID}")


def reconcile(apply):
    state = drained_namespace()
    need(not any(os.path.lexists(RT / p) for p in ("HELD_OWNER.json", "POST_GUARD_SCREEN.json", "barrier/allow")),
         "the V52 attempt has release evidence")
    need(not list(RT.glob("POST_GUARD_SCREEN.refused-*.json")),
         "a recorded held quote changed the failed V52 scope")
    booking_ref = ref(BOOKING)
    booking = json.loads(BOOKING.read_bytes())
    need(booking_ref["sha256"] == BOOKING_SHA and booking["writer_active"]["sha256"] == ACTIVE_SHA
         and booking["unit"] == UNIT and booking["latest_start_unix_seconds"] < time.time(),
         "different or unexpired V52 booking")
    items = {name: (RT / name, FAILED / name) for name in
             ("PRESTART_SCREEN.json", "ACTUAL_GUARD_PLAN.json", "guard-receipts", "barrier")}
    screen, plan, receipts, barrier = (locate(*paths) for paths in items.values())
    run = locate(RUN, OLD_RUN)
    need((digest(screen), digest(plan)) == (SCREEN_SHA, PLAN_SHA)
         and json.loads(plan.read_bytes())["invocation_id"] == IID
         and set(p.relative_to(run).as_posix() for p in run.rglob("*")) ==
         {"ledger", "ledger/genesis.tar.bz2", "private", "scratch"}
         and (run / "ledger/genesis.tar.bz2").stat().st_size == 0 and not list(barrier.iterdir())
         and {p.name for p in receipts.iterdir()} == {f"sample-{iid}.json" for iid in SAMPLES},
         "V52 retained attempt changed or wrote replay output")
    for iid, sha in SAMPLES.items():
        path = receipts / f"sample-{iid}.json"
        sample = json.loads(path.read_bytes())
        need(digest(path) == sha and sample["producer_invocation_id"] == IID
             and sample["guard_invocation_id"] == iid and sample["plan_sha256"] == PLAN_SHA
             and sample["producer_stop_enabled"] and sample["workers"] == []
             and sample["trip_reason"] is sample["root_physical_observation_error"] is sample["worker_observation_error"] is None,
             "V52 guard evidence changed")
    rows = {"producer": journal(UNIT, IID),
            "guards": {iid: journal(GUARD + ".service", iid) for iid in SAMPLES}}
    for seq in (rows["producer"], *rows["guards"].values()):
        need(any(row.get("MESSAGE_ID") == "7ad2d189f7e94e70a38c781354912448" for row in seq),
             "a V52 invocation has no clean PID1 terminal event")
    stdout = subprocess.check_output(
        ["/usr/bin/journalctl", "-b", "--quiet", "--no-pager", "-o", "json", "_SYSTEMD_INVOCATION_ID=" + IID],
        text=True, timeout=15,
    )
    rows["gate"] = [json.loads(line) for line in stdout.splitlines()]
    need(len(rows["gate"]) == 2
         and "inode=118554661 bytes=3714834246" in rows["gate"][0]["MESSAGE"]
         and f"invocation {IID} waiting at most 180 seconds" in rows["gate"][1]["MESSAGE"],
         "corrected snapshot gate or wait evidence changed")
    if not apply:
        return dict(native=state, pid1=rows, expired_booking=booking_ref, release_absent=True,
                    prestart=ref(screen), guard_plan=ref(plan))
    FAILED.mkdir(mode=0o700, exist_ok=True)
    need(FAILED.resolve(strict=True) == FAILED and FAILED.stat().st_uid == 0
         and stat.S_IMODE(FAILED.stat().st_mode) == 0o700, "unsafe V52 attempt archive")
    terminal = FAILED / "PID1_TERMINALS.json"
    if not terminal.exists():
        put(terminal, rows)
    else:
        need(json.loads(terminal.read_bytes()) == rows, "V52 stored journal changed")
    for old, new in items.values():
        move(old, new)
    move(RUN, OLD_RUN)
    return put(FAILED / "RECONCILED.json", dict(
        schema="horizon-epoch143-unreleased-gate-reconciled-v2", failed_invocation=IID,
        expired_booking=booking_ref, pid1=ref(terminal), native=state, release_absent=True,
        prestart_screen=ref(FAILED / "PRESTART_SCREEN.json"), guard_plan=ref(FAILED / "ACTUAL_GUARD_PLAN.json"),
        guard_samples={iid: ref(FAILED / "guard-receipts" / f"sample-{iid}.json") for iid in SAMPLES},
        failed_HOME_tree=str(OLD_RUN), archive_created=False, resource_credit_bytes=0,
        reconciled_unix_seconds=int(time.time())))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--check", action="store_true")
    modes.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    need(os.geteuid() == 0, "V52 reconciliation requires root")
    os.umask(0o077)
    with LOCK.open("rb") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        completed = FAILED / "RECONCILED.json"
        print(json.dumps(ref(completed) if completed.exists() else reconcile(args.apply)))
