"""Close the first epoch 143 interval against native exit, checkpoint and independent reread."""

import json
import os
from pathlib import Path
import re
import runpy
import subprocess
import sys
import time

watch = runpy.run_path(str(Path(__file__).with_name("epoch143-hourly-exit.py")))
helper, require, root, dest, unit, iid = (watch[k] for k in ("helper", "require", "ROOT", "DEST", "UNIT", "IID"))
GUARD = "horizon-guard-143-first-hourly-20261127-v1"
BOOTSTRAP, TERMINAL, OUTPUT_START = 61775538, 61787631, 61776000
WORKER = "2cca500106d274ebfbbc8c5bfa0e6e8343cd5e41003f9e82c93282800732d8c8"
VERIFIER = Path("/usr/local/lib/jetstreamer/horizon-epoch157-retained-prefix-validator-20261021-v1/jetstreamer-qualification-verify")
VERIFIER_SHA = "b075d4548224cd3ca01f6f7bb441d835b7db4dd769136065d0b516fdeceac582"
VERIFIER_UNIT = "horizon-validate-143-first-hourly-20261128-v1.service"
VALIDATION = dest / "epoch143-through-61787631.validation.json"
ALIAS = dest / "projection" / "epoch-143-through-61787631.jet"
CHECKPOINT = re.compile(
    r"\] historical checkpoint slot=(\d+) bank_hash=(\w+) accounts_hash=(\w+) last_blockhash=(\w+) "
    r"capitalization=(\d+) transactions=(\d+) tick_height=(\d+) complete=(true|false) writes=(\d+) next_write_version=(\d+)$"
)


def associated_exit(actor, binds):
    armed, arm_ref = helper.read(dest / "ARMED.json", 0)
    exit_record, exit_ref = helper.read(dest / "PID1_EXIT.json", 0)
    state = exit_record["properties"]
    require(armed["unit_reference_held"] and armed["pidfd_bound"]
            and armed["actor"] == exit_record["actor"] == actor and armed["bindings"] == exit_record["bindings"] == binds
            and exit_record["armed"] == arm_ref and state["Id"] == unit
            and state["InvocationID"] == iid and state["ActiveState"] == "inactive"
            and (state["Result"], state["ExecMainCode"], state["ExecMainStatus"]) == ("success", "1", "0")
            and state["MainPID"] == state["ControlPID"] == "0"
            and state["ExecMainPID"] == str(actor["producer_pid"])
            and not Path("/sys/fs/cgroup/system.slice", unit, "cgroup.procs").exists(),
            "first hourly producer did not exit cleanly and drain")
    fields = "Id,ActiveState,InvocationID,MainPID,ControlPID,Job"
    for name in (unit, GUARD + ".timer", GUARD + ".service"):
        row = helper.native_properties(name, fields)
        require(row["Id"] == name and row["ActiveState"] in ("inactive", "failed") and not row["Job"]
                and row.get("MainPID", "0") == row.get("ControlPID", "0") == "0"
                and not Path("/sys/fs/cgroup/system.slice", name, "cgroup.procs").exists(),
                "production scope has not drained: " + name)
    helper.inactive(GUARD + ".timer")
    helper.GUARD = GUARD
    guard = helper.guard_drain(dict(exit_timestamp_monotonic_usec=int(state["ExecMainExitTimestampMonotonic"]),
                                    boot_id=actor["boot_id"]))
    require(not any((root / "guard-receipts" / x).exists() for x in ("stop-intent.json", "stop-completion.json")),
            "guard stopped the recorder")
    return exit_ref, state, guard


def journal_checkpoints(actor, state, manifest_path):
    output = subprocess.check_output(
        ["/usr/bin/journalctl", "--quiet", "--no-pager", "-o", "json",
         f"--grep=historical checkpoint slot=({BOOTSTRAP}|{TERMINAL}) |published verified historical segment evidence",
         "_BOOT_ID=" + actor["boot_id"].replace("-", ""), "_PID=" + str(actor["producer_pid"]),
         "_SYSTEMD_UNIT=" + unit, "_SYSTEMD_INVOCATION_ID=" + iid],
        text=True, timeout=60)
    checkpoints, completed = {}, []
    lower = int(state["ExecMainStartTimestampMonotonic"])
    upper = int(state["ExecMainExitTimestampMonotonic"])
    for line in output.splitlines():
        row = json.loads(line)
        require(lower <= int(row["__MONOTONIC_TIMESTAMP"]) <= upper, "journal outside exact native invocation")
        message = row["MESSAGE"]
        match = CHECKPOINT.search(message)
        if match is None:
            require(message.endswith("published verified historical segment evidence " + str(manifest_path)),
                    "different manifest in native completion")
            completed.append(row["__CURSOR"])
            continue
        slot, bank, accounts, block, capital, txs, tick, complete, writes, cursor = match.groups()
        checkpoint = dict(slot=int(slot), bank_hash=bank, accounts_hash=accounts, last_blockhash=block,
                          capitalization=int(capital), transaction_count=int(txs), tick_height=int(tick),
                          slot_complete=complete == "true", write_count=int(writes), next_write_version=int(cursor))
        require(int(slot) not in checkpoints or checkpoints[int(slot)]["checkpoint"] == checkpoint,
                "inconsistent checkpoints under one native invocation")
        checkpoints[int(slot)] = dict(checkpoint=checkpoint, cursor=row["__CURSOR"])
    require(set(checkpoints) == {BOOTSTRAP, TERMINAL} and len(completed) == 1, "incomplete native checkpoint journal")
    return checkpoints, completed[0]


def identity(path):
    s = path.stat(follow_symlinks=False)
    return (s.st_dev, s.st_ino, s.st_size, s.st_ctime_ns, s.st_mtime_ns)


def boundary_manifest(source, archive):
    path = archive.with_name(archive.name + ".segment.json")
    manifest, ref = helper.read(path, 1001)
    count = TERMINAL - OUTPUT_START + 1
    require(manifest["schema_version"] == 1 and manifest["epoch"] == 143 and manifest["output_slot_start"] == OUTPUT_START
            and manifest["output_slot_count"] == count and manifest["runtime"]["runtime_profile"] == source["runtime"]
            and manifest["worker_executable_sha256"] == source["images_and_genesis"]["worker"]["sha256"] == WORKER
            and manifest["bootstrap_archive_sha256"] == source["bootstrap"]["sha256"]
            and manifest["bootstrap"]["slot"] == source["bootstrap"]["slot"] == BOOTSTRAP
            and manifest["terminal"]["slot"] == source["terminal"]["slot"] == TERMINAL
            and manifest["terminal"]["accounts_hash"] == source["terminal"]["accounts_hash"]
            and manifest["bootstrap"]["slot_complete"] and manifest["terminal"]["slot_complete"]
            and manifest["bootstrap"]["write_count"] == 0 and not os.path.lexists(archive.with_suffix(".jet.sha256")),
            "different scope, runtime, checkpoint or canonical sidecar")
    return path, manifest, ref


def scan(archive, manifest_path):
    binary, _ = helper.file_ref(VERIFIER, 0)
    require(binary["sha256"] == VERIFIER_SHA, "different independent verifier")
    alias_manifest = ALIAS.with_name(ALIAS.name + ".segment.json")
    projection = [(archive, ALIAS), (manifest_path, alias_manifest)]
    cmd = ["/usr/bin/systemd-run", "--wait", "--pipe", "--quiet", "--unit=" + VERIFIER_UNIT,
           "--property=Type=oneshot", "--property=TimeoutStartSec=35min", "--property=Restart=no",
           "--setenv=RAYON_NUM_THREADS=1", "--property=MemoryMax=4G", "--property=MemorySwapMax=0", "--property=CPUQuota=100%",
           "--property=TasksMax=32", "--property=ProtectSystem=strict", "--property=ProtectHome=read-only",
           "--property=PrivateTmp=yes", "--property=PrivateNetwork=yes", "--property=NoNewPrivileges=yes",
           "--property=ReadWritePaths=" + str(dest)]
    cmd += ["--property=BindReadOnlyPaths=" + str(src) + ":" + str(alias) for src, alias in projection]
    cmd += ["--", str(VERIFIER), str(ALIAS), "--private-root=" + str(ALIAS.parent),
            "--expected-epoch=143", f"--expected-output-start-slot={OUTPUT_START}",
            f"--expected-bootstrap-slot={BOOTSTRAP}", f"--expected-terminal-slot={TERMINAL}",
            "--expected-runtime-profile=solana-v1.4.25", "--expected-worker-sha256=" + WORKER,
            "--receipt=" + str(VALIDATION)]
    subprocess.run(cmd, check=True, timeout=2200)
    return binary


def accept(scan_if_needed):
    actor, bindings, source, contract = watch["frozen"]()
    terminal_ref, state, guard = associated_exit(actor, bindings)
    archive = Path(contract["prepared_output_file"])
    mp, manifest, manifest_ref = boundary_manifest(source, archive)
    before = identity(archive), identity(mp)
    checkpoints, completion = journal_checkpoints(actor, state, mp)
    require(manifest["bootstrap"] == checkpoints[BOOTSTRAP]["checkpoint"]
            and manifest["terminal"] == checkpoints[TERMINAL]["checkpoint"], "manifest differs from native checkpoints")
    if not scan_if_needed:
        return dict(exit=terminal_ref, guard=guard, checkpoint=checkpoints[TERMINAL], manifest=manifest_ref)
    verifier = scan(archive, mp)
    proof, proof_ref = helper.read(VALIDATION, 0)
    require(proof["validation"] == "pass" and proof["archive"] == str(ALIAS)
            and proof["archive_bytes"] == before[0][2] and proof["archive_sha256"] == manifest["archive_sha256"]
            and proof["output_slot_count"] == manifest["output_slot_count"]
            and proof["canonical_checksum_sidecar_absent"] and before == (identity(archive), identity(mp))
            and helper.file_ref(mp, 1001)[0] == manifest_ref,
            "independent validation did not bind unchanged archive and manifest")
    helper.AUTHORITY = dest
    path = dest / "PRIVATE_FIRST_HOURLY_ACCEPTANCE.json"
    helper.persist(path, dict(schema="horizon-143-private-first-hourly-acceptance-v1", epoch=143,
        producer_invocation_id=iid, native_terminal=terminal_ref, guard_drain=guard, bindings=bindings,
        archive=dict(path=str(archive), sha256=manifest["archive_sha256"]), archive_bytes=before[0][2],
        segment_manifest=manifest_ref, verifier=verifier, independent_validation=proof_ref,
        checkpoints=checkpoints, verified_manifest_journal_cursor=completion,
        output_slot_start=OUTPUT_START, output_slot_count=manifest["output_slot_count"],
        terminal_slot=TERMINAL, recorded_unix_seconds=time.time(), publication_authorized=False, resource_credit_bytes=0))
    return helper.file_ref(path, 0)[0]


if __name__ == "__main__":
    require(sys.argv[1:] in (["check"], ["accept"]), "expected check or accept")
    print(json.dumps(accept(sys.argv[1] == "accept")), flush=True)
