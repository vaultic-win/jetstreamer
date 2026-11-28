"""The fourth bounded window starts at the previous private segment's last checkpoint."""

from pathlib import Path
import stat

from evidence import BASE, bound, checked, need
import continuation170_retry_contract as predecessor

ROOT = BASE / "epoch170-from-73766969-20261127-v1"
INTERFACE = dict(
    path=str(ROOT / "BOUNDED_SUCCESSOR_WRITER_INTERFACE.json"),
    sha256="6b0e1674cb45059761c95b312fbbb478a80ed1a0ab22dcee22a55cbfc03efb40",
)
UNIT = "horizon-qualify-170-from-73766969-20261127-v1.service"
TIMER = "horizon-guard-170-from-73766969-20261127-v1.timer"
PREVIOUS_IID = "c3ab30cfeb05428bb8f5c48a5a44822c"
CHECKPOINTS = (
    (73746882, "UjWmG6TowgFrbT6Ntd1vcH9m4E6LXX9AsaVG8727mW6"),
    (73753554, "H2N735BwDow5DsyhJX58KiVnvpFiNtDuJpagw2zjkMu4"),
    (73760367, "7gcF7iqN9FvU2JrCkdqX7DmeV1X1AvZaGYoJjrLkCrsF"),
    (73766969, "9mYMWeKx1ZWjsBcGLUhmDGbdkY2GMCmdFnE6UxfAeQjW"),
)
SIGNED = (
    "701d627d08c1c2ba956f51f0db47b0a20c1fd504359cb4e8b05f0723d03e61dc",
    "a7339abbeb10539faf4a0554ada23007044dd63991f850398a20fc05aaeb642e",
    "f30e1752318adbf5f697f1fd4d13969006452d9f42b17961964df4760ef45c2c",
    "37b6c60c61404dc19a58ca6a34f42091aea35509fd2bbb8c8d520fa660ae3d42",
)


def interface():
    scope = checked(INTERFACE)
    handoff = checked(scope["handoff"])
    proof = checked(scope["source_preflight"])
    profile = scope["profile"]
    previous = predecessor.interface()
    need(
        scope["schema"] == "horizon-170-bounded-continuation-writer-interface-v2"
        and scope["handoff"] == scope["closed_terminal_handoff"]
        and handoff["live_owner"] == scope["old_actor"]
        and handoff["original_release"] == scope["old_release"]
        and handoff["original_interface"] == predecessor.INTERFACE
        and (scope["bootstrap"], scope["first_new_slot"], scope["last"])
        == (73766969, 73766970, 73787145)
        and scope["bootstrap"] == previous["last"]
        and profile["positions"] == 20176
        and profile == handoff["profile"]
        and profile["host_unit"] == scope["expected_producer_unit"] == UNIT
        and scope["expected_guard_timer"] == TIMER
        and scope["expected_guard_unit"] == TIMER.replace(".timer", ".service")
        and scope["closed_comparison"]
        == handoff["closed_compare"]
        == str(ROOT / "CLOSED_PREDECESSOR_COMPARISON.json")
        and proof["namespace"] == scope["namespace"]
        and proof["scope"] == [73766970, 73787145]
        and scope["guard_seal"] == profile["sealed_package"]
        and scope["held_gate_before_worker"]
        and scope["native_enrollment_needed"]
        and proof["route_accepted"]
        and scope["admission_or_release"]
        is proof["worker_executed"]
        is handoff["publication_authorized"]
        is False
        and scope["recording"] == "private",
        "different fourth bounded epoch 170 interface",
    )
    return scope


def previous_owner(row, scope, terminal=False):
    need(
        row
        and row["interface"] == predecessor.INTERFACE
        and row["actor_ref"] == scope["old_actor"]
        and row["release"] == scope["old_release"]
        and row["actor"]["producer_invocation_id"] == PREVIOUS_IID
        and row["archive_publication_authorized"] is False,
        "different preceding bounded epoch 170 owner",
    )
    if terminal:
        need(
            row["phase"] == "terminal" and row.get("native_terminal"),
            "epoch 170 predecessor has not closed cleanly",
        )
        native = row["native_terminal"]
        need(
            native["INVOCATION_ID"] == PREVIOUS_IID
            and native["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448"
            and native["UNIT"] == row["actor"]["unit"]
            and native["_PID"] == "1"
            and native["_UID"] == "0",
            "epoch 170 predecessor has not closed cleanly",
        )
    return row


def closed_comparison(scope):
    ref = bound(Path(scope["closed_comparison"]))
    report = checked(ref)
    evidence = report["evidence"]
    segment = evidence["closed_segment"]
    old = predecessor.interface()
    archive = Path(old["run"]) / "ledger/epoch-170.diagnostic.jet"
    manifest_ref = segment["manifest"]
    path = Path(manifest_ref["path"])
    meta = path.lstat()
    need(
        segment["path"] == str(archive)
        and path == archive.with_name(archive.name + ".segment.json")
        and path.resolve(strict=True) == path
        and stat.S_ISREG(meta.st_mode)
        and meta.st_nlink == 1
        and (meta.st_uid, meta.st_gid, stat.S_IMODE(meta.st_mode))
        == (1001, 1003, 0o600),
        "different predecessor segment custody",
    )
    manifest = checked(manifest_ref, root=False)
    verify_comparison(scope, report, manifest)
    return ref


def verify_comparison(scope, report, manifest):
    evidence = report["evidence"]
    segment = evidence["closed_segment"]
    terminal = evidence["pid1_exit"]["native"]
    previous = checked(scope["old_release"])
    signed_dir = Path(predecessor.interface()["guard_seal"]["path"]).parent
    refs = [
        dict(path=str(signed_dir / f"reference-{slot}.json"), sha256=digest)
        for (slot, _), digest in zip(CHECKPOINTS, SIGNED, strict=True)
    ]
    need(
        evidence["signed_checkpoints"] == refs
        and evidence["signed_endpoint"] == refs[-1]
        and report["predecessor"] == previous["closed_comparison"],
        "different preceding private comparison or signed votes",
    )
    points = report["checkpoints"]
    need(
        report["schema"] == "horizon-170-successor-closed-checkpoint-comparison-v1"
        and report["release"] == scope["old_release"]
        and report["actor"] == scope["old_actor"]
        and report["interface"] == predecessor.INTERFACE
        and evidence["comparison"] == "closed"
        and terminal["InvocationID"] == PREVIOUS_IID
        and terminal["Result"] == "success"
        and terminal["ExecMainCode"] == "1"
        and terminal["ExecMainStatus"] == "0"
        and tuple((p["slot"], p["accounts_hash"]) for p in points) == CHECKPOINTS
        and all(p["slot_complete"] for p in points)
        and manifest["terminal"] == points[-1]
        and manifest["archive_sha256"] == segment["sha256"]
        and manifest["output_slot_start"] == 73746883
        and manifest["output_slot_count"] == 20087
        and report["canonical_publication_authorized"] is False,
        "missing exact fourth-window predecessor closure",
    )
    for point, ref in zip(points, refs, strict=True):
        vote = checked(ref)
        need(
            all(
                vote[key] == point[key]
                for key in ("slot", "bank_hash", "last_blockhash")
            ),
            "different signed checkpoint",
        )
