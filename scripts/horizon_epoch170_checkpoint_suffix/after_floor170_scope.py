"""Publish the qualified service, input custody and independent checkpoints as one writer interface."""
from pathlib import Path

import after_floor170_hourly as hourly
import following_prepare as f

SCOPE = hourly.ROOT / "AFTER_FLOOR_WRITER_INTERFACE.json"


def document():
    root = hourly.ROOT
    prior = f.read(hourly.prior.SCOPE)
    source_ref = f.reference(root / "package/hourly-source.json")
    source = f.read(source_ref)
    f.need(source == hourly.source(), "different source-exact hourly interval")
    layout_ref = f.reference(root / "LAYOUT.json")
    layout = f.read(layout_ref)
    namespace = f.reference(root / "NAMESPACE.json")
    parser = f.reference(root / "NATIVE_PREFLIGHT.json")
    ns, entry = f.read(namespace), f.read(parser)
    f.need(entry["route_accepted"] and not entry["worker_executed"] and entry["scope"] == [source["first"], source["last"]]
           and entry["namespace"] == namespace and entry["layout"] == ns["layout"] == layout_ref
           and entry["service"] == ns["unit"] == layout["service"] and entry["seal"] == ns["seal"] == layout["seal"]
           and ns["report"]["residency"]["realized_bytes"] > 0 and ns["report"]["fixture_guard_only"]
           and ns["wrong_tmpfs_size_refused"] and ns["no_host_scratch_payload"], "unqualified source or private workspace")
    profile = dict(prior["profile"], first=source["first"], last=source["last"], bootstrap=hourly.FIRST,
                   checkpoints=[source["endpoints"][-1]["name"]], positions=source["positions"],
                   host_unit=hourly.UNIT, namespace=namespace, sealed_package=layout["seal"],
                   scratch_noswap_tmpfs_bytes=hourly.TMPFS, producer_memory_bytes=hourly.RAM,
                   new_home_total_bytes=hourly.HOME, new_control_bytes=64<<20)
    guard = hourly.UNIT.replace("-qualify-", "-guard-")
    return dict(schema="horizon-170-after-floor-hourly-writer-interface-v1", profile=profile, source_packet=source_ref,
                preceding_disk_interface=hourly.prior.SCOPE, stopped_custody=hourly.STOP, stopped_drain=hourly.DRAIN,
                scratch_retirement=hourly.RETIRE, predecessor=hourly.PREDECESSOR,
                retained_comparison=f.read(hourly.PREDECESSOR)["comparison"], following_input=source["immutable_bootstrap"],
                expected_producer_unit=hourly.UNIT, expected_guard_unit=guard, expected_guard_timer=guard.replace(".service",".timer"),
                bootstrap=hourly.FIRST, first_new_slot=source["first"], last=source["last"], recording="private",
                run=layout["run"], log=str(Path(layout["run"])/"producer.log"), barrier=str(root/"barrier/allow"),
                guard_receipts=str(root/"guard-receipts"), namespace=namespace, layout=layout_ref,
                fixture=f.reference(root/"GUARD_STATIC_FIXTURE.json"), source_preflight=parser,
                guard_sha=f.reference(root/"package/guard")["sha256"], guard_seal=layout["seal"],
                actor_path=str(root/"SUCCESSOR_ACTOR.json"), release_path=str(root/"SUCCESSOR_RELEASE.json"),
                plan_path=str(root/"ACTUAL_GUARD_PLAN.json"), enrollment_path=str(root/"WRITER_ENROLLMENT.json"),
                held_gate_before_worker=True, native_enrollment_needed=True, admission_or_release=False, publication_authorized=False)
