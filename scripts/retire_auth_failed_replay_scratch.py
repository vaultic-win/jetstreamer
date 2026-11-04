#!/usr/bin/env python3
"""Retire empty scratch trees from sealed replays stopped by GCloud auth failure.

The root-owned plan is the only command-line path.  This helper accepts only
cursor-free runs whose input and archive directories are empty, whose exact
producer invocation logged the non-interactive reauthentication failure, and
whose controller assignment is durably failed.  It preserves every run
directory and all non-scratch evidence.  It never accesses remote storage.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any, Sequence

if __package__:
    from scripts import retire_reboot_interrupted_replay_scratch as base
else:
    import retire_reboot_interrupted_replay_scratch as base


PLAN_SCHEMA = "jetstreamer-auth-failed-scratch-retirement-plan-v1"
INTENT_SCHEMA = "jetstreamer-auth-failed-scratch-retirement-intent-v1"
COMPLETION_SCHEMA = "jetstreamer-auth-failed-scratch-retirement-completion-v1"
RUN_STATE_SCHEMA = "jetstreamer-root-cohort-run-v1"
AUTH_FAILURE = "Reauthentication failed. cannot prompt during non-interactive execution."
DOWNLOAD_FAILURE = "failed to download audited predecessor snapshot generation"
RUN_NAME = re.compile(r"^run-[0-9]+-[0-9]+$")


class RetirementError(RuntimeError):
    """A fail-closed authentication-failure retirement gate was not met."""


def require_empty_directory(path: Path, label: str, uid: int) -> dict[str, Any]:
    metadata = base.exact_directory(path, label, uid)
    try:
        entries = list(path.iterdir())
    except OSError as error:
        raise RetirementError(f"cannot enumerate {label} {path}: {error}") from error
    if entries:
        raise RetirementError(f"{label} is not empty: {path}")
    return {
        "path": str(path),
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
    }


def validate_failure_journal(boot_id: str, item: dict[str, Any]) -> dict[str, Any]:
    unit = item.get("producer_unit")
    invocation = item.get("producer_invocation_id")
    if (
        not isinstance(unit, str)
        or base.UNIT_NAME.fullmatch(unit) is None
        or not isinstance(invocation, str)
        or base.INVOCATION_ID.fullmatch(invocation) is None
    ):
        raise RetirementError("producer journal binding is invalid")
    completed = subprocess.run(
        [
            "/usr/bin/journalctl",
            f"--boot={boot_id}",
            f"_SYSTEMD_INVOCATION_ID={invocation}",
            "--output=json",
            "--no-pager",
            "--quiet",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    auth_entry: dict[str, Any] | None = None
    download_entry: dict[str, Any] | None = None
    count = 0
    for line in completed.stdout.splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as error:
            raise RetirementError("journal returned invalid JSON") from error
        if entry.get("_SYSTEMD_UNIT") != unit or entry.get("_SYSTEMD_INVOCATION_ID") != invocation:
            continue
        count += 1
        message = entry.get("MESSAGE")
        if isinstance(message, str) and AUTH_FAILURE in message:
            auth_entry = entry
        if isinstance(message, str) and DOWNLOAD_FAILURE in message:
            download_entry = entry
    if auth_entry is None or download_entry is None:
        raise RetirementError(f"bound authentication-failure journal evidence is absent for {unit}")
    return {
        "unit": unit,
        "invocation_id": invocation,
        "matching_entries": count,
        "auth_failure_realtime_micros": int(auth_entry["__REALTIME_TIMESTAMP"]),
        "download_failure_realtime_micros": int(download_entry["__REALTIME_TIMESTAMP"]),
        "auth_failure": AUTH_FAILURE,
        "download_failure": DOWNLOAD_FAILURE,
    }


def validate_run(item: dict[str, Any], *, allow_missing_scratch: bool) -> dict[str, Any]:
    start = item.get("start_epoch")
    end = item.get("end_epoch")
    run = Path(str(item.get("run_directory", "")))
    scratch = Path(str(item.get("scratch", "")))
    if (
        not isinstance(start, int)
        or isinstance(start, bool)
        or not isinstance(end, int)
        or isinstance(end, bool)
        or start < 0
        or end < start
        or not run.is_absolute()
        or RUN_NAME.fullmatch(run.name) is None
        or run.parent.name != f"root-cohort-{start}-{end}"
        or run.parent.parent.name != "work"
        or scratch != run / "scratch"
    ):
        raise RetirementError(f"run layout is invalid for {item.get('label')}")
    run_metadata = base.exact_directory(run, "cohort run")
    uid = run_metadata.st_uid
    state_path = run / "cohort-state.json"
    state_identity = base.file_identity(state_path, uid)
    if state_identity["mode"] != "0600" or base.sha256_file(state_path) != item.get("cohort_state_sha256"):
        raise RetirementError(f"cohort state identity changed: {state_path}")
    try:
        state = json.loads(state_path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise RetirementError(f"cannot read cohort state {state_path}: {error}") from error
    if (
        state.get("schema") != RUN_STATE_SCHEMA
        or state.get("status") != "running-private"
        or state.get("start_epoch") != start
        or state.get("end_epoch") != end
        or set(state) != {"schema", "status", "start_epoch", "end_epoch", "manifest_fingerprint"}
    ):
        raise RetirementError(f"cohort state is not cursor-free running-private: {state_path}")
    actual_names = {entry.name for entry in run.iterdir()}
    required = {"archives", "cohort-state.json", "inputs"}
    allowed = required | {"scratch"}
    if not required <= actual_names or actual_names - allowed:
        raise RetirementError(f"cohort run has unexpected entries: {sorted(actual_names)}")
    archives = require_empty_directory(run / "archives", "archives", uid)
    inputs = require_empty_directory(run / "inputs", "inputs", uid)
    scratch_identity = None
    scratch_bytes = None
    if scratch.exists() or scratch.is_symlink():
        scratch_identity = require_empty_directory(scratch, "scratch", uid)
        if scratch_identity["device"] != run_metadata.st_dev:
            raise RetirementError("scratch is on a different filesystem")
        scratch_bytes = base.physical_bytes(scratch)
    elif not allow_missing_scratch:
        raise RetirementError(f"scratch is absent before intent: {scratch}")
    return {
        "label": item.get("label"),
        "start_epoch": start,
        "end_epoch": end,
        "run_directory": str(run),
        "run_device": run_metadata.st_dev,
        "run_inode": run_metadata.st_ino,
        "run_uid": uid,
        "run_gid": run_metadata.st_gid,
        "run_mode": f"{stat.S_IMODE(run_metadata.st_mode):04o}",
        "cohort_state": {**state_identity, "sha256": base.sha256_file(state_path)},
        "archives": archives,
        "inputs": inputs,
        "scratch": str(scratch),
        "scratch_identity": scratch_identity,
        "scratch_physical_bytes": scratch_bytes,
    }


def validate_plan(plan: dict[str, Any]) -> None:
    if set(plan) != {"schema", "boot_id", "runs", "intent_receipt", "completion_receipt"}:
        raise RetirementError("retirement plan has an invalid shape")
    if plan.get("schema") != PLAN_SCHEMA or plan.get("boot_id") != base.read_boot_id():
        raise RetirementError("retirement plan does not bind the current boot")
    runs = plan.get("runs")
    if not isinstance(runs, list) or not 1 <= len(runs) <= 32:
        raise RetirementError("retirement plan must contain 1..32 runs")
    labels: set[str] = set()
    paths: set[str] = set()
    invocations: set[str] = set()
    required = {
        "label", "lane", "start_epoch", "end_epoch", "controller_unit",
        "controller_state", "controller_state_sha256", "producer_unit",
        "producer_invocation_id", "run_directory", "scratch", "cohort_state_sha256",
    }
    for item in runs:
        if not isinstance(item, dict) or set(item) != required:
            raise RetirementError("retirement run has an invalid shape")
        label = item.get("label")
        path = item.get("scratch")
        invocation = item.get("producer_invocation_id")
        if (
            not isinstance(label, str) or label in labels
            or not isinstance(path, str) or path in paths
            or not isinstance(invocation, str) or invocation in invocations
            or base.UNIT_NAME.fullmatch(str(item.get("controller_unit", ""))) is None
            or base.UNIT_NAME.fullmatch(str(item.get("producer_unit", ""))) is None
            or base.SHA256.fullmatch(str(item.get("controller_state_sha256", ""))) is None
            or base.SHA256.fullmatch(str(item.get("cohort_state_sha256", ""))) is None
        ):
            raise RetirementError("retirement run bindings are invalid or duplicated")
        labels.add(label)
        paths.add(path)
        invocations.add(invocation)


def stable_evidence(plan_path: Path, plan_sha256: str, plan: dict[str, Any], *, allow_missing: bool) -> dict[str, Any]:
    units: dict[str, dict[str, Any]] = {}
    states: dict[str, dict[str, Any]] = {}
    journals: list[dict[str, Any]] = []
    runs: list[dict[str, Any]] = []
    for item in plan["runs"]:
        for key in ("controller_unit", "producer_unit"):
            unit = item[key]
            units.setdefault(unit, base.parse_unit_state(unit))
        state_path = item["controller_state"]
        states.setdefault(state_path, base.validate_controller_state({**item, "assignment_phase": "failed"}))
        journals.append(validate_failure_journal(plan["boot_id"], item))
        runs.append(validate_run(item, allow_missing_scratch=allow_missing))
    tool = Path(__file__).resolve(strict=True)
    common_tool = Path(base.__file__).resolve(strict=True)
    return {
        "plan": str(plan_path),
        "plan_sha256": plan_sha256,
        "boot_id": plan["boot_id"],
        "units": [units[name] for name in sorted(units)],
        "controller_states": [states[name] for name in sorted(states)],
        "failure_journals": journals,
        "runs": runs,
        "retirement_tool": {"path": str(tool), "sha256": base.sha256_file(tool)},
        "common_helper": {"path": str(common_tool), "sha256": base.sha256_file(common_tool)},
        "archives_preserved": True,
        "inputs_preserved": True,
        "run_directories_preserved": True,
        "remote_mutations": False,
        "r2_mutations": False,
    }


def read_bound_receipt(path: Path, schema: str, common: dict[str, Any]) -> dict[str, Any]:
    payload, _ = base.require_root_private_json(path, "retirement receipt")
    for key, value in {"schema": schema, **common}.items():
        if payload.get(key) != value:
            raise RetirementError(f"retirement receipt binding changed: {path}")
    return payload


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--check-only", action="store_true")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    if os.geteuid() != 0:
        parser.error("authentication-failure scratch retirement must run as root")
    try:
        plan, plan_sha256 = base.require_root_private_json(args.plan, "retirement plan")
        validate_plan(plan)
        intent = base.require_receipt_path(plan["intent_receipt"], "intent receipt")
        completion = base.require_receipt_path(plan["completion_receipt"], "completion receipt")
    except base.RetirementError as error:
        raise RetirementError(str(error)) from error
    if intent == completion:
        raise RetirementError("intent and completion receipts must differ")
    intent_exists = intent.exists() or intent.is_symlink()
    completion_exists = completion.exists() or completion.is_symlink()
    if completion_exists and not intent_exists:
        raise RetirementError("completion receipt exists without intent")
    try:
        common = stable_evidence(args.plan, plan_sha256, plan, allow_missing=intent_exists)
    except base.RetirementError as error:
        raise RetirementError(str(error)) from error

    if args.check_only:
        if intent_exists or completion_exists:
            raise RetirementError("check-only requires unused receipt paths")
        for run in common["runs"]:
            scratch = Path(run["scratch"])
            references = base.process_references(scratch)
            if references:
                raise RetirementError(f"live process references {scratch}: {'; '.join(references)}")
            staged = base.systemd_definition_references(scratch)
            if staged:
                raise RetirementError(f"systemd definition references {scratch}: {staged}")
        print(json.dumps({"check_only": True, **common}, sort_keys=True), flush=True)
        return 0

    if intent_exists:
        prior, _ = base.require_root_private_json(intent, "retirement intent")
        prior_runs = prior.get("runs")
        if not isinstance(prior_runs, list) or len(prior_runs) != len(common["runs"]):
            raise RetirementError("retirement intent has invalid run evidence")
        normalized: list[dict[str, Any]] = []
        for current, original in zip(common["runs"], prior_runs, strict=True):
            if not isinstance(original, dict) or not isinstance(original.get("scratch_identity"), dict):
                raise RetirementError("retirement intent lacks original scratch identity")
            if current["scratch_identity"] not in (None, original["scratch_identity"]):
                raise RetirementError("scratch identity changed after intent")
            normalized.append({
                **current,
                "scratch_identity": original["scratch_identity"],
                "scratch_physical_bytes": original["scratch_physical_bytes"],
            })
        common = {**common, "runs": normalized}
        prior = read_bound_receipt(intent, INTENT_SCHEMA, common)
        free_before = prior.get("available_bytes_before")
        if not isinstance(free_before, int) or isinstance(free_before, bool):
            raise RetirementError("retirement intent lacks free-space evidence")
    else:
        free_before = base.available_bytes(Path(common["runs"][0]["run_directory"]))
        base.write_json_noclobber(intent, {
            "schema": INTENT_SCHEMA,
            **common,
            "status": "deletion-intent-fsynced",
            "observed_at_utc": datetime.now(timezone.utc).isoformat(),
            "available_bytes_before": free_before,
        })

    if completion_exists:
        completed = read_bound_receipt(completion, COMPLETION_SCHEMA, common)
        if any(Path(run["scratch"]).exists() or Path(run["scratch"]).is_symlink() for run in common["runs"]):
            raise RetirementError("completion exists while scratch remains")
        print(json.dumps(completed, sort_keys=True), flush=True)
        return 0

    for run in common["runs"]:
        scratch = Path(run["scratch"])
        if scratch.exists() or scratch.is_symlink():
            references = base.process_references(scratch)
            if references:
                raise RetirementError(f"live process references {scratch}: {'; '.join(references)}")
            staged = base.systemd_definition_references(scratch)
            if staged:
                raise RetirementError(f"systemd definition references {scratch}: {staged}")
    for unit in common["units"]:
        base.parse_unit_state(unit["unit"])
    for run in common["runs"]:
        scratch = Path(run["scratch"])
        if scratch.exists() or scratch.is_symlink():
            base.delete_exact_tree(scratch)
    try:
        preserved = stable_evidence(args.plan, plan_sha256, plan, allow_missing=True)
    except base.RetirementError as error:
        raise RetirementError(str(error)) from error
    expected = [{**run, "scratch_identity": None, "scratch_physical_bytes": None} for run in common["runs"]]
    if preserved["runs"] != expected:
        raise RetirementError("preserved run evidence changed during scratch deletion")
    completed = {
        "schema": COMPLETION_SCHEMA,
        **common,
        "status": "deleted",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "intent_receipt": str(intent),
        "intent_receipt_sha256": base.sha256_file(intent),
        "available_bytes_before": free_before,
        "available_bytes_after": base.available_bytes(Path(common["runs"][0]["run_directory"])),
        "scratch_deleted": True,
    }
    base.write_json_noclobber(completion, completed)
    print(json.dumps(completed, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RetirementError, base.RetirementError, subprocess.CalledProcessError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1) from error
