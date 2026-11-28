#!/usr/bin/env python3
"""Seal exact recovered transient-controller commands and configuration hashes."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import sys
from types import ModuleType
from typing import Any, Sequence

if __package__:
    from scripts import retire_reboot_interrupted_replay_scratch as base
else:
    import retire_reboot_interrupted_replay_scratch as base


PLAN_SCHEMA = "jetstreamer-recovered-controller-command-plan-v1"
RECEIPT_SCHEMA = "jetstreamer-recovered-controller-command-receipt-v1"


class SealError(RuntimeError):
    """Recovered command evidence failed a closed validation gate."""


def load_controller(path: Path, label: str) -> ModuleType:
    name = "_recovered_horizon_controller_" + hashlib.sha256(label.encode()).hexdigest()[:16]
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise SealError(f"cannot load controller source {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


def controller_argv(command: str, controller_path: Path) -> list[str]:
    try:
        tokens = shlex.split(command)
    except ValueError as error:
        raise SealError(f"cannot parse recovered command: {error}") from error
    matches = [index for index, token in enumerate(tokens) if token == str(controller_path)]
    if len(matches) != 1:
        raise SealError("recovered command does not contain one exact controller path")
    index = matches[0]
    if index == 0 or tokens[index - 1] != "/usr/bin/python3":
        raise SealError("recovered controller is not launched by exact /usr/bin/python3")
    return tokens[index + 1 :]


def recovered_journal_command(boot_id: str, pid: int, unit: str) -> dict[str, Any]:
    completed = subprocess.run(
        [
            "/usr/bin/journalctl",
            f"--boot={boot_id}",
            f"_PID={pid}",
            "--output=json",
            "--no-pager",
            "--quiet",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    matches: dict[str, dict[str, Any]] = {}
    prefix = f"sudo -n systemd-run --unit={unit}"
    for line in completed.stdout.splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as error:
            raise SealError("journal returned invalid JSON") from error
        command = entry.get("_CMDLINE")
        if entry.get("_COMM") == "sudo" and isinstance(command, str) and command.startswith(prefix):
            matches[command] = entry
    if len(matches) != 1:
        raise SealError(f"expected one recovered sudo command for {unit}, found {len(matches)}")
    command, entry = next(iter(matches.items()))
    return {
        "command": command,
        "command_sha256": hashlib.sha256(command.encode()).hexdigest(),
        "journal_pid": pid,
        "journal_realtime_micros": int(entry["__REALTIME_TIMESTAMP"]),
    }


def validate_plan(plan: dict[str, Any]) -> None:
    if set(plan) != {"schema", "boot_id", "entries", "receipt"}:
        raise SealError("recovery plan has an invalid shape")
    if plan.get("schema") != PLAN_SCHEMA or plan.get("boot_id") != base.read_boot_id():
        raise SealError("recovery plan does not bind the current boot")
    entries = plan.get("entries")
    if not isinstance(entries, list) or not 1 <= len(entries) <= 16:
        raise SealError("recovery plan must contain 1..16 entries")
    labels: set[str] = set()
    units: set[str] = set()
    required = {
        "label", "journal_pid", "unit", "state_path", "controller_path",
        "expected_configuration_sha256",
    }
    for item in entries:
        if not isinstance(item, dict) or set(item) != required:
            raise SealError("recovery entry has an invalid shape")
        label = item.get("label")
        unit = item.get("unit")
        if (
            not isinstance(label, str) or not label or label in labels
            or not isinstance(unit, str) or unit in units or base.UNIT_NAME.fullmatch(unit) is None
            or not isinstance(item.get("journal_pid"), int) or item["journal_pid"] <= 1
            or base.SHA256.fullmatch(str(item.get("expected_configuration_sha256", ""))) is None
        ):
            raise SealError("recovery entry bindings are invalid or duplicated")
        labels.add(label)
        units.add(unit)


def validate_entry(boot_id: str, item: dict[str, Any]) -> dict[str, Any]:
    unit_state = base.parse_unit_state(item["unit"])
    state_path = Path(item["state_path"])
    controller_path = Path(item["controller_path"])
    state_identity = base.file_identity(state_path, 0)
    controller_identity = base.file_identity(controller_path, 0)
    controller_mode = int(controller_identity["mode"], 8)
    if controller_mode & 0o022 or controller_mode & 0o7000:
        raise SealError("controller source is not immutable by mode")
    try:
        state = json.loads(state_path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise SealError(f"cannot read controller state {state_path}: {error}") from error
    expected = item["expected_configuration_sha256"]
    if state.get("configuration_sha256") != expected:
        raise SealError(f"preserved state configuration hash changed for {item['label']}")
    journal = recovered_journal_command(boot_id, item["journal_pid"], item["unit"])
    argv = controller_argv(journal["command"], controller_path)
    controller = load_controller(controller_path, item["label"])
    try:
        args = controller.build_argument_parser().parse_args(argv)
        cohorts, adopted, lanes = controller.prepare(args)
        computed = controller.controller_configuration_sha256(args, cohorts, adopted, lanes)
    except SystemExit as error:
        raise SealError(f"controller argument parser rejected recovered command: {error}") from error
    except BaseException as error:
        raise SealError(f"controller rejected recovered configuration: {error}") from error
    if computed != expected:
        raise SealError(
            f"recovered command configuration mismatch for {item['label']}: {computed} != {expected}"
        )
    return {
        "label": item["label"],
        "unit": item["unit"],
        "current_unit_state": unit_state,
        **journal,
        "controller": {**controller_identity, "sha256": base.sha256_file(controller_path)},
        "state": {**state_identity, "sha256": base.sha256_file(state_path)},
        "configuration_sha256": computed,
        "manifest_fingerprint": state.get("manifest_fingerprint"),
        "recovered_argv": argv,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    if os.geteuid() != 0:
        parser.error("controller command recovery must run as root")
    try:
        plan, plan_sha256 = base.require_root_private_json(args.plan, "recovery plan")
        validate_plan(plan)
        receipt = base.require_receipt_path(plan["receipt"], "recovery receipt")
    except base.RetirementError as error:
        raise SealError(str(error)) from error
    if receipt.exists() or receipt.is_symlink():
        raise SealError("recovery receipt already exists")
    evidence = [validate_entry(plan["boot_id"], item) for item in plan["entries"]]
    tool = Path(__file__).resolve(strict=True)
    payload = {
        "schema": RECEIPT_SCHEMA,
        "status": "sealed",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "plan": str(args.plan),
        "plan_sha256": plan_sha256,
        "boot_id": plan["boot_id"],
        "entries": evidence,
        "tool": {"path": str(tool), "sha256": base.sha256_file(tool)},
        "remote_mutations": False,
        "r2_mutations": False,
    }
    base.write_json_noclobber(receipt, payload)
    print(json.dumps(payload, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (SealError, base.RetirementError, subprocess.CalledProcessError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1) from error
