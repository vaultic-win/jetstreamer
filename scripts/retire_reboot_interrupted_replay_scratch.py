#!/usr/bin/env python3
"""Retire scratch from replay processes interrupted by one authenticated reboot.

The root-owned plan is the only command-line path.  Partial archives, inputs,
cohort state, controller state, and journal evidence remain preserved.  This
tool never accesses or mutates remote storage.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any, Sequence


PLAN_SCHEMA = "jetstreamer-reboot-interrupted-scratch-retirement-plan-v1"
INTENT_SCHEMA = "jetstreamer-reboot-interrupted-scratch-retirement-intent-v1"
COMPLETION_SCHEMA = "jetstreamer-reboot-interrupted-scratch-retirement-completion-v1"
RUN_STATE_SCHEMA = "jetstreamer-root-cohort-run-v1"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
BOOT_ID = re.compile(r"^[0-9a-f]{32}$")
INVOCATION_ID = re.compile(r"^[0-9a-f]{32}$")
UNIT_NAME = re.compile(r"^[A-Za-z0-9_.@:-]+\.service$")
RUN_NAME = re.compile(r"^run-[0-9]+-[0-9]+$")
MAX_PLAN_BYTES = 1024 * 1024


class RetirementError(RuntimeError):
    """A fail-closed interruption-retirement invariant was not satisfied."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def require_root_private_json(path: Path, description: str) -> tuple[dict[str, Any], str]:
    if not path.is_absolute():
        raise RetirementError(f"{description} must be absolute")
    try:
        resolved = path.resolve(strict=True)
        metadata = path.lstat()
        raw = path.read_bytes()
        payload = json.loads(raw)
    except (OSError, json.JSONDecodeError) as error:
        raise RetirementError(f"cannot read {description} {path}: {error}") from error
    if (
        resolved != path
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) & 0o077
        or len(raw) > MAX_PLAN_BYTES
        or not isinstance(payload, dict)
    ):
        raise RetirementError(f"{description} has unsafe identity: {path}")
    return payload, hashlib.sha256(raw).hexdigest()


def require_receipt_path(value: object, label: str) -> Path:
    if not isinstance(value, str):
        raise RetirementError(f"{label} must be a path string")
    path = Path(value)
    if not path.is_absolute() or path.name in ("", ".", ".."):
        raise RetirementError(f"{label} must be an absolute file path")
    try:
        parent = path.parent.resolve(strict=True)
        metadata = parent.stat()
    except OSError as error:
        raise RetirementError(f"cannot resolve {label} parent: {error}") from error
    if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise RetirementError(f"{label} parent must be root-owned and owner-only")
    return parent / path.name


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_json_noclobber(path: Path, payload: dict[str, Any]) -> None:
    data = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
    finally:
        os.close(descriptor)
    fsync_directory(path.parent)


def read_boot_id() -> str:
    value = Path("/proc/sys/kernel/random/boot_id").read_text().strip().replace("-", "")
    if BOOT_ID.fullmatch(value) is None:
        raise RetirementError("current kernel boot ID is invalid")
    return value


def parse_unit_state(unit: str) -> dict[str, Any]:
    if UNIT_NAME.fullmatch(unit) is None:
        raise RetirementError(f"invalid systemd unit name: {unit}")
    completed = subprocess.run(
        [
            "/usr/bin/systemctl",
            "show",
            unit,
            "--no-pager",
            "--property=LoadState,ActiveState,SubState,Result,MainPID,InvocationID,NRestarts",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    fields = dict(line.split("=", 1) for line in completed.stdout.splitlines() if "=" in line)
    result: dict[str, Any] = {
        "unit": unit,
        "load_state": fields.get("LoadState", "unknown"),
        "active_state": fields.get("ActiveState", "unknown"),
        "sub_state": fields.get("SubState", "unknown"),
        "result": fields.get("Result", "unknown"),
        "main_pid": int(fields.get("MainPID", "0") or 0),
        "invocation_id": fields.get("InvocationID", ""),
        "restarts": int(fields.get("NRestarts", "0") or 0),
    }
    if result["active_state"] in {"active", "activating", "reloading", "deactivating"}:
        raise RetirementError(f"unit is still live: {result}")
    if result["main_pid"] != 0 or result["restarts"] != 0:
        raise RetirementError(f"unit has unsafe current state: {result}")
    return result


def validate_journal_record(
    previous_boot_id: str,
    unit: str,
    invocation_id: str,
    realtime_micros: int,
    message: str,
) -> None:
    start = max(0, realtime_micros // 1_000_000 - 2)
    end = realtime_micros // 1_000_000 + 3
    completed = subprocess.run(
        [
            "/usr/bin/journalctl",
            f"--boot={previous_boot_id}",
            f"--unit={unit}",
            f"--since=@{start}",
            f"--until=@{end}",
            "--output=json",
            "--no-pager",
            "--quiet",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    for line in completed.stdout.splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as error:
            raise RetirementError("journal returned invalid JSON") from error
        if (
            entry.get("_SYSTEMD_UNIT") == unit
            and entry.get("_SYSTEMD_INVOCATION_ID") == invocation_id
            and int(entry.get("__REALTIME_TIMESTAMP", -1)) == realtime_micros
            and entry.get("MESSAGE") == message
        ):
            return
    raise RetirementError(f"previous-boot journal evidence is absent for {unit}")


def validate_shutdown_record(previous_boot_id: str, shutdown: dict[str, Any]) -> None:
    micros = shutdown.get("realtime_micros")
    command = shutdown.get("command")
    if not isinstance(micros, int) or command != "sudo shutdown -r 0":
        raise RetirementError("shutdown evidence is invalid")
    start = max(0, micros // 1_000_000 - 2)
    end = micros // 1_000_000 + 3
    completed = subprocess.run(
        [
            "/usr/bin/journalctl",
            f"--boot={previous_boot_id}",
            "_COMM=sudo",
            f"--since=@{start}",
            f"--until=@{end}",
            "--output=json",
            "--no-pager",
            "--quiet",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    for line in completed.stdout.splitlines():
        entry = json.loads(line)
        if (
            int(entry.get("__REALTIME_TIMESTAMP", -1)) == micros
            and entry.get("_CMDLINE") == command
            and "/usr/sbin/shutdown -r 0" in entry.get("MESSAGE", "")
        ):
            return
    raise RetirementError("authenticated reboot journal evidence is absent")


def file_identity(path: Path, required_uid: int | None = None) -> dict[str, Any]:
    try:
        resolved = path.resolve(strict=True)
        metadata = path.lstat()
    except OSError as error:
        raise RetirementError(f"cannot inspect preserved file {path}: {error}") from error
    if (
        resolved != path
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or (required_uid is not None and metadata.st_uid != required_uid)
    ):
        raise RetirementError(f"preserved file has unsafe identity: {path}")
    return {
        "path": str(path),
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "size": metadata.st_size,
        "mtime_ns": metadata.st_mtime_ns,
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
    }


def exact_directory(path: Path, label: str, required_uid: int | None = None) -> os.stat_result:
    try:
        resolved = path.resolve(strict=True)
        metadata = path.lstat()
    except OSError as error:
        raise RetirementError(f"cannot inspect {label} {path}: {error}") from error
    if (
        resolved != path
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or os.path.ismount(path)
        or (required_uid is not None and metadata.st_uid != required_uid)
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise RetirementError(f"{label} has unsafe identity: {path}")
    return metadata


def validate_controller_state(item: dict[str, Any]) -> dict[str, Any]:
    path = Path(item["controller_state"])
    identity = file_identity(path, 0)
    digest = sha256_file(path)
    if digest != item.get("controller_state_sha256"):
        raise RetirementError(f"controller state digest changed: {path}")
    try:
        state = json.loads(path.read_text())
    except json.JSONDecodeError as error:
        raise RetirementError(f"controller state is invalid JSON: {path}") from error
    lane = item.get("lane")
    assignment = state.get("assignments", {}).get(lane)
    if (
        not isinstance(assignment, dict)
        or assignment.get("unit") != item.get("producer_unit")
        or assignment.get("first_epoch") != item.get("start_epoch")
        or assignment.get("last_epoch") != item.get("end_epoch")
        or assignment.get("phase") != item.get("assignment_phase")
    ):
        raise RetirementError(f"controller assignment changed for {item.get('label')}")
    return {**identity, "sha256": digest, "assignment": assignment}


def directory_files(path: Path, uid: int) -> list[dict[str, Any]]:
    entries = sorted(path.iterdir(), key=lambda entry: entry.name)
    if not entries or len(entries) > 32:
        raise RetirementError(f"preserved directory must contain 1..32 files: {path}")
    return [file_identity(entry, uid) for entry in entries]


def physical_bytes(path: Path) -> int:
    completed = subprocess.run(
        ["/usr/bin/du", "-sx", "--block-size=1", str(path)],
        check=True,
        capture_output=True,
        text=True,
    )
    return int(completed.stdout.split()[0])


def validate_run(item: dict[str, Any], *, allow_missing_scratch: bool) -> dict[str, Any]:
    start_epoch = item.get("start_epoch")
    end_epoch = item.get("end_epoch")
    fingerprint = item.get("manifest_fingerprint")
    run = Path(item["run_directory"])
    scratch = Path(item["scratch"])
    if (
        not isinstance(start_epoch, int)
        or not isinstance(end_epoch, int)
        or start_epoch < 0
        or end_epoch < start_epoch
        or not isinstance(fingerprint, str)
        or not fingerprint.startswith("sha256:")
        or SHA256.fullmatch(fingerprint.removeprefix("sha256:")) is None
        or RUN_NAME.fullmatch(run.name) is None
        or run.parent.name != f"root-cohort-{start_epoch}-{end_epoch}"
        or run.parent.parent.name != "work"
        or scratch != run / "scratch"
    ):
        raise RetirementError(f"run layout is invalid for {item.get('label')}")
    run_metadata = exact_directory(run, "cohort run")
    uid = run_metadata.st_uid
    state_path = run / "cohort-state.json"
    expected_state = {
        "end_epoch": end_epoch,
        "manifest_fingerprint": fingerprint,
        "schema": RUN_STATE_SCHEMA,
        "start_epoch": start_epoch,
        "status": "running-private",
    }
    try:
        state = json.loads(state_path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise RetirementError(f"cannot read cohort state {state_path}: {error}") from error
    state_identity = file_identity(state_path, uid)
    if state != expected_state or state_identity["mode"] != "0600":
        raise RetirementError(f"cohort state is not cursor-free running-private: {state_path}")
    if sha256_file(state_path) != item.get("cohort_state_sha256"):
        raise RetirementError(f"cohort state digest changed: {state_path}")
    archives = run / "archives"
    inputs = run / "inputs"
    exact_directory(archives, "archives", uid)
    exact_directory(inputs, "inputs", uid)
    actual_names = {entry.name for entry in run.iterdir()}
    allowed = {"archives", "cohort-state.json", "inputs", "scratch"}
    if actual_names - allowed or not {"archives", "cohort-state.json", "inputs"} <= actual_names:
        raise RetirementError(f"cohort run has unexpected entries: {sorted(actual_names)}")
    archive_files = directory_files(archives, uid)
    if archive_files != item.get("partial_archives"):
        raise RetirementError(f"partial archive identity changed for {item.get('label')}")
    for archive in archive_files:
        sidecar = Path(archive["path"] + ".sha256")
        if sidecar.exists() or sidecar.is_symlink():
            raise RetirementError(f"partial archive unexpectedly has a sidecar: {sidecar}")
    scratch_identity = None
    scratch_bytes = None
    if scratch.exists() or scratch.is_symlink():
        metadata = exact_directory(scratch, "replay scratch", uid)
        if metadata.st_dev != run_metadata.st_dev:
            raise RetirementError("scratch is on a different filesystem")
        scratch_identity = {
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
            "uid": metadata.st_uid,
            "gid": metadata.st_gid,
            "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        }
        scratch_bytes = physical_bytes(scratch)
    elif not allow_missing_scratch:
        raise RetirementError(f"scratch is absent before intent: {scratch}")
    return {
        "label": item.get("label"),
        "run_directory": str(run),
        "run_device": run_metadata.st_dev,
        "run_inode": run_metadata.st_ino,
        "run_uid": uid,
        "run_gid": run_metadata.st_gid,
        "run_mode": f"{stat.S_IMODE(run_metadata.st_mode):04o}",
        "cohort_state": {**state_identity, "sha256": sha256_file(state_path)},
        "archives": archive_files,
        "inputs": directory_files(inputs, uid),
        "scratch": str(scratch),
        "scratch_identity": scratch_identity,
        "scratch_physical_bytes": scratch_bytes,
    }


def _read_proc_file(path: Path) -> bytes | None:
    try:
        return path.read_bytes()
    except (FileNotFoundError, ProcessLookupError):
        return None
    except OSError as error:
        raise RetirementError(f"cannot inspect process evidence {path}: {error}") from error


def _read_proc_link(path: Path) -> str | None:
    try:
        return os.readlink(path).removesuffix(" (deleted)")
    except (FileNotFoundError, ProcessLookupError):
        return None
    except OSError as error:
        raise RetirementError(f"cannot inspect process link {path}: {error}") from error


def ancestor_pids(proc_root: Path = Path("/proc")) -> set[int]:
    result: set[int] = set()
    current = os.getpid()
    while current > 1 and current not in result:
        result.add(current)
        try:
            suffix = (proc_root / str(current) / "stat").read_text().rsplit(")", 1)[1]
            current = int(suffix.split()[1])
        except (FileNotFoundError, ProcessLookupError, OSError, ValueError, IndexError):
            break
    result.add(current)
    return result


def process_references(target: Path, proc_root: Path = Path("/proc")) -> list[str]:
    needle = os.fsencode(str(target))
    references: list[str] = []
    ancestors = ancestor_pids(proc_root)
    try:
        processes = list(proc_root.iterdir())
    except OSError as error:
        raise RetirementError(f"cannot enumerate processes: {error}") from error
    for process in processes:
        if not process.name.isdigit() or int(process.name) == os.getpid():
            continue
        pid = int(process.name)
        for label in ("cmdline", "maps"):
            content = _read_proc_file(process / label)
            if content is not None and needle in content and not (label == "cmdline" and pid in ancestors):
                references.append(f"pid {pid} {label}")
        for label in ("cwd", "root", "exe"):
            link = _read_proc_link(process / label)
            if link is None:
                continue
            try:
                Path(link).relative_to(target)
            except ValueError:
                continue
            references.append(f"pid {pid} {label}")
        try:
            descriptors = list((process / "fd").iterdir())
        except (FileNotFoundError, ProcessLookupError):
            descriptors = []
        except OSError as error:
            raise RetirementError(f"cannot inspect pid {pid} descriptors: {error}") from error
        for descriptor in descriptors:
            link = _read_proc_link(descriptor)
            if link is None:
                continue
            try:
                Path(link).relative_to(target)
            except ValueError:
                continue
            references.append(f"pid {pid} fd {descriptor.name}")
    return references


def systemd_definition_references(target: Path) -> list[str]:
    needle = os.fsencode(str(target))
    matches: list[str] = []
    for root in (Path("/etc/systemd/system"), Path("/run/systemd/system"), Path("/run/systemd/transient")):
        if not root.exists():
            continue
        for path in root.rglob("*"):
            try:
                metadata = path.lstat()
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 1024 * 1024:
                continue
            try:
                content = path.read_bytes()
            except FileNotFoundError:
                continue
            except OSError as error:
                raise RetirementError(f"cannot inspect systemd definition {path}: {error}") from error
            if needle in content:
                matches.append(str(path))
    return matches


def available_bytes(path: Path) -> int:
    filesystem = os.statvfs(path)
    return filesystem.f_bavail * filesystem.f_frsize


def delete_exact_tree(path: Path) -> None:
    completed = subprocess.run(
        ["/usr/bin/find", str(path), "-xdev", "-depth", "-delete"],
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0 or path.exists() or path.is_symlink():
        raise RetirementError(
            "scratch deletion did not complete: "
            + (completed.stderr.strip() or completed.stdout.strip())
        )
    fsync_directory(path.parent)


def validate_plan(plan: dict[str, Any], *, check_journal: bool = True) -> None:
    if set(plan) != {
        "schema",
        "previous_boot_id",
        "current_boot_id",
        "shutdown",
        "runs",
        "intent_receipt",
        "completion_receipt",
    } or plan.get("schema") != PLAN_SCHEMA:
        raise RetirementError("retirement plan has an invalid schema")
    previous = plan.get("previous_boot_id")
    current = plan.get("current_boot_id")
    if (
        not isinstance(previous, str)
        or BOOT_ID.fullmatch(previous) is None
        or not isinstance(current, str)
        or BOOT_ID.fullmatch(current) is None
        or previous == current
        or read_boot_id() != current
    ):
        raise RetirementError("retirement plan boot IDs do not bind this reboot")
    runs = plan.get("runs")
    if not isinstance(runs, list) or not runs or len(runs) > 32:
        raise RetirementError("retirement plan must contain 1..32 runs")
    labels: set[str] = set()
    scratches: set[str] = set()
    for item in runs:
        if not isinstance(item, dict):
            raise RetirementError("retirement run is not an object")
        label = item.get("label")
        scratch = item.get("scratch")
        if not isinstance(label, str) or label in labels or not isinstance(scratch, str) or scratch in scratches:
            raise RetirementError("retirement run labels and scratches must be unique")
        labels.add(label)
        scratches.add(scratch)
        if UNIT_NAME.fullmatch(str(item.get("controller_unit", ""))) is None or UNIT_NAME.fullmatch(str(item.get("producer_unit", ""))) is None:
            raise RetirementError(f"retirement run has invalid unit names: {label}")
        invocation = item.get("producer_invocation_id")
        micros = item.get("last_progress_realtime_micros")
        message = item.get("last_progress_message")
        if INVOCATION_ID.fullmatch(str(invocation)) is None or not isinstance(micros, int) or not isinstance(message, str):
            raise RetirementError(f"retirement run has invalid journal binding: {label}")
        if check_journal:
            validate_journal_record(previous, item["producer_unit"], invocation, micros, message)
    if check_journal:
        validate_shutdown_record(previous, plan["shutdown"])


def stable_evidence(plan_path: Path, plan_sha256: str, plan: dict[str, Any], allow_missing: bool) -> dict[str, Any]:
    units: dict[str, dict[str, Any]] = {}
    states: list[dict[str, Any]] = []
    runs: list[dict[str, Any]] = []
    for item in plan["runs"]:
        for key in ("controller_unit", "producer_unit"):
            unit = item[key]
            units.setdefault(unit, parse_unit_state(unit))
        states.append(validate_controller_state(item))
        runs.append(validate_run(item, allow_missing_scratch=allow_missing))
    return {
        "plan": str(plan_path),
        "plan_sha256": plan_sha256,
        "previous_boot_id": plan["previous_boot_id"],
        "current_boot_id": plan["current_boot_id"],
        "shutdown": plan["shutdown"],
        "units": [units[name] for name in sorted(units)],
        "controller_states": states,
        "runs": runs,
        "retirement_tool": {
            "path": str(Path(__file__).resolve(strict=True)),
            "sha256": sha256_file(Path(__file__).resolve(strict=True)),
        },
        "partial_archive_hashes_deferred": True,
        "partial_archives_preserved": True,
        "remote_mutations": False,
        "r2_mutations": False,
    }


def read_bound_receipt(path: Path, schema: str, common: dict[str, Any]) -> dict[str, Any]:
    payload, _ = require_root_private_json(path, "retirement receipt")
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
        parser.error("reboot-interrupted scratch retirement must run as root")
    plan, plan_sha256 = require_root_private_json(args.plan, "retirement plan")
    validate_plan(plan)
    intent = require_receipt_path(plan["intent_receipt"], "intent receipt")
    completion = require_receipt_path(plan["completion_receipt"], "completion receipt")
    if intent == completion:
        raise RetirementError("intent and completion receipts must differ")
    intent_exists = intent.exists() or intent.is_symlink()
    completion_exists = completion.exists() or completion.is_symlink()
    if completion_exists and not intent_exists:
        raise RetirementError("completion receipt exists without intent")
    common = stable_evidence(args.plan, plan_sha256, plan, allow_missing=intent_exists)

    if args.check_only:
        if intent_exists or completion_exists:
            raise RetirementError("check-only requires unused receipt paths")
        for run in common["runs"]:
            scratch = Path(run["scratch"])
            references = process_references(scratch)
            if references:
                raise RetirementError(f"live process references {scratch}: {'; '.join(references)}")
            staged = systemd_definition_references(scratch)
            if staged:
                raise RetirementError(f"systemd definition references {scratch}: {staged}")
        print(json.dumps({"check_only": True, **common}, sort_keys=True), flush=True)
        return 0

    if intent_exists:
        prior, _ = require_root_private_json(intent, "retirement intent")
        prior_runs = prior.get("runs")
        if not isinstance(prior_runs, list) or len(prior_runs) != len(common["runs"]):
            raise RetirementError("retirement intent has invalid run evidence")
        normalized: list[dict[str, Any]] = []
        for current_run, prior_run in zip(common["runs"], prior_runs, strict=True):
            if not isinstance(prior_run, dict) or not isinstance(prior_run.get("scratch_identity"), dict):
                raise RetirementError("retirement intent lacks original scratch identity")
            if current_run["scratch_identity"] not in (None, prior_run["scratch_identity"]):
                raise RetirementError("scratch identity changed after intent")
            normalized.append(
                {
                    **current_run,
                    "scratch_identity": prior_run["scratch_identity"],
                    "scratch_physical_bytes": prior_run["scratch_physical_bytes"],
                }
            )
        common = {**common, "runs": normalized}
        prior = read_bound_receipt(intent, INTENT_SCHEMA, common)
        free_before = prior.get("available_bytes_before")
        if not isinstance(free_before, int):
            raise RetirementError("retirement intent lacks free-space evidence")
    else:
        free_before = available_bytes(Path(common["runs"][0]["run_directory"]))
        write_json_noclobber(
            intent,
            {
                "schema": INTENT_SCHEMA,
                **common,
                "status": "deletion-intent-fsynced",
                "observed_at_utc": datetime.now(timezone.utc).isoformat(),
                "available_bytes_before": free_before,
            },
        )

    if completion_exists:
        completed = read_bound_receipt(completion, COMPLETION_SCHEMA, common)
        if any(Path(run["scratch"]).exists() or Path(run["scratch"]).is_symlink() for run in common["runs"]):
            raise RetirementError("completion exists while scratch remains")
        print(json.dumps(completed, sort_keys=True), flush=True)
        return 0

    for run in common["runs"]:
        scratch = Path(run["scratch"])
        if scratch.exists() or scratch.is_symlink():
            references = process_references(scratch)
            if references:
                raise RetirementError(f"live process references {scratch}: {'; '.join(references)}")
            staged = systemd_definition_references(scratch)
            if staged:
                raise RetirementError(f"systemd definition references {scratch}: {staged}")
    # Re-observe every stopped unit immediately before the first mutation.
    for unit in common["units"]:
        parse_unit_state(unit["unit"])
    for run in common["runs"]:
        scratch = Path(run["scratch"])
        if scratch.exists() or scratch.is_symlink():
            delete_exact_tree(scratch)
    preserved = stable_evidence(args.plan, plan_sha256, plan, allow_missing=True)
    expected = [{**run, "scratch_identity": None, "scratch_physical_bytes": None} for run in common["runs"]]
    if preserved["runs"] != expected:
        raise RetirementError("preserved run evidence changed during scratch deletion")
    free_after = available_bytes(Path(common["runs"][0]["run_directory"]))
    completed = {
        "schema": COMPLETION_SCHEMA,
        **common,
        "status": "deleted",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "intent_receipt": str(intent),
        "intent_receipt_sha256": sha256_file(intent),
        "available_bytes_before": free_before,
        "available_bytes_after": free_after,
        "available_bytes_recovered": max(0, free_after - free_before),
        "scratch_deleted": True,
        "run_directories_preserved": True,
    }
    write_json_noclobber(completion, completed)
    print(json.dumps(completed, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RetirementError as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1) from error
