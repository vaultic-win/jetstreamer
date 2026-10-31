#!/usr/bin/env python3
"""Atomically refresh GCloud configurations for authenticated idle replay lanes.

The root-owned plan is the only command-line path.  A validated snapshot of the
operator's refreshed configuration is copied to each lane, proven with one
exact generation-bound GCS metadata lookup, and atomically exchanged with the
idle lane's effective configuration.  Per-lane no-clobber receipts make an
interrupted exchange resumable.  This helper performs no GCS or R2 mutation.
"""

from __future__ import annotations

import argparse
import ctypes
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys
from typing import Any, Iterable, Sequence

if __package__:
    from scripts import retire_reboot_interrupted_replay_scratch as base
else:
    import retire_reboot_interrupted_replay_scratch as base


PLAN_SCHEMA = "jetstreamer-idle-gcloud-refresh-plan-v2"
PREPARATION_SCHEMA = "jetstreamer-idle-gcloud-refresh-preparation-v2"
INTENT_SCHEMA = "jetstreamer-idle-gcloud-refresh-intent-v2"
LANE_SCHEMA = "jetstreamer-idle-gcloud-refresh-lane-v2"
COMPLETION_SCHEMA = "jetstreamer-idle-gcloud-refresh-completion-v2"
AT_FDCWD = -100
RENAME_NOREPLACE = 1
RENAME_EXCHANGE = 2
SAFE_LABEL = re.compile(r"^[a-z0-9][a-z0-9-]{0,79}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
MINIMAL_PATH = "/usr/bin:/bin"
LOADED_UNIT_BINDING_KEYS = {
    "kind",
    "name",
    "fragment_path",
    "fragment_sha256",
    "exec_start_sha256",
    "load_state",
    "active_state",
    "sub_state",
    "result",
    "unit_file_state",
    "invocation_id",
    "restarts",
    "triggers",
    "triggered_by",
    "claimed_lanes",
}
RECOVERED_UNIT_BINDING_KEYS = {
    "kind",
    "name",
    "recovery_receipt",
    "recovery_receipt_sha256",
    "recovery_entry_label",
    "load_state",
    "active_state",
    "sub_state",
    "result",
    "unit_file_state",
    "invocation_id",
    "restarts",
    "triggers",
    "triggered_by",
    "claimed_lanes",
}
WORKSPACE_KEYS = {"path", "device", "inode", "mode", "uid", "gid"}


class RefreshError(RuntimeError):
    """A fail-closed lane credential refresh invariant was not satisfied."""


def exact_directory(path: Path, label: str) -> os.stat_result:
    try:
        resolved = path.resolve(strict=True)
        metadata = path.lstat()
    except OSError as error:
        raise RefreshError(f"cannot inspect {label} {path}: {error}") from error
    if (
        resolved != path
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or os.path.ismount(path)
    ):
        raise RefreshError(f"{label} is not an exact ordinary directory: {path}")
    return metadata


def sha256_descriptor(descriptor: int) -> str:
    digest = hashlib.sha256()
    with os.fdopen(os.dup(descriptor), "rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def tree_summary(path: Path, *, allow_empty: bool = False) -> dict[str, Any]:
    expected_root = exact_directory(path, "configuration tree")
    try:
        root_descriptor = os.open(
            path,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
    except OSError as error:
        raise RefreshError(f"cannot open configuration tree {path}: {error}") from error
    root = os.fstat(root_descriptor)
    if (root.st_dev, root.st_ino) != (expected_root.st_dev, expected_root.st_ino):
        os.close(root_descriptor)
        raise RefreshError(f"configuration tree changed while opening it: {path}")
    records: list[dict[str, Any]] = []
    total_bytes = 0
    file_count = 0
    directory_count = 0

    def visit(directory_descriptor: int, relative: Path) -> None:
        nonlocal total_bytes, file_count, directory_count
        try:
            names = sorted(entry.name for entry in os.scandir(directory_descriptor))
        except OSError as error:
            raise RefreshError(
                f"cannot enumerate configuration directory {path / relative}: {error}"
            ) from error
        for name in names:
            entry_path = path / relative / name
            entry_relative = relative / name
            try:
                metadata = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
            except OSError as error:
                raise RefreshError(f"cannot inspect configuration entry {entry_path}: {error}") from error
            if metadata.st_dev != root.st_dev:
                raise RefreshError(f"configuration contains a mounted entry: {entry_path}")
            common = {
                "path": entry_relative.as_posix(),
                "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
                "uid": metadata.st_uid,
                "gid": metadata.st_gid,
            }
            if stat.S_ISDIR(metadata.st_mode):
                try:
                    child_descriptor = os.open(
                        name,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                        dir_fd=directory_descriptor,
                    )
                except OSError as error:
                    raise RefreshError(
                        f"cannot open configuration directory {entry_path}: {error}"
                    ) from error
                opened = os.fstat(child_descriptor)
                if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                    os.close(child_descriptor)
                    raise RefreshError(f"configuration directory changed while opening: {entry_path}")
                directory_count += 1
                records.append({**common, "type": "directory"})
                try:
                    visit(child_descriptor, entry_relative)
                finally:
                    os.close(child_descriptor)
            elif stat.S_ISREG(metadata.st_mode):
                if metadata.st_nlink != 1:
                    raise RefreshError(f"configuration file is multiply linked: {entry_path}")
                try:
                    descriptor = os.open(
                        name,
                        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                        dir_fd=directory_descriptor,
                    )
                except OSError as error:
                    raise RefreshError(f"cannot open configuration file {entry_path}: {error}") from error
                opened = os.fstat(descriptor)
                if (
                    (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
                    or not stat.S_ISREG(opened.st_mode)
                    or opened.st_nlink != 1
                ):
                    os.close(descriptor)
                    raise RefreshError(f"configuration file changed while opening: {entry_path}")
                file_count += 1
                total_bytes += metadata.st_size
                try:
                    file_hash = sha256_descriptor(descriptor)
                    after = os.fstat(descriptor)
                finally:
                    os.close(descriptor)
                if (
                    (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                    != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
                ):
                    raise RefreshError(f"configuration file changed while hashing: {entry_path}")
                records.append(
                    {
                        **common,
                        "type": "file",
                        "size": metadata.st_size,
                        "sha256": file_hash,
                    }
                )
            else:
                raise RefreshError(f"configuration contains a special file or symlink: {entry_path}")

    try:
        visit(root_descriptor, Path("."))
        final_root = os.fstat(root_descriptor)
    finally:
        os.close(root_descriptor)
    if (
        final_root.st_dev,
        final_root.st_ino,
        final_root.st_mtime_ns,
    ) != (root.st_dev, root.st_ino, root.st_mtime_ns):
        raise RefreshError(f"configuration tree changed while scanning it: {path}")
    if file_count == 0 and not allow_empty:
        raise RefreshError(f"configuration tree contains no files: {path}")
    content_records = [
        {key: value for key, value in record.items() if key not in {"mode", "uid", "gid"}}
        for record in records
    ]
    encoded = json.dumps(content_records, sort_keys=True, separators=(",", ":")).encode()
    return {
        "path": str(path),
        "device": root.st_dev,
        "inode": root.st_ino,
        "mode": f"{stat.S_IMODE(root.st_mode):04o}",
        "uid": root.st_uid,
        "gid": root.st_gid,
        "file_count": file_count,
        "directory_count": directory_count,
        "file_bytes": total_bytes,
        "content_sha256": hashlib.sha256(encoded).hexdigest(),
    }


def same_content(left: dict[str, Any], right: dict[str, Any]) -> bool:
    keys = ("file_count", "directory_count", "file_bytes", "content_sha256")
    return all(left.get(key) == right.get(key) for key in keys)


def same_tree_identity(left: dict[str, Any], right: dict[str, Any]) -> bool:
    identity = ("device", "inode", "mode", "uid", "gid")
    return same_content(left, right) and all(left.get(key) == right.get(key) for key in identity)


def aliased_value(payload: dict[str, Any], names: Sequence[str], label: str) -> Any:
    values = [(name, payload[name]) for name in names if name in payload]
    if not values:
        raise RefreshError(f"GCS metadata omits {label}")
    first = values[0][1]
    if any(value != first for _, value in values[1:]):
        raise RefreshError(f"GCS metadata has conflicting {label} aliases")
    return first


def parse_probe_metadata(payload: dict[str, Any], expected: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise RefreshError("GCS metadata output is not an object")
    size = aliased_value(payload, ("size",), "size")
    generation = aliased_value(payload, ("generation",), "generation")
    crc32c = aliased_value(payload, ("crc32c_hash", "crc32c"), "CRC32C")
    md5 = aliased_value(payload, ("md5_hash", "md5Hash"), "MD5")
    try:
        size_value = int(size)
        generation_value = int(generation)
    except (TypeError, ValueError) as error:
        raise RefreshError("GCS metadata size or generation is not an integer") from error
    if (
        size_value != expected["size"]
        or generation_value != expected["generation"]
        or crc32c != expected["crc32c_hash"]
        or md5 != expected["md5_hash"]
    ):
        raise RefreshError("GCS metadata identity or hashes do not match the sealed probe")
    storage_url = payload.get("storage_url")
    raw_id = payload.get("id")
    if storage_url is not None and storage_url != expected["versioned_uri"]:
        raise RefreshError("GCS normalized storage URL does not match the sealed generation")
    if raw_id is not None and raw_id != expected["raw_id"]:
        raise RefreshError("GCS raw object ID does not match the sealed generation")
    if storage_url is None and raw_id is None:
        raise RefreshError("GCS metadata omits both normalized storage URL and raw object ID")
    return {
        "versioned_uri": expected["versioned_uri"],
        "generation": generation_value,
        "size": size_value,
        "crc32c_hash": crc32c,
        "md5_hash": md5,
        "identity_field": "storage_url" if storage_url is not None else "id",
    }


def probe_config(config: Path, plan: dict[str, Any]) -> dict[str, Any]:
    metadata = exact_directory(config, "GCloud configuration")
    try:
        account = pwd.getpwuid(metadata.st_uid)
    except KeyError as error:
        raise RefreshError(f"GCloud configuration owner has no passwd entry: {metadata.st_uid}") from error
    if account.pw_gid != metadata.st_gid:
        raise RefreshError(
            f"GCloud configuration owner/group is not the owner's primary identity: {config}"
        )
    command = [
        "/usr/bin/setpriv",
        f"--reuid={metadata.st_uid}",
        f"--regid={metadata.st_gid}",
        "--init-groups",
        "--reset-env",
        "--no-new-privs",
        "/usr/bin/env",
        "-i",
        f"HOME={account.pw_dir}",
        f"USER={account.pw_name}",
        f"LOGNAME={account.pw_name}",
        f"PATH={MINIMAL_PATH}",
        f"CLOUDSDK_CONFIG={config}",
        plan["gcloud_bin"],
        "storage",
        "objects",
        "describe",
        plan["probe"]["versioned_uri"],
        f"--account={plan['account']}",
        f"--project={plan['project']}",
        "--format=json",
        "--quiet",
    ]
    completed = subprocess.run(command, capture_output=True, text=True)
    if completed.returncode != 0:
        detail = completed.stderr.strip().splitlines()
        raise RefreshError(
            "generation-bound GCS metadata lookup failed: "
            + (detail[-1] if detail else f"exit {completed.returncode}")
        )
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise RefreshError("GCS metadata lookup returned invalid JSON") from error
    return parse_probe_metadata(payload, plan["probe"])


def _read_proc(path: Path) -> bytes | None:
    try:
        return path.read_bytes()
    except (FileNotFoundError, ProcessLookupError):
        return None
    except OSError as error:
        raise RefreshError(f"cannot inspect process evidence {path}: {error}") from error


def _read_link(path: Path) -> str | None:
    try:
        return os.readlink(path).removesuffix(" (deleted)")
    except (FileNotFoundError, ProcessLookupError):
        return None
    except OSError as error:
        raise RefreshError(f"cannot inspect process link {path}: {error}") from error


def process_references(target: Path, proc_root: Path = Path("/proc")) -> list[str]:
    needle = os.fsencode(str(target))
    matches: list[str] = []
    ancestors = base.ancestor_pids(proc_root)
    try:
        processes = list(proc_root.iterdir())
    except OSError as error:
        raise RefreshError(f"cannot enumerate processes: {error}") from error
    for process in processes:
        if not process.name.isdigit() or int(process.name) == os.getpid():
            continue
        pid = int(process.name)
        for label in ("cmdline", "environ", "maps"):
            content = _read_proc(process / label)
            if content is not None and needle in content and not (label == "cmdline" and pid in ancestors):
                matches.append(f"pid {pid} {label}")
        for label in ("cwd", "root", "exe"):
            value = _read_link(process / label)
            if value is None:
                continue
            try:
                Path(value).relative_to(target)
            except ValueError:
                continue
            matches.append(f"pid {pid} {label}")
        try:
            descriptors = list((process / "fd").iterdir())
        except (FileNotFoundError, ProcessLookupError):
            descriptors = []
        except OSError as error:
            raise RefreshError(f"cannot inspect pid {pid} descriptors: {error}") from error
        for descriptor in descriptors:
            value = _read_link(descriptor)
            if value is None:
                continue
            try:
                Path(value).relative_to(target)
            except ValueError:
                continue
            matches.append(f"pid {pid} fd {descriptor.name}")
    return matches


def _is_cloud_sdk_command(command: bytes) -> bool:
    arguments = [argument for argument in command.split(b"\0") if argument]
    if not arguments:
        return False

    def name(argument: bytes) -> bytes:
        return argument.rsplit(b"/", 1)[-1]

    sdk_commands = {
        b"bq",
        b"bq.py",
        b"gcloud",
        b"gcloud.py",
        b"gsutil",
        b"gsutil.py",
    }
    if name(arguments[0]) in sdk_commands:
        return True

    interpreter = name(arguments[0])
    if (
        interpreter in {b"bash", b"dash", b"sh", b"zsh"}
        or interpreter.startswith(b"python")
    ):
        return len(arguments) > 1 and name(arguments[1]) in sdk_commands

    if interpreter != b"env":
        return False
    index = 1
    while index < len(arguments) and (
        arguments[index].startswith(b"-") or b"=" in arguments[index]
    ):
        index += 1
    if index >= len(arguments):
        return False
    if name(arguments[index]) in sdk_commands:
        return True
    nested_interpreter = name(arguments[index])
    return (
        nested_interpreter in {b"bash", b"dash", b"sh", b"zsh"}
        or nested_interpreter.startswith(b"python")
    ) and index + 1 < len(arguments) and name(arguments[index + 1]) in sdk_commands


def live_gcloud_processes(proc_root: Path = Path("/proc")) -> list[int]:
    result: list[int] = []
    ancestors = base.ancestor_pids(proc_root)
    try:
        processes = list(proc_root.iterdir())
    except OSError as error:
        raise RefreshError(f"cannot enumerate processes: {error}") from error
    for process in processes:
        if not process.name.isdigit():
            continue
        pid = int(process.name)
        command = _read_proc(process / "cmdline")
        if command is None or pid in ancestors:
            continue
        if _is_cloud_sdk_command(command):
            result.append(pid)
    return sorted(result)


def _unit_fragment_sha256(path: Path) -> str:
    try:
        resolved = path.resolve(strict=True)
        metadata = path.lstat()
    except OSError as error:
        raise RefreshError(f"cannot inspect systemd unit fragment {path}: {error}") from error
    if (
        resolved != path
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise RefreshError(f"systemd unit fragment has unsafe identity: {path}")
    return base.sha256_file(path)


def _systemd_fields(unit: str) -> dict[str, str]:
    completed = subprocess.run(
        [
            "/usr/bin/systemctl",
            "show",
            unit,
            "--no-pager",
            "--property=LoadState,ActiveState,SubState,Result,MainPID,InvocationID,NRestarts,"
            "UnitFileState,FragmentPath,ExecStart,Job,Triggers,TriggeredBy",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return dict(line.split("=", 1) for line in completed.stdout.splitlines() if "=" in line)


def _require_recorded_file(record: dict[str, Any], label: str) -> None:
    required = {"path", "device", "inode", "mode", "uid", "gid", "size", "mtime_ns", "sha256"}
    if not isinstance(record, dict) or set(record) != required:
        raise RefreshError(f"recovered controller receipt has an invalid {label} record")
    path = Path(str(record.get("path", "")))
    try:
        resolved = path.resolve(strict=True)
        metadata = path.lstat()
    except OSError as error:
        raise RefreshError(f"cannot inspect recovered {label} {path}: {error}") from error
    observed = {
        "path": str(path),
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "size": metadata.st_size,
        "mtime_ns": metadata.st_mtime_ns,
        "sha256": base.sha256_file(path),
    }
    if (
        resolved != path
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or observed != record
    ):
        raise RefreshError(f"recovered {label} no longer matches its sealed identity: {path}")


def validate_recovered_unit_authority(binding: dict[str, Any]) -> None:
    path = Path(binding["recovery_receipt"])
    try:
        receipt, receipt_sha256 = base.require_root_private_json(
            path, "recovered controller command receipt"
        )
    except base.RetirementError as error:
        raise RefreshError(str(error)) from error
    if (
        receipt_sha256 != binding["recovery_receipt_sha256"]
        or receipt.get("schema") != "jetstreamer-recovered-controller-command-receipt-v1"
        or receipt.get("status") != "sealed"
        or receipt.get("boot_id") != base.read_boot_id()
        or receipt.get("remote_mutations") is not False
        or receipt.get("r2_mutations") is not False
    ):
        raise RefreshError("recovered controller command receipt is invalid or stale")
    entries = receipt.get("entries")
    if not isinstance(entries, list):
        raise RefreshError("recovered controller command receipt has no entry list")
    matches = [
        entry
        for entry in entries
        if isinstance(entry, dict) and entry.get("label") == binding["recovery_entry_label"]
    ]
    if len(matches) != 1:
        raise RefreshError("recovered controller command receipt lacks one selected entry")
    entry = matches[0]
    if entry.get("unit") != binding["name"]:
        raise RefreshError("recovered controller entry names a different unit")
    recorded_state = entry.get("current_unit_state")
    expected_state = {
        "unit": binding["name"],
        "load_state": binding["load_state"],
        "active_state": binding["active_state"],
        "sub_state": binding["sub_state"],
        "result": binding["result"],
        "main_pid": 0,
        "invocation_id": binding["invocation_id"],
        "restarts": binding["restarts"],
    }
    if recorded_state != expected_state:
        raise RefreshError("recovered controller entry has a different terminal unit state")
    argv = entry.get("recovered_argv")
    if not isinstance(argv, list) or any(not isinstance(item, str) for item in argv):
        raise RefreshError("recovered controller entry has invalid arguments")
    claims: list[str] = []
    index = 0
    while index < len(argv):
        item = argv[index]
        if item == "--lane":
            index += 1
            if index >= len(argv) or argv[index].startswith("--") or "=" not in argv[index]:
                raise RefreshError("recovered controller entry has a malformed two-token lane claim")
            claims.append(argv[index])
        elif item.startswith("--lane="):
            value = item.removeprefix("--lane=")
            if not value or "=" not in value:
                raise RefreshError("recovered controller entry has a malformed lane claim")
            claims.append(value)
        index += 1
    if len(claims) != len(set(claims)):
        raise RefreshError("recovered controller entry has duplicate lane claims")
    claims.sort()
    if claims != sorted(binding["claimed_lanes"]):
        raise RefreshError("recovered controller entry has different lane claims")
    if SHA256.fullmatch(str(entry.get("command_sha256", ""))) is None or SHA256.fullmatch(
        str(entry.get("configuration_sha256", ""))
    ) is None:
        raise RefreshError("recovered controller entry lacks sealed command hashes")
    _require_recorded_file(entry.get("controller"), "controller")
    _require_recorded_file(entry.get("state"), "controller state")


def observe_loaded_unit(binding: dict[str, Any]) -> dict[str, Any]:
    unit = binding["name"]
    fields = _systemd_fields(unit)
    try:
        main_pid = int(fields.get("MainPID", "0") or 0)
        restarts = int(fields.get("NRestarts", "0") or 0)
    except ValueError as error:
        raise RefreshError(f"systemd returned invalid numeric state for {unit}") from error
    triggers = sorted(fields.get("Triggers", "").split())
    triggered_by = sorted(fields.get("TriggeredBy", "").split())
    fragment = Path(fields.get("FragmentPath", ""))
    if not fragment.is_absolute():
        raise RefreshError(f"systemd unit has no exact fragment path: {unit}")
    observed = {
        "kind": "loaded-unit",
        "name": unit,
        "fragment_path": str(fragment),
        "fragment_sha256": _unit_fragment_sha256(fragment),
        "exec_start_sha256": hashlib.sha256(fields.get("ExecStart", "").encode()).hexdigest(),
        "load_state": fields.get("LoadState", "unknown"),
        "active_state": fields.get("ActiveState", "unknown"),
        "sub_state": fields.get("SubState", "unknown"),
        "result": fields.get("Result", "unknown"),
        "unit_file_state": fields.get("UnitFileState", "unknown"),
        "invocation_id": fields.get("InvocationID", ""),
        "restarts": restarts,
        "triggers": triggers,
        "triggered_by": triggered_by,
        "claimed_lanes": binding["claimed_lanes"],
    }
    if fields.get("Job", ""):
        raise RefreshError(f"systemd unit has a pending job: {unit}: {fields['Job']}")
    if main_pid != 0 or observed != binding:
        raise RefreshError(f"systemd unit no longer matches its sealed idle binding: {unit}")
    exec_start = fields.get("ExecStart", "")
    if any(f"--lane={claim}" not in exec_start for claim in binding["claimed_lanes"]):
        raise RefreshError(f"systemd unit no longer contains its exact lane claims: {unit}")
    if (
        observed["load_state"] != "loaded"
        or observed["active_state"] != "inactive"
        or observed["sub_state"] != "dead"
        or observed["restarts"] != 0
        or observed["invocation_id"]
        or observed["triggers"]
        or observed["triggered_by"]
    ):
        raise RefreshError(f"systemd unit is not sealed idle: {unit}")
    return observed


def observe_recovered_unit(binding: dict[str, Any]) -> dict[str, Any]:
    validate_recovered_unit_authority(binding)
    fields = _systemd_fields(binding["name"])
    try:
        main_pid = int(fields.get("MainPID", "0") or 0)
        restarts = int(fields.get("NRestarts", "0") or 0)
    except ValueError as error:
        raise RefreshError("systemd returned invalid recovered-unit numeric state") from error
    observed = {
        "kind": "collected-transient",
        "name": binding["name"],
        "recovery_receipt": binding["recovery_receipt"],
        "recovery_receipt_sha256": binding["recovery_receipt_sha256"],
        "recovery_entry_label": binding["recovery_entry_label"],
        "load_state": fields.get("LoadState", "unknown"),
        "active_state": fields.get("ActiveState", "unknown"),
        "sub_state": fields.get("SubState", "unknown"),
        "result": fields.get("Result", "unknown"),
        "unit_file_state": fields.get("UnitFileState", ""),
        "invocation_id": fields.get("InvocationID", ""),
        "restarts": restarts,
        "triggers": sorted(fields.get("Triggers", "").split()),
        "triggered_by": sorted(fields.get("TriggeredBy", "").split()),
        "claimed_lanes": binding["claimed_lanes"],
    }
    if (
        fields.get("Job", "")
        or fields.get("FragmentPath", "")
        or fields.get("ExecStart", "")
        or main_pid != 0
        or observed != binding
    ):
        raise RefreshError(
            f"collected transient unit no longer matches its sealed absent state: {binding['name']}"
        )
    return observed


def observe_bound_unit(binding: dict[str, Any]) -> dict[str, Any]:
    if binding.get("kind") == "loaded-unit":
        return observe_loaded_unit(binding)
    if binding.get("kind") == "collected-transient":
        return observe_recovered_unit(binding)
    raise RefreshError("unknown controller binding kind")


def require_idle(units: Sequence[dict[str, Any]], targets: Iterable[Path]) -> list[dict[str, Any]]:
    states = [observe_bound_unit(unit) for unit in units]
    for target in targets:
        references = process_references(target)
        if references:
            raise RefreshError(f"live process references {target}: {'; '.join(references)}")
    return states


def normalize_config_tree(path: Path, uid: int, gid: int) -> None:
    expected = exact_directory(path, "configuration tree")
    root = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        opened = os.fstat(root)
        if (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino):
            raise RefreshError(f"configuration tree changed while opening it: {path}")
        root_device = opened.st_dev

        def visit(directory: int, relative: Path) -> None:
            names = sorted(entry.name for entry in os.scandir(directory))
            for name in names:
                candidate = path / relative / name
                metadata = os.stat(name, dir_fd=directory, follow_symlinks=False)
                if metadata.st_dev != root_device:
                    raise RefreshError(f"configuration contains a mounted entry: {candidate}")
                if stat.S_ISDIR(metadata.st_mode):
                    child = os.open(
                        name,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                        dir_fd=directory,
                    )
                    try:
                        actual = os.fstat(child)
                        if (actual.st_dev, actual.st_ino) != (metadata.st_dev, metadata.st_ino):
                            raise RefreshError(f"configuration directory changed while opening: {candidate}")
                        visit(child, relative / name)
                        os.fchown(child, uid, gid)
                        os.fchmod(child, 0o700)
                    finally:
                        os.close(child)
                elif stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
                    child = os.open(
                        name,
                        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                        dir_fd=directory,
                    )
                    try:
                        actual = os.fstat(child)
                        if (
                            (actual.st_dev, actual.st_ino) != (metadata.st_dev, metadata.st_ino)
                            or actual.st_nlink != 1
                        ):
                            raise RefreshError(f"configuration file changed while opening: {candidate}")
                        os.fchown(child, uid, gid)
                        os.fchmod(child, 0o600)
                    finally:
                        os.close(child)
                else:
                    raise RefreshError(f"configuration contains an unsafe entry: {candidate}")

        visit(root, Path("."))
        os.fchown(root, uid, gid)
        os.fchmod(root, 0o700)
    finally:
        os.close(root)
    final = exact_directory(path, "normalized configuration tree")
    if (final.st_dev, final.st_ino) != (expected.st_dev, expected.st_ino):
        raise RefreshError(f"configuration tree changed during normalization: {path}")


def require_normalized_config_tree(path: Path, uid: int, gid: int) -> None:
    expected = exact_directory(path, "configuration tree")
    root = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        opened = os.fstat(root)
        if (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino):
            raise RefreshError(f"configuration tree changed while opening it: {path}")
        root_device = opened.st_dev

        def require_directory_policy(metadata: os.stat_result, candidate: Path) -> None:
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != uid
                or metadata.st_gid != gid
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                raise RefreshError(
                    f"configuration directory violates the sealed 0700 policy: {candidate}"
                )

        def visit(directory: int, relative: Path) -> None:
            require_directory_policy(os.fstat(directory), path / relative)
            names = sorted(entry.name for entry in os.scandir(directory))
            for name in names:
                candidate = path / relative / name
                metadata = os.stat(name, dir_fd=directory, follow_symlinks=False)
                if metadata.st_dev != root_device:
                    raise RefreshError(f"configuration contains a mounted entry: {candidate}")
                if stat.S_ISDIR(metadata.st_mode):
                    child = os.open(
                        name,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                        dir_fd=directory,
                    )
                    try:
                        actual = os.fstat(child)
                        if (actual.st_dev, actual.st_ino) != (metadata.st_dev, metadata.st_ino):
                            raise RefreshError(f"configuration directory changed while opening: {candidate}")
                        visit(child, relative / name)
                    finally:
                        os.close(child)
                elif stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
                    child = os.open(
                        name,
                        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                        dir_fd=directory,
                    )
                    try:
                        actual = os.fstat(child)
                        if (
                            (actual.st_dev, actual.st_ino) != (metadata.st_dev, metadata.st_ino)
                            or actual.st_nlink != 1
                            or actual.st_uid != uid
                            or actual.st_gid != gid
                            or stat.S_IMODE(actual.st_mode) != 0o600
                        ):
                            raise RefreshError(
                                f"configuration file violates the sealed 0600 policy: {candidate}"
                            )
                    finally:
                        os.close(child)
                else:
                    raise RefreshError(f"configuration contains an unsafe entry: {candidate}")

        visit(root, Path("."))
    finally:
        os.close(root)
    final = exact_directory(path, "validated configuration tree")
    if (final.st_dev, final.st_ino) != (expected.st_dev, expected.st_ino):
        raise RefreshError(f"configuration tree changed during policy validation: {path}")


def copy_config(source: Path, destination: Path, uid: int, gid: int) -> None:
    if destination.exists() or destination.is_symlink():
        raise RefreshError(f"configuration staging path already exists: {destination}")
    destination.mkdir(mode=0o700)
    os.chown(destination, uid, gid)
    completed = subprocess.run(
        ["/usr/bin/cp", "-a", "--reflink=auto", "--", str(source) + "/.", str(destination) + "/"],
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise RefreshError(f"cannot copy GCloud configuration: {completed.stderr.strip()}")
    normalize_config_tree(destination, uid, gid)
    require_normalized_config_tree(destination, uid, gid)


def fsync_tree(root: Path) -> None:
    expected = exact_directory(root, "configuration tree")
    root_descriptor = os.open(
        root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    try:
        opened = os.fstat(root_descriptor)
        if (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino):
            raise RefreshError(f"configuration tree changed while opening it: {root}")
        root_device = opened.st_dev

        def visit(directory: int, relative: Path) -> None:
            names = sorted(entry.name for entry in os.scandir(directory))
            for name in names:
                candidate = root / relative / name
                metadata = os.stat(name, dir_fd=directory, follow_symlinks=False)
                if metadata.st_dev != root_device:
                    raise RefreshError(f"configuration contains a mounted entry: {candidate}")
                flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
                if stat.S_ISDIR(metadata.st_mode):
                    child = os.open(name, flags | os.O_DIRECTORY, dir_fd=directory)
                    try:
                        actual = os.fstat(child)
                        if (actual.st_dev, actual.st_ino) != (metadata.st_dev, metadata.st_ino):
                            raise RefreshError(f"configuration directory changed while opening: {candidate}")
                        visit(child, relative / name)
                        os.fsync(child)
                    finally:
                        os.close(child)
                elif stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
                    child = os.open(name, flags, dir_fd=directory)
                    try:
                        actual = os.fstat(child)
                        if (
                            (actual.st_dev, actual.st_ino) != (metadata.st_dev, metadata.st_ino)
                            or actual.st_nlink != 1
                        ):
                            raise RefreshError(f"configuration file changed while opening: {candidate}")
                        os.fsync(child)
                    finally:
                        os.close(child)
                else:
                    raise RefreshError(f"cannot fsync unsafe configuration entry: {candidate}")

        visit(root_descriptor, Path("."))
        os.fsync(root_descriptor)
    finally:
        os.close(root_descriptor)
    final = exact_directory(root, "fsynced configuration tree")
    if (final.st_dev, final.st_ino) != (expected.st_dev, expected.st_ino):
        raise RefreshError(f"configuration tree changed during fsync: {root}")


def renameat2(left: Path, right: Path, flags: int, operation: str) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    function = getattr(libc, "renameat2", None)
    if function is None:
        raise RefreshError("renameat2 is unavailable; atomic directory exchange is unsupported")
    function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    function.restype = ctypes.c_int
    result = function(AT_FDCWD, os.fsencode(left), AT_FDCWD, os.fsencode(right), flags)
    if result != 0:
        error = ctypes.get_errno()
        raise RefreshError(f"atomic configuration {operation} failed: {os.strerror(error)}")


def rename_exchange(left: Path, right: Path) -> None:
    renameat2(left, right, RENAME_EXCHANGE, "exchange")


def rename_noreplace(left: Path, right: Path) -> None:
    renameat2(left, right, RENAME_NOREPLACE, "no-clobber move")


def require_workspace(plan: dict[str, Any]) -> os.stat_result:
    workspace = plan["workspace"]
    path = Path(workspace["path"])
    metadata = exact_directory(path, "refresh workspace")
    observed = {
        "path": str(path),
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
    }
    if observed != workspace or metadata.st_uid != 0 or metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) != 0o711:
        raise RefreshError("refresh workspace does not match its sealed root-owned 0711 identity")
    return metadata


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def validate_plan(plan: dict[str, Any]) -> None:
    required = {
        "schema", "boot_id", "source_config", "source_snapshot", "account", "project",
        "gcloud_bin", "probe", "units", "lanes", "preparation_receipt", "intent_receipt",
        "completion_receipt", "workspace",
    }
    if set(plan) != required or plan.get("schema") != PLAN_SCHEMA or plan.get("boot_id") != base.read_boot_id():
        raise RefreshError("refresh plan has an invalid shape or boot binding")
    if not isinstance(plan.get("account"), str) or not plan["account"] or not isinstance(plan.get("project"), str) or not plan["project"]:
        raise RefreshError("refresh plan account or project is invalid")
    gcloud = Path(str(plan.get("gcloud_bin", "")))
    if not gcloud.is_absolute() or gcloud.resolve(strict=True) != gcloud:
        raise RefreshError("refresh plan GCloud binary is not exact")
    workspace = plan.get("workspace")
    if not isinstance(workspace, dict) or set(workspace) != WORKSPACE_KEYS:
        raise RefreshError("refresh plan workspace binding is invalid")
    if (
        not Path(str(workspace.get("path", ""))).is_absolute()
        or not isinstance(workspace.get("device"), int)
        or not isinstance(workspace.get("inode"), int)
        or workspace.get("device", 0) <= 0
        or workspace.get("inode", 0) <= 0
        or workspace.get("mode") != "0711"
        or workspace.get("uid") != 0
        or workspace.get("gid") != 0
    ):
        raise RefreshError("refresh plan workspace is not a sealed root-owned 0711 directory")
    probe = plan.get("probe")
    probe_keys = {"versioned_uri", "raw_id", "generation", "size", "crc32c_hash", "md5_hash"}
    if (
        not isinstance(probe, dict) or set(probe) != probe_keys
        or not isinstance(probe.get("generation"), int) or probe["generation"] <= 0
        or not isinstance(probe.get("size"), int) or probe["size"] <= 0
        or not all(
            isinstance(probe.get(key), str) and probe[key]
            for key in probe_keys - {"generation", "size", "md5_hash"}
        )
        or (probe.get("md5_hash") is not None and (not isinstance(probe["md5_hash"], str) or not probe["md5_hash"]))
    ):
        raise RefreshError("refresh plan probe is invalid")
    units = plan.get("units")
    if (
        not isinstance(units, list)
        or not units
        or any(
            not isinstance(unit, dict)
            or (
                set(unit) != LOADED_UNIT_BINDING_KEYS
                and set(unit) != RECOVERED_UNIT_BINDING_KEYS
            )
            for unit in units
        )
        or len({str(unit.get("name")) for unit in units}) != len(units)
    ):
        raise RefreshError("refresh plan units are invalid")
    for unit in units:
        common_invalid = (
            base.UNIT_NAME.fullmatch(str(unit.get("name", ""))) is None
            or unit.get("active_state") != "inactive"
            or unit.get("sub_state") != "dead"
            or not isinstance(unit.get("result"), str)
            or not isinstance(unit.get("unit_file_state"), str)
            or unit.get("invocation_id") != ""
            or unit.get("restarts") != 0
            or unit.get("triggers") != []
            or unit.get("triggered_by") != []
            or not isinstance(unit.get("claimed_lanes"), list)
            or not unit.get("claimed_lanes")
            or len(unit["claimed_lanes"]) != len(set(unit["claimed_lanes"]))
            or any(not isinstance(claim, str) or "=" not in claim for claim in unit["claimed_lanes"])
        )
        loaded_invalid = unit.get("kind") == "loaded-unit" and (
            set(unit) != LOADED_UNIT_BINDING_KEYS
            or not Path(str(unit.get("fragment_path", ""))).is_absolute()
            or SHA256.fullmatch(str(unit.get("fragment_sha256", ""))) is None
            or SHA256.fullmatch(str(unit.get("exec_start_sha256", ""))) is None
            or unit.get("load_state") != "loaded"
        )
        recovered_invalid = unit.get("kind") == "collected-transient" and (
            set(unit) != RECOVERED_UNIT_BINDING_KEYS
            or not Path(str(unit.get("recovery_receipt", ""))).is_absolute()
            or SHA256.fullmatch(str(unit.get("recovery_receipt_sha256", ""))) is None
            or SAFE_LABEL.fullmatch(str(unit.get("recovery_entry_label", ""))) is None
            or unit.get("load_state") != "not-found"
            or unit.get("unit_file_state") != ""
        )
        if (
            common_invalid
            or unit.get("kind") not in {"loaded-unit", "collected-transient"}
            or loaded_invalid
            or recovered_invalid
        ):
            raise RefreshError("refresh plan unit binding is not a sealed idle state")
    lanes = plan.get("lanes")
    if not isinstance(lanes, list) or not 1 <= len(lanes) <= 32:
        raise RefreshError("refresh plan must contain 1..32 lanes")
    if len({str(lane.get("label")) for lane in lanes if isinstance(lane, dict)}) != len(lanes):
        raise RefreshError("refresh plan lane labels are duplicated")
    seen: set[str] = set()
    lane_keys = {
        "label", "uid", "gid", "controller", "effective_config", "staged_config",
        "backup_config", "receipt",
    }
    for lane in lanes:
        if (
            not isinstance(lane, dict)
            or set(lane) != lane_keys
            or SAFE_LABEL.fullmatch(str(lane.get("label", ""))) is None
            or not isinstance(lane.get("uid"), int)
            or lane["uid"] < 0
            or not isinstance(lane.get("gid"), int)
            or lane["gid"] < 0
            or base.UNIT_NAME.fullmatch(str(lane.get("controller", ""))) is None
        ):
            raise RefreshError("refresh plan lane is invalid")
        paths = [Path(lane[key]) for key in ("effective_config", "staged_config", "backup_config", "receipt")]
        if any(not path.is_absolute() for path in paths) or any(str(path) in seen for path in paths):
            raise RefreshError("refresh plan lane paths are invalid or duplicated")
        seen.update(str(path) for path in paths)
        effective, staged, backup, _ = paths
        workspace_path = Path(workspace["path"])
        if (
            effective.name != "gcloud"
            or staged.parent != workspace_path
            or backup.parent != workspace_path
            or staged == backup
        ):
            raise RefreshError("refresh lane temporary paths must be distinct direct workspace children")
        claim = f"{lane['label']}={effective.parent.parent}"
        matching_units = [unit for unit in units if unit["name"] == lane["controller"]]
        if len(matching_units) != 1 or claim not in matching_units[0]["claimed_lanes"]:
            raise RefreshError(f"refresh lane lacks an exact controller claim: {lane['label']}")
    expected_claims = sorted(
        f"{lane['label']}={Path(lane['effective_config']).parent.parent}" for lane in lanes
    )
    observed_claims = sorted(claim for unit in units for claim in unit["claimed_lanes"])
    if observed_claims != expected_claims:
        raise RefreshError("refresh controller lane claims do not exactly cover the plan")
    source = Path(plan["source_config"])
    snapshot = Path(plan["source_snapshot"])
    if (
        not source.is_absolute()
        or not snapshot.is_absolute()
        or snapshot.parent != Path(workspace["path"])
        or source == snapshot
    ):
        raise RefreshError("refresh source paths are invalid")
    tree_paths = [source, *[Path(lane["effective_config"]) for lane in lanes]]
    temp_paths = [snapshot, *[Path(lane[key]) for lane in lanes for key in ("staged_config", "backup_config")]]
    receipt_paths = [
        Path(plan[key]) for key in ("preparation_receipt", "intent_receipt", "completion_receipt")
    ] + [Path(lane["receipt"]) for lane in lanes]
    if len({str(path) for path in temp_paths + receipt_paths + tree_paths}) != len(temp_paths + receipt_paths + tree_paths):
        raise RefreshError("refresh plan paths collide")
    for path in tree_paths + temp_paths + receipt_paths:
        if not path.is_absolute() or ".." in path.parts:
            raise RefreshError("refresh plan contains a non-canonical path")
    for index, path in enumerate(tree_paths):
        for other in tree_paths[index + 1:]:
            if _is_within(path, other) or _is_within(other, path):
                raise RefreshError("source and effective configuration trees overlap")
    workspace_path = Path(workspace["path"])
    if (
        any(_is_within(path, workspace_path) for path in receipt_paths)
        or any(_is_within(path, tree) for path in receipt_paths for tree in tree_paths)
        or any(_is_within(workspace_path, tree) or _is_within(tree, workspace_path) for tree in tree_paths)
    ):
        raise RefreshError("workspace, receipt, source, and effective paths must not overlap")
    require_workspace(plan)


def receipt_path(value: str, label: str) -> Path:
    try:
        return base.require_receipt_path(value, label)
    except base.RetirementError as error:
        raise RefreshError(str(error)) from error


def validate_authority_path_separation(plan_path: Path, plan: dict[str, Any]) -> None:
    mutable_trees = [
        Path(plan["source_config"]).resolve(strict=True),
        Path(plan["workspace"]["path"]).resolve(strict=True),
        *[
            Path(lane["effective_config"]).resolve(strict=True)
            for lane in plan["lanes"]
        ],
    ]
    evidence_paths = [
        plan_path.resolve(strict=True),
        Path(plan["gcloud_bin"]).resolve(strict=True),
        receipt_path(plan["preparation_receipt"], "preparation receipt"),
        receipt_path(plan["intent_receipt"], "intent receipt"),
        receipt_path(plan["completion_receipt"], "completion receipt"),
        *[receipt_path(lane["receipt"], "lane receipt") for lane in plan["lanes"]],
    ]
    for binding in plan["units"]:
        if binding["kind"] == "loaded-unit":
            evidence_paths.append(Path(binding["fragment_path"]).resolve(strict=True))
            continue
        recovery_path = Path(binding["recovery_receipt"]).resolve(strict=True)
        evidence_paths.append(recovery_path)
        try:
            receipt, _ = base.require_root_private_json(
                recovery_path, "recovered controller command receipt"
            )
        except base.RetirementError as error:
            raise RefreshError(str(error)) from error
        matches = [
            entry
            for entry in receipt.get("entries", [])
            if isinstance(entry, dict)
            and entry.get("label") == binding["recovery_entry_label"]
        ]
        if len(matches) != 1:
            raise RefreshError("cannot resolve recovered controller authority paths")
        for key in ("controller", "state"):
            record = matches[0].get(key)
            if not isinstance(record, dict) or not isinstance(record.get("path"), str):
                raise RefreshError("recovered controller authority omits an evidence path")
            evidence_paths.append(Path(record["path"]).resolve(strict=True))
    canonical_evidence = [path.parent.resolve(strict=True) / path.name for path in evidence_paths]
    if len({str(path) for path in canonical_evidence}) != len(canonical_evidence):
        raise RefreshError("refresh authority and receipt paths collide")
    for evidence in canonical_evidence:
        for tree in mutable_trees:
            if _is_within(evidence, tree) or _is_within(tree, evidence):
                raise RefreshError(
                    f"refresh authority path overlaps a mutable configuration tree: {evidence}"
                )


def lane_receipt_matches(
    path: Path,
    plan_sha256: str,
    plan: dict[str, Any],
    lane: dict[str, Any],
    bound: dict[str, Any],
) -> dict[str, Any]:
    try:
        payload, _ = base.require_root_private_json(path, "lane refresh receipt")
    except base.RetirementError as error:
        raise RefreshError(str(error)) from error
    required = {
        "schema", "status", "observed_at_utc", "plan_sha256", "boot_id", "label",
        "effective_config", "old_summary", "staged_summary", "effective_summary", "probe",
        "remote_mutations", "r2_mutations",
    }
    if (
        set(payload) != required
        or payload.get("schema") != LANE_SCHEMA
        or payload.get("plan_sha256") != plan_sha256
        or payload.get("boot_id") != plan["boot_id"]
        or payload.get("label") != lane["label"]
        or payload.get("status") != "installed-and-validated"
        or payload.get("effective_config") != lane["effective_config"]
        or payload.get("old_summary") != bound["old_summary"]
        or payload.get("staged_summary") != bound["staged_summary"]
        or payload.get("probe") != bound["staged_probe"]
        or payload.get("remote_mutations") is not False
        or payload.get("r2_mutations") is not False
    ):
        raise RefreshError(f"lane receipt does not bind this refresh: {path}")
    require_normalized_config_tree(
        Path(lane["effective_config"]), lane["uid"], lane["gid"]
    )
    current = tree_summary(Path(lane["effective_config"]))
    if payload.get("effective_summary") != current:
        raise RefreshError(f"lane configuration changed after its refresh receipt: {path}")
    return payload


def ensure_initial_paths(plan: dict[str, Any]) -> list[dict[str, Any]]:
    require_workspace(plan)
    source = Path(plan["source_config"])
    exact_directory(source, "source GCloud configuration")
    lanes: list[dict[str, Any]] = []
    for lane in plan["lanes"]:
        effective = Path(lane["effective_config"])
        effective_metadata = exact_directory(effective, "effective lane GCloud configuration")
        if (
            stat.S_IMODE(effective_metadata.st_mode) != 0o700
            or effective_metadata.st_uid != lane["uid"]
            or effective_metadata.st_gid != lane["gid"]
        ):
            raise RefreshError(
                f"effective lane configuration does not match its exact 0700 identity: {effective}"
            )
        for key in ("staged_config", "backup_config"):
            path = Path(lane[key])
            if path.exists() or path.is_symlink():
                raise RefreshError(f"unused lane refresh path already exists: {path}")
        receipt = receipt_path(lane["receipt"], "lane receipt")
        if receipt.exists() or receipt.is_symlink():
            raise RefreshError(f"unused lane receipt already exists: {receipt}")
        lanes.append({**lane, "effective_metadata": effective_metadata})
    snapshot = Path(plan["source_snapshot"])
    if snapshot.exists() or snapshot.is_symlink():
        raise RefreshError(f"unused source snapshot already exists: {snapshot}")
    return lanes


def build_preparation(plan_path: Path, plan_sha256: str, plan: dict[str, Any]) -> dict[str, Any]:
    lanes = ensure_initial_paths(plan)
    targets = [Path(lane["effective_config"]) for lane in plan["lanes"]]
    unit_states = require_idle(plan["units"], targets)
    active_gcloud = live_gcloud_processes()
    if active_gcloud:
        raise RefreshError(f"GCloud processes are still live: {active_gcloud}")
    source = Path(plan["source_config"])
    source_probe = probe_config(source, plan)
    if live_gcloud_processes():
        raise RefreshError("a GCloud process remained after source authentication probe")
    source_summary = tree_summary(source)
    lane_records: list[dict[str, Any]] = []
    for lane in lanes:
        lane_records.append({
            "label": lane["label"],
            "uid": lane["uid"],
            "gid": lane["gid"],
            "controller": lane["controller"],
            "effective_config": lane["effective_config"],
            "staged_config": lane["staged_config"],
            "backup_config": lane["backup_config"],
            "receipt": lane["receipt"],
            # A newly staged dormant lane can legitimately have an empty
            # configuration directory before its first credential install.
            # Keep that empty identity fully bound so the atomic exchange and
            # retained backup remain auditable.
            "old_summary": tree_summary(
                Path(lane["effective_config"]), allow_empty=True
            ),
        })
    return {
        "schema": PREPARATION_SCHEMA,
        "status": "copy-preparation-fsynced",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "plan": str(plan_path),
        "plan_sha256": plan_sha256,
        "boot_id": plan["boot_id"],
        "unit_states": unit_states,
        "source_config": source_summary,
        "source_probe": source_probe,
        "lanes": lane_records,
        "remote_mutations": False,
        "r2_mutations": False,
    }


def load_preparation(path: Path, plan_path: Path, plan_sha256: str, plan: dict[str, Any]) -> dict[str, Any]:
    try:
        payload, _ = base.require_root_private_json(path, "refresh preparation")
    except base.RetirementError as error:
        raise RefreshError(str(error)) from error
    required = {
        "schema", "status", "observed_at_utc", "plan", "plan_sha256", "boot_id",
        "unit_states", "source_config", "source_probe", "lanes", "remote_mutations",
        "r2_mutations",
    }
    if (
        set(payload) != required
        or payload.get("schema") != PREPARATION_SCHEMA
        or payload.get("status") != "copy-preparation-fsynced"
        or payload.get("plan") != str(plan_path)
        or payload.get("plan_sha256") != plan_sha256
        or payload.get("boot_id") != plan["boot_id"]
        or payload.get("remote_mutations") is not False
        or payload.get("r2_mutations") is not False
        or payload.get("unit_states") != plan["units"]
    ):
        raise RefreshError("refresh preparation does not bind this plan")
    records = payload.get("lanes")
    if not isinstance(records, list) or len(records) != len(plan["lanes"]):
        raise RefreshError("refresh preparation has an invalid lane set")
    record_keys = {
        "label", "uid", "gid", "controller", "effective_config", "staged_config",
        "backup_config", "receipt", "old_summary",
    }
    for lane in plan["lanes"]:
        matches = [record for record in records if isinstance(record, dict) and record.get("label") == lane["label"]]
        if len(matches) != 1 or set(matches[0]) != record_keys:
            raise RefreshError(f"refresh preparation lacks one exact lane binding for {lane['label']}")
        record = matches[0]
        for key in (
            "label", "uid", "gid", "controller", "effective_config", "staged_config",
            "backup_config", "receipt",
        ):
            if record.get(key) != lane[key]:
                raise RefreshError(f"refresh preparation lane binding changed for {lane['label']}")
    return payload


def preparation_lane(preparation: dict[str, Any], label: str) -> dict[str, Any]:
    matches = [
        item
        for item in preparation.get("lanes", [])
        if isinstance(item, dict) and item.get("label") == label
    ]
    if len(matches) != 1:
        raise RefreshError(f"refresh preparation lacks one lane binding for {label}")
    return matches[0]


def reset_pre_intent_paths(plan: dict[str, Any], preparation: dict[str, Any]) -> None:
    require_workspace(plan)
    targets = [Path(lane["effective_config"]) for lane in plan["lanes"]]
    require_idle(plan["units"], targets)
    if live_gcloud_processes():
        raise RefreshError("GCloud processes are still live while resuming preparation")
    for lane in plan["lanes"]:
        bound = preparation_lane(preparation, lane["label"])
        effective = Path(lane["effective_config"])
        metadata = exact_directory(effective, "effective lane GCloud configuration")
        if (
            stat.S_IMODE(metadata.st_mode) != 0o700
            or metadata.st_uid != lane["uid"]
            or metadata.st_gid != lane["gid"]
            or not same_content(
                tree_summary(effective, allow_empty=True), bound["old_summary"]
            )
        ):
            raise RefreshError(f"effective configuration changed before exchange for {lane['label']}")
        for key in ("backup_config", "receipt"):
            candidate = Path(lane[key])
            if candidate.exists() or candidate.is_symlink():
                raise RefreshError(f"pre-intent resume found an unsafe {key}: {candidate}")
        staged = Path(lane["staged_config"])
        if staged.exists() or staged.is_symlink():
            references = process_references(staged)
            if references:
                raise RefreshError(f"live process references partial staging tree {staged}: {references}")
            base.delete_exact_tree(staged)
            base.fsync_directory(Path(plan["workspace"]["path"]))
    snapshot = Path(plan["source_snapshot"])
    if snapshot.exists() or snapshot.is_symlink():
        references = process_references(snapshot)
        if references:
            raise RefreshError(f"live process references partial source snapshot {snapshot}: {references}")
        base.delete_exact_tree(snapshot)
        base.fsync_directory(Path(plan["workspace"]["path"]))


def build_intent(
    plan_path: Path,
    plan_sha256: str,
    plan: dict[str, Any],
    preparation: dict[str, Any],
) -> dict[str, Any]:
    reset_pre_intent_paths(plan, preparation)
    source = Path(plan["source_config"])
    source_before = tree_summary(source)
    if not same_content(source_before, preparation["source_config"]):
        raise RefreshError("source GCloud configuration changed after preparation")
    snapshot = Path(plan["source_snapshot"])
    source_metadata = exact_directory(source, "source GCloud configuration")
    copy_config(source, snapshot, source_metadata.st_uid, source_metadata.st_gid)
    base.fsync_directory(Path(plan["workspace"]["path"]))
    source_after = tree_summary(source)
    snapshot_before_probe = tree_summary(snapshot)
    if not same_content(source_before, source_after) or not same_content(source_before, snapshot_before_probe):
        raise RefreshError("source GCloud configuration changed during coherent snapshot copy")
    snapshot_probe = probe_config(snapshot, plan)
    normalize_config_tree(snapshot, source_metadata.st_uid, source_metadata.st_gid)
    require_normalized_config_tree(snapshot, source_metadata.st_uid, source_metadata.st_gid)
    fsync_tree(snapshot)
    snapshot_summary = tree_summary(snapshot)
    lane_records: list[dict[str, Any]] = []
    for lane in plan["lanes"]:
        effective = Path(lane["effective_config"])
        staged = Path(lane["staged_config"])
        old_summary = preparation_lane(preparation, lane["label"])["old_summary"]
        copy_config(snapshot, staged, lane["uid"], lane["gid"])
        base.fsync_directory(Path(plan["workspace"]["path"]))
        copied = tree_summary(staged)
        if not same_content(snapshot_summary, copied):
            raise RefreshError(f"staged configuration copy differs for {lane['label']}")
        stage_probe = probe_config(staged, plan)
        normalize_config_tree(staged, lane["uid"], lane["gid"])
        require_normalized_config_tree(staged, lane["uid"], lane["gid"])
        fsync_tree(staged)
        staged_summary = tree_summary(staged)
        lane_records.append({
            "label": lane["label"],
            "controller": lane["controller"],
            "effective_config": str(effective),
            "staged_config": str(staged),
            "backup_config": lane["backup_config"],
            "receipt": lane["receipt"],
            "old_summary": old_summary,
            "staged_summary": staged_summary,
            "staged_probe": stage_probe,
        })
    if live_gcloud_processes():
        raise RefreshError("a GCloud process remained after lane validation probes")
    return {
        "schema": INTENT_SCHEMA,
        "status": "exchange-intent-fsynced",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "plan": str(plan_path),
        "plan_sha256": plan_sha256,
        "boot_id": plan["boot_id"],
        "unit_states": require_idle(plan["units"], [Path(lane["effective_config"]) for lane in plan["lanes"]]),
        "source_config": source_before,
        "source_probe": preparation["source_probe"],
        "source_snapshot": snapshot_summary,
        "source_snapshot_probe": snapshot_probe,
        "lanes": lane_records,
        "remote_mutations": False,
        "r2_mutations": False,
    }


def load_intent(
    path: Path,
    plan_path: Path,
    plan_sha256: str,
    plan: dict[str, Any],
    preparation: dict[str, Any],
) -> dict[str, Any]:
    try:
        payload, _ = base.require_root_private_json(path, "refresh intent")
    except base.RetirementError as error:
        raise RefreshError(str(error)) from error
    required = {
        "schema", "status", "observed_at_utc", "plan", "plan_sha256", "boot_id",
        "unit_states", "source_config", "source_probe", "source_snapshot",
        "source_snapshot_probe", "lanes", "remote_mutations", "r2_mutations",
    }
    if (
        set(payload) != required
        or payload.get("schema") != INTENT_SCHEMA
        or payload.get("status") != "exchange-intent-fsynced"
        or payload.get("plan") != str(plan_path)
        or payload.get("plan_sha256") != plan_sha256
        or payload.get("boot_id") != plan["boot_id"]
        or payload.get("unit_states") != plan["units"]
        or payload.get("source_config") != preparation["source_config"]
        or payload.get("source_probe") != preparation["source_probe"]
        or payload.get("remote_mutations") is not False
        or payload.get("r2_mutations") is not False
    ):
        raise RefreshError("refresh intent does not bind this plan")
    records = payload.get("lanes")
    record_keys = {
        "label", "controller", "effective_config", "staged_config", "backup_config",
        "receipt", "old_summary", "staged_summary", "staged_probe",
    }
    if not isinstance(records, list) or len(records) != len(plan["lanes"]):
        raise RefreshError("refresh intent has an invalid lane set")
    for lane in plan["lanes"]:
        bound = intent_lane(payload, lane["label"])
        if set(bound) != record_keys:
            raise RefreshError(f"refresh intent lane has an invalid shape for {lane['label']}")
        for key in (
            "label", "controller", "effective_config", "staged_config", "backup_config",
            "receipt",
        ):
            if bound.get(key) != lane[key]:
                raise RefreshError(f"refresh intent lane binding changed for {lane['label']}")
        if bound.get("old_summary") != preparation_lane(preparation, lane["label"])["old_summary"]:
            raise RefreshError(f"refresh intent old summary changed for {lane['label']}")
    return payload


def intent_lane(intent: dict[str, Any], label: str) -> dict[str, Any]:
    matches = [item for item in intent.get("lanes", []) if isinstance(item, dict) and item.get("label") == label]
    if len(matches) != 1:
        raise RefreshError(f"refresh intent lacks one lane binding for {label}")
    return matches[0]


def install_lane(plan: dict[str, Any], plan_sha256: str, lane: dict[str, Any], bound: dict[str, Any]) -> dict[str, Any]:
    require_workspace(plan)
    effective = Path(lane["effective_config"])
    staged = Path(lane["staged_config"])
    backup = Path(lane["backup_config"])
    receipt = receipt_path(lane["receipt"], "lane receipt")
    if receipt.exists() or receipt.is_symlink():
        payload = lane_receipt_matches(receipt, plan_sha256, plan, lane, bound)
        if backup.exists() or backup.is_symlink():
            backup_summary = tree_summary(backup, allow_empty=True)
            if not same_tree_identity(backup_summary, bound["old_summary"]):
                raise RefreshError(f"receipted backup identity changed for {lane['label']}")
            references = process_references(backup)
            if references:
                raise RefreshError(f"live process references retained backup {backup}: {references}")
        else:
            raise RefreshError(f"receipted lane lacks its retained backup: {backup}")
        if staged.exists() or staged.is_symlink():
            raise RefreshError(f"staging path remains after completed lane receipt: {staged}")
        return payload
    require_idle(plan["units"], (effective, staged, backup))
    effective_summary = tree_summary(effective, allow_empty=True)
    staged_exists = staged.exists() or staged.is_symlink()
    backup_exists = backup.exists() or backup.is_symlink()
    if backup_exists:
        backup_summary = tree_summary(backup, allow_empty=True)
        if not same_tree_identity(backup_summary, bound["old_summary"]):
            raise RefreshError(f"backup configuration changed for {lane['label']}")
        if (
            staged_exists
            or not same_tree_identity(effective_summary, bound["staged_summary"])
        ):
            raise RefreshError(f"invalid post-exchange path state for {lane['label']}")
    elif staged_exists:
        staged_summary = tree_summary(staged, allow_empty=True)
        if (
            same_tree_identity(effective_summary, bound["old_summary"])
            and same_tree_identity(staged_summary, bound["staged_summary"])
        ):
            require_idle(plan["units"], (effective, staged, backup))
            rename_exchange(effective, staged)
            base.fsync_directory(effective.parent)
            base.fsync_directory(Path(plan["workspace"]["path"]))
            exchanged_old = tree_summary(staged, allow_empty=True)
            exchanged_new = tree_summary(effective)
            if (
                not same_tree_identity(exchanged_old, bound["old_summary"])
                or not same_tree_identity(exchanged_new, bound["staged_summary"])
            ):
                raise RefreshError(f"atomic exchange identities changed for {lane['label']}")
            require_idle(plan["units"], (effective, staged, backup))
            rename_noreplace(staged, backup)
            base.fsync_directory(Path(plan["workspace"]["path"]))
        elif (
            same_tree_identity(staged_summary, bound["old_summary"])
            and same_tree_identity(effective_summary, bound["staged_summary"])
        ):
            require_idle(plan["units"], (effective, staged, backup))
            rename_noreplace(staged, backup)
            base.fsync_directory(Path(plan["workspace"]["path"]))
        else:
            raise RefreshError(f"cannot identify interrupted exchange state for {lane['label']}")
    else:
        raise RefreshError(f"lane has neither staged nor backup configuration: {lane['label']}")
    require_idle(plan["units"], (effective, backup))
    if not same_tree_identity(tree_summary(effective), bound["staged_summary"]):
        raise RefreshError(f"installed configuration differs from the sealed staged tree for {lane['label']}")
    require_normalized_config_tree(effective, lane["uid"], lane["gid"])
    probe = probe_config(effective, plan)
    normalize_config_tree(effective, lane["uid"], lane["gid"])
    require_normalized_config_tree(effective, lane["uid"], lane["gid"])
    fsync_tree(effective)
    final_summary = tree_summary(effective)
    payload = {
        "schema": LANE_SCHEMA,
        "status": "installed-and-validated",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "plan_sha256": plan_sha256,
        "boot_id": plan["boot_id"],
        "label": lane["label"],
        "effective_config": str(effective),
        "old_summary": bound["old_summary"],
        "staged_summary": bound["staged_summary"],
        "effective_summary": final_summary,
        "probe": probe,
        "remote_mutations": False,
        "r2_mutations": False,
    }
    base.write_json_noclobber(receipt, payload)
    lane_receipt_matches(receipt, plan_sha256, plan, lane, bound)
    references = process_references(backup)
    if references:
        raise RefreshError(f"live process references retained backup {backup}: {references}")
    backup_summary = tree_summary(backup, allow_empty=True)
    if not same_tree_identity(backup_summary, bound["old_summary"]):
        raise RefreshError(f"backup identity changed after receipt for {lane['label']}")
    return payload


def validate_completion(
    payload: dict[str, Any],
    args_plan: Path,
    plan_sha256: str,
    plan: dict[str, Any],
    preparation_path: Path,
    intent_path: Path,
    intent: dict[str, Any],
) -> None:
    required = {
        "schema", "status", "observed_at_utc", "plan", "plan_sha256", "boot_id",
        "preparation_receipt", "preparation_receipt_sha256", "intent_receipt",
        "intent_receipt_sha256", "lane_receipts", "lane_count", "source_snapshot_retained",
        "backups_retained", "remote_mutations", "r2_mutations",
    }
    if (
        set(payload) != required
        or payload.get("schema") != COMPLETION_SCHEMA
        or payload.get("status") != "installed-and-validated"
        or payload.get("plan") != str(args_plan)
        or payload.get("plan_sha256") != plan_sha256
        or payload.get("boot_id") != plan["boot_id"]
        or payload.get("preparation_receipt") != str(preparation_path)
        or payload.get("preparation_receipt_sha256") != base.sha256_file(preparation_path)
        or payload.get("intent_receipt") != str(intent_path)
        or payload.get("intent_receipt_sha256") != base.sha256_file(intent_path)
        or payload.get("lane_count") != len(plan["lanes"])
        or payload.get("source_snapshot_retained") is not True
        or payload.get("backups_retained") is not True
        or payload.get("remote_mutations") is not False
        or payload.get("r2_mutations") is not False
    ):
        raise RefreshError("refresh completion does not bind this plan")
    snapshot = Path(plan["source_snapshot"])
    if not snapshot.exists() and not snapshot.is_symlink():
        raise RefreshError("refresh completion exists without the retained source snapshot")
    if not same_tree_identity(tree_summary(snapshot), intent["source_snapshot"]):
        raise RefreshError("retained source snapshot identity changed")
    expected_receipts: list[dict[str, str]] = []
    for lane in plan["lanes"]:
        bound = intent_lane(intent, lane["label"])
        path = receipt_path(lane["receipt"], "lane receipt")
        lane_receipt_matches(path, plan_sha256, plan, lane, bound)
        staged = Path(lane["staged_config"])
        backup = Path(lane["backup_config"])
        if staged.exists() or staged.is_symlink():
            raise RefreshError(f"refresh completion exists with a staged lane path for {lane['label']}")
        if not backup.exists() and not backup.is_symlink():
            raise RefreshError(f"refresh completion lacks the retained backup for {lane['label']}")
        if not same_tree_identity(
            tree_summary(backup, allow_empty=True), bound["old_summary"]
        ):
            raise RefreshError(f"retained backup identity changed for {lane['label']}")
        expected_receipts.append({"path": str(path), "sha256": base.sha256_file(path)})
    if payload.get("lane_receipts") != expected_receipts:
        raise RefreshError("refresh completion has an invalid lane receipt set")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--check-only", action="store_true")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    if os.geteuid() != 0:
        parser.error("idle GCloud configuration refresh must run as root")
    try:
        plan, plan_sha256 = base.require_root_private_json(args.plan, "refresh plan")
        validate_plan(plan)
        validate_authority_path_separation(args.plan, plan)
    except base.RetirementError as error:
        raise RefreshError(str(error)) from error
    preparation_path = receipt_path(plan["preparation_receipt"], "preparation receipt")
    intent_path = receipt_path(plan["intent_receipt"], "intent receipt")
    completion_path = receipt_path(plan["completion_receipt"], "completion receipt")
    all_receipts = [preparation_path, intent_path, completion_path] + [
        receipt_path(lane["receipt"], "lane receipt") for lane in plan["lanes"]
    ]
    if len(set(all_receipts)) != len(all_receipts):
        raise RefreshError("preparation, intent, lane, and completion receipts must differ")
    if completion_path.exists() or completion_path.is_symlink():
        try:
            completed, _ = base.require_root_private_json(completion_path, "refresh completion")
        except base.RetirementError as error:
            raise RefreshError(str(error)) from error
        preparation = load_preparation(preparation_path, args.plan, plan_sha256, plan)
        intent = load_intent(intent_path, args.plan, plan_sha256, plan, preparation)
        validate_completion(
            completed, args.plan, plan_sha256, plan, preparation_path, intent_path, intent
        )
        print(json.dumps(completed, sort_keys=True), flush=True)
        return 0
    preparation_exists = preparation_path.exists() or preparation_path.is_symlink()
    intent_exists = intent_path.exists() or intent_path.is_symlink()
    if args.check_only:
        if preparation_exists or intent_exists:
            raise RefreshError("check-only requires unused preparation and intent paths")
        lanes = ensure_initial_paths(plan)
        states = require_idle(plan["units"], [Path(lane["effective_config"]) for lane in lanes])
        if live_gcloud_processes():
            raise RefreshError("GCloud processes are still live during check-only")
        source_probe = probe_config(Path(plan["source_config"]), plan)
        if live_gcloud_processes():
            raise RefreshError("a GCloud process remained after the check-only probe")
        print(json.dumps({
            "check_only": True,
            "plan_sha256": plan_sha256,
            "lane_count": len(lanes),
            "unit_states": states,
            "source_probe": source_probe,
            "remote_mutations": False,
            "r2_mutations": False,
        }, sort_keys=True), flush=True)
        return 0
    if preparation_exists:
        preparation = load_preparation(preparation_path, args.plan, plan_sha256, plan)
    else:
        if intent_exists:
            raise RefreshError("refresh intent exists without its preparation receipt")
        preparation = build_preparation(args.plan, plan_sha256, plan)
        base.write_json_noclobber(preparation_path, preparation)
    if intent_exists:
        intent = load_intent(intent_path, args.plan, plan_sha256, plan, preparation)
    else:
        intent = build_intent(args.plan, plan_sha256, plan, preparation)
        base.write_json_noclobber(intent_path, intent)
    lanes: list[dict[str, Any]] = []
    for lane in plan["lanes"]:
        lanes.append(install_lane(plan, plan_sha256, lane, intent_lane(intent, lane["label"])))
    snapshot = Path(plan["source_snapshot"])
    if not snapshot.exists() and not snapshot.is_symlink():
        raise RefreshError("source snapshot disappeared before completion")
    if not same_tree_identity(tree_summary(snapshot), intent["source_snapshot"]):
        raise RefreshError("source snapshot changed before completion")
    lane_receipts = []
    for lane in plan["lanes"]:
        path = receipt_path(lane["receipt"], "lane receipt")
        lane_receipt_matches(
            path, plan_sha256, plan, lane, intent_lane(intent, lane["label"])
        )
        lane_receipts.append({"path": str(path), "sha256": base.sha256_file(path)})
    completion = {
        "schema": COMPLETION_SCHEMA,
        "status": "installed-and-validated",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "plan": str(args.plan),
        "plan_sha256": plan_sha256,
        "boot_id": plan["boot_id"],
        "preparation_receipt": str(preparation_path),
        "preparation_receipt_sha256": base.sha256_file(preparation_path),
        "intent_receipt": str(intent_path),
        "intent_receipt_sha256": base.sha256_file(intent_path),
        "lane_receipts": lane_receipts,
        "lane_count": len(lanes),
        "source_snapshot_retained": True,
        "backups_retained": True,
        "remote_mutations": False,
        "r2_mutations": False,
    }
    base.write_json_noclobber(completion_path, completion)
    validate_completion(
        completion, args.plan, plan_sha256, plan, preparation_path, intent_path, intent
    )
    print(json.dumps(completion, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RefreshError, base.RetirementError, subprocess.CalledProcessError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1) from error
