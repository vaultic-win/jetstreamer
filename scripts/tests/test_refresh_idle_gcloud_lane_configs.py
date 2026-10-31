import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from subprocess import CompletedProcess
from unittest.mock import patch

from scripts import refresh_idle_gcloud_lane_configs as refresh


class IdleGCloudRefreshTests(unittest.TestCase):
    def test_direct_cli_help_is_cwd_independent(self) -> None:
        with TemporaryDirectory() as temporary:
            completed = subprocess.run(
                [sys.executable, str(Path(refresh.__file__).resolve()), "--help"],
                cwd=temporary,
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def probe(self) -> dict:
        return {
            "versioned_uri": "gs://bucket/object#123",
            "raw_id": "bucket/o/object/123",
            "generation": 123,
            "size": 456,
            "crc32c_hash": "abcd==",
            "md5_hash": "efgh==",
        }

    def test_accepts_normalized_probe_shape(self) -> None:
        payload = {
            "storage_url": "gs://bucket/object#123",
            "generation": 123,
            "size": 456,
            "crc32c_hash": "abcd==",
            "md5_hash": "efgh==",
        }
        self.assertEqual(refresh.parse_probe_metadata(payload, self.probe())["generation"], 123)

    def test_accepts_raw_probe_shape(self) -> None:
        payload = {
            "id": "bucket/o/object/123",
            "generation": "123",
            "size": "456",
            "crc32c": "abcd==",
            "md5Hash": "efgh==",
        }
        self.assertEqual(refresh.parse_probe_metadata(payload, self.probe())["identity_field"], "id")

    def test_accepts_composite_object_null_md5_and_rejects_missing_md5(self) -> None:
        expected = self.probe()
        expected["md5_hash"] = None
        payload = {
            "storage_url": "gs://bucket/object#123",
            "generation": 123,
            "size": 456,
            "crc32c_hash": "abcd==",
            "md5_hash": None,
        }
        self.assertIsNone(refresh.parse_probe_metadata(payload, expected)["md5_hash"])
        del payload["md5_hash"]
        with self.assertRaisesRegex(refresh.RefreshError, "omits MD5"):
            refresh.parse_probe_metadata(payload, expected)

    def test_rejects_conflicting_hash_aliases(self) -> None:
        payload = {
            "storage_url": "gs://bucket/object#123",
            "generation": 123,
            "size": 456,
            "crc32c_hash": "abcd==",
            "crc32c": "different",
            "md5_hash": "efgh==",
        }
        with self.assertRaisesRegex(refresh.RefreshError, "conflicting CRC32C"):
            refresh.parse_probe_metadata(payload, self.probe())

    @patch("scripts.refresh_idle_gcloud_lane_configs.os.path.ismount", return_value=False)
    def test_tree_summary_detects_content_change_and_rejects_symlink(self, _ismount) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary) / "config"
            root.mkdir(mode=0o700)
            (root / "credentials.db").write_bytes(b"one")
            first = refresh.tree_summary(root)
            (root / "credentials.db").write_bytes(b"two")
            second = refresh.tree_summary(root)
            self.assertFalse(refresh.same_content(first, second))
            (root / "link").symlink_to(root / "credentials.db")
            with self.assertRaisesRegex(refresh.RefreshError, "special file or symlink"):
                refresh.tree_summary(root)

    @patch("scripts.refresh_idle_gcloud_lane_configs.os.path.ismount", return_value=False)
    def test_tree_summary_allows_only_explicitly_bound_empty_lane(self, _ismount) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary) / "config"
            root.mkdir(mode=0o700)
            with self.assertRaisesRegex(refresh.RefreshError, "contains no files"):
                refresh.tree_summary(root)
            summary = refresh.tree_summary(root, allow_empty=True)
            self.assertEqual(summary["file_count"], 0)
            self.assertEqual(summary["file_bytes"], 0)

    @patch("scripts.refresh_idle_gcloud_lane_configs.os.path.ismount", return_value=False)
    def test_install_accepts_empty_initial_lane_and_retains_empty_backup(self, _ismount) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            effective = root / "gcloud"
            staged = root / "gcloud.staged"
            backup = root / "gcloud.backup"
            receipt = root / "lane.json"
            effective.mkdir(mode=0o700)
            staged.mkdir(mode=0o700)
            (staged / "credentials.db").write_bytes(b"new")
            refresh.normalize_config_tree(staged, os.getuid(), os.getgid())
            old_summary = refresh.tree_summary(effective, allow_empty=True)
            staged_summary = refresh.tree_summary(staged)
            staged_probe = {"generation": 123, "identity_field": "storage_url"}
            lane = {
                "label": "lane-a",
                "uid": os.getuid(),
                "gid": os.getgid(),
                "controller": "controller.service",
                "effective_config": str(effective),
                "staged_config": str(staged),
                "backup_config": str(backup),
                "receipt": str(receipt),
            }
            bound = {
                "old_summary": old_summary,
                "staged_summary": staged_summary,
                "staged_probe": staged_probe,
            }
            plan = {
                "units": [],
                "boot_id": "a" * 32,
                "workspace": {"path": str(root)},
            }

            def read_test_receipt(path: Path, _label: str) -> tuple[dict, str]:
                return json.loads(path.read_text()), "unused"

            with (
                patch.object(refresh, "receipt_path", return_value=receipt),
                patch.object(refresh, "require_workspace"),
                patch.object(refresh, "require_idle", return_value=[]),
                patch.object(refresh, "process_references", return_value=[]),
                patch.object(refresh, "probe_config", return_value=staged_probe),
                patch.object(
                    refresh.base,
                    "require_root_private_json",
                    side_effect=read_test_receipt,
                ),
            ):
                refresh.install_lane(plan, "d" * 64, lane, bound)
            self.assertEqual((effective / "credentials.db").read_bytes(), b"new")
            self.assertTrue(backup.is_dir())
            self.assertEqual(
                refresh.tree_summary(backup, allow_empty=True)["file_count"], 0
            )

    @patch("scripts.refresh_idle_gcloud_lane_configs.os.path.ismount", return_value=False)
    def test_atomic_directory_exchange(self, _ismount) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            left = root / "left"
            right = root / "right"
            left.mkdir()
            right.mkdir()
            (left / "value").write_text("left")
            (right / "value").write_text("right")
            refresh.rename_exchange(left, right)
            self.assertEqual((left / "value").read_text(), "right")
            self.assertEqual((right / "value").read_text(), "left")

    @patch("scripts.refresh_idle_gcloud_lane_configs.os.path.ismount", return_value=False)
    def test_no_clobber_move_rejects_existing_destination(self, _ismount) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            destination = root / "destination"
            source.mkdir()
            destination.mkdir()
            with self.assertRaisesRegex(refresh.RefreshError, "no-clobber move failed"):
                refresh.rename_noreplace(source, destination)
            self.assertTrue(source.is_dir())
            self.assertTrue(destination.is_dir())

    def test_probe_uses_sanitized_privilege_drop_environment(self) -> None:
        expected = self.probe()
        payload = {
            "storage_url": expected["versioned_uri"],
            "generation": expected["generation"],
            "size": expected["size"],
            "crc32c_hash": expected["crc32c_hash"],
            "md5_hash": expected["md5_hash"],
        }
        metadata = SimpleNamespace(st_uid=os.getuid(), st_gid=os.getgid())
        account = SimpleNamespace(pw_name="lane-user", pw_dir="/lane-home", pw_gid=os.getgid())
        completed = CompletedProcess([], 0, stdout=json.dumps(payload), stderr="")
        plan = {
            "gcloud_bin": "/usr/bin/gcloud",
            "account": "account@example.invalid",
            "project": "sealed-project",
            "probe": expected,
        }
        with (
            patch.object(refresh, "exact_directory", return_value=metadata),
            patch.object(refresh.pwd, "getpwuid", return_value=account),
            patch.object(refresh.subprocess, "run", return_value=completed) as run,
        ):
            refresh.probe_config(Path("/lane/gcloud"), plan)
        command = run.call_args.args[0]
        self.assertIn("--reset-env", command)
        self.assertIn("--no-new-privs", command)
        env_index = command.index("/usr/bin/env")
        self.assertEqual(command[env_index + 1], "-i")
        self.assertIn("HOME=/lane-home", command)
        self.assertIn("CLOUDSDK_CONFIG=/lane/gcloud", command)
        self.assertNotIn("HORIZON_SECRET_ACCESS_KEY", " ".join(command))

    def test_cloud_sdk_process_detection_ignores_controller_option(self) -> None:
        controller = (
            b"/usr/bin/python3\0/controller.py\0"
            b"--gcloud-bin=/usr/lib/google-cloud-sdk/bin/gcloud\0"
        )
        self.assertFalse(refresh._is_cloud_sdk_command(controller))

    def test_cloud_sdk_process_detection_accepts_direct_and_interpreted_commands(self) -> None:
        commands = [
            b"/usr/lib/google-cloud-sdk/bin/gcloud\0storage\0objects\0describe\0",
            b"/usr/bin/python3\0/usr/lib/google-cloud-sdk/lib/gcloud.py\0storage\0",
            b"/bin/bash\0/usr/lib/google-cloud-sdk/bin/gsutil\0stat\0",
            b"/usr/bin/env\0-i\0CLOUDSDK_CONFIG=/lane/config\0python3\0"
            b"/usr/lib/google-cloud-sdk/lib/gcloud.py\0",
            b"bq\0query\0",
        ]
        for command in commands:
            with self.subTest(command=command):
                self.assertTrue(refresh._is_cloud_sdk_command(command))

    def test_live_gcloud_processes_reports_only_actual_sdk_command(self) -> None:
        with TemporaryDirectory() as temporary:
            proc_root = Path(temporary)
            commands = {
                101: b"/usr/bin/python3\0/controller.py\0--gcloud-bin=/bin/gcloud\0",
                102: b"/usr/bin/python3\0/opt/google-cloud-sdk/lib/gcloud.py\0auth\0",
                103: b"/bin/gcloud\0storage\0ls\0",
            }
            for pid, command in commands.items():
                process = proc_root / str(pid)
                process.mkdir()
                (process / "cmdline").write_bytes(command)
            with patch.object(refresh.base, "ancestor_pids", return_value=set()):
                self.assertEqual(refresh.live_gcloud_processes(proc_root), [102, 103])

    @patch("scripts.refresh_idle_gcloud_lane_configs.require_workspace")
    @patch("scripts.refresh_idle_gcloud_lane_configs.base.read_boot_id", return_value="a" * 32)
    def test_plan_accepts_explicit_null_md5(self, _boot_id, _workspace) -> None:
        workspace = "/workspace"
        plan = {
            "schema": refresh.PLAN_SCHEMA,
            "boot_id": "a" * 32,
            "source_config": "/source/gcloud",
            "source_snapshot": f"{workspace}/source.snapshot",
            "account": "account@example.invalid",
            "project": "sealed-project",
            "gcloud_bin": str(Path("/usr/bin/true").resolve(strict=True)),
            "probe": {**self.probe(), "md5_hash": None},
            "units": [{
                "kind": "loaded-unit",
                "name": "controller.service",
                "fragment_path": "/etc/systemd/system/controller.service",
                "fragment_sha256": "b" * 64,
                "exec_start_sha256": "c" * 64,
                "load_state": "loaded",
                "active_state": "inactive",
                "sub_state": "dead",
                "result": "success",
                "unit_file_state": "static",
                "invocation_id": "",
                "restarts": 0,
                "triggers": [],
                "triggered_by": [],
                "claimed_lanes": ["lane-a=/lanes/lane-a"],
            }],
            "lanes": [{
                "label": "lane-a",
                "uid": 1001,
                "gid": 1001,
                "controller": "controller.service",
                "effective_config": "/lanes/lane-a/config/gcloud",
                "staged_config": f"{workspace}/lane-a.staged",
                "backup_config": f"{workspace}/lane-a.backup",
                "receipt": "/receipts/lane-a.json",
            }],
            "workspace": {
                "path": workspace,
                "device": 1,
                "inode": 2,
                "mode": "0711",
                "uid": 0,
                "gid": 0,
            },
            "preparation_receipt": "/receipts/preparation.json",
            "intent_receipt": "/receipts/intent.json",
            "completion_receipt": "/receipts/completion.json",
        }
        refresh.validate_plan(plan)

    def test_copy_normalizes_private_owner_only_tree(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            destination = root / "destination"
            child = source / "nested"
            child.mkdir(parents=True)
            credential = child / "credentials.db"
            credential.write_bytes(b"credentials")
            source.chmod(0o775)
            child.chmod(0o775)
            credential.chmod(0o664)
            refresh.copy_config(source, destination, os.getuid(), os.getgid())
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((destination / "nested").stat().st_mode), 0o700)
            self.assertEqual(
                stat.S_IMODE((destination / "nested" / "credentials.db").stat().st_mode),
                0o600,
            )
            refresh.require_normalized_config_tree(destination, os.getuid(), os.getgid())

    @patch("scripts.refresh_idle_gcloud_lane_configs.os.path.ismount", return_value=False)
    def test_pre_intent_resume_removes_only_bound_partial_copies(self, _ismount) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            effective = root / "gcloud"
            staged = root / "gcloud.staged"
            snapshot = root / "source.snapshot"
            effective.mkdir(mode=0o700)
            (effective / "credentials.db").write_bytes(b"old")
            staged.mkdir(mode=0o700)
            (staged / "credentials.db").write_bytes(b"partial")
            snapshot.mkdir(mode=0o700)
            (snapshot / "credentials.db").write_bytes(b"partial")
            lane = {
                "label": "lane-a",
                "uid": os.getuid(),
                "gid": os.getgid(),
                "controller": "controller.service",
                "effective_config": str(effective),
                "staged_config": str(staged),
                "backup_config": str(root / "gcloud.backup"),
                "receipt": str(root / "lane.json"),
            }
            plan = {
                "units": [],
                "lanes": [lane],
                "source_snapshot": str(snapshot),
                "workspace": {"path": str(root)},
            }
            preparation = {"lanes": [{**lane, "old_summary": refresh.tree_summary(effective)}]}
            with (
                patch.object(refresh, "require_workspace"),
                patch.object(refresh, "require_idle", return_value=[]),
                patch.object(refresh, "live_gcloud_processes", return_value=[]),
                patch.object(refresh, "process_references", return_value=[]),
            ):
                refresh.reset_pre_intent_paths(plan, preparation)
            self.assertTrue(effective.is_dir())
            self.assertFalse(staged.exists())
            self.assertFalse(snapshot.exists())

    @patch("scripts.refresh_idle_gcloud_lane_configs.os.path.ismount", return_value=False)
    def test_install_resumes_after_exchange_before_backup_move(self, _ismount) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            effective = root / "gcloud"
            staged = root / "gcloud.staged"
            backup = root / "gcloud.backup"
            receipt = root / "lane.json"
            effective.mkdir(mode=0o700)
            (effective / "credentials.db").write_bytes(b"old")
            staged.mkdir(mode=0o700)
            (staged / "credentials.db").write_bytes(b"new")
            refresh.normalize_config_tree(staged, os.getuid(), os.getgid())
            old_summary = refresh.tree_summary(effective)
            staged_summary = refresh.tree_summary(staged)
            staged_probe = {"generation": 123, "identity_field": "storage_url"}
            lane = {
                "label": "lane-a",
                "uid": os.getuid(),
                "gid": os.getgid(),
                "controller": "controller.service",
                "effective_config": str(effective),
                "staged_config": str(staged),
                "backup_config": str(backup),
                "receipt": str(receipt),
            }
            bound = {
                "old_summary": old_summary,
                "staged_summary": staged_summary,
                "staged_probe": staged_probe,
            }
            plan = {
                "units": [],
                "boot_id": "a" * 32,
                "workspace": {"path": str(root)},
            }
            refresh.rename_exchange(effective, staged)
            def read_test_receipt(path: Path, _label: str) -> tuple[dict, str]:
                return json.loads(path.read_text()), "unused"
            def probe_with_permissive_file(_config: Path, _plan: dict) -> dict:
                created = effective / "probe-created.db"
                created.write_bytes(b"probe")
                created.chmod(0o644)
                return staged_probe
            with (
                patch.object(refresh, "receipt_path", return_value=receipt),
                patch.object(refresh, "require_workspace"),
                patch.object(refresh, "require_idle", return_value=[]),
                patch.object(refresh, "process_references", return_value=[]),
                patch.object(refresh, "probe_config", side_effect=probe_with_permissive_file),
                patch.object(refresh.base, "require_root_private_json", side_effect=read_test_receipt),
            ):
                refresh.install_lane(plan, "d" * 64, lane, bound)
            self.assertEqual((effective / "credentials.db").read_bytes(), b"new")
            self.assertFalse(staged.exists())
            self.assertTrue(backup.exists())
            self.assertEqual((backup / "credentials.db").read_bytes(), b"old")
            self.assertTrue(receipt.is_file())
            self.assertEqual(stat.S_IMODE((effective / "probe-created.db").stat().st_mode), 0o600)
            (effective / "credentials.db").chmod(0o644)
            with (
                patch.object(refresh, "receipt_path", return_value=receipt),
                patch.object(refresh, "require_workspace"),
                patch.object(refresh.base, "require_root_private_json", side_effect=read_test_receipt),
            ):
                with self.assertRaisesRegex(refresh.RefreshError, "sealed 0600 policy"):
                    refresh.install_lane(plan, "d" * 64, lane, bound)

    @patch("scripts.refresh_idle_gcloud_lane_configs.os.path.ismount", return_value=False)
    def test_install_rejects_substituted_effective_tree_after_exchange(self, _ismount) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            effective = root / "gcloud"
            staged = root / "gcloud.staged"
            backup = root / "gcloud.backup"
            effective.mkdir(mode=0o700)
            (effective / "credentials.db").write_bytes(b"old")
            staged.mkdir(mode=0o700)
            (staged / "credentials.db").write_bytes(b"new")
            refresh.normalize_config_tree(staged, os.getuid(), os.getgid())
            old_summary = refresh.tree_summary(effective)
            staged_summary = refresh.tree_summary(staged)
            lane = {
                "label": "lane-a",
                "uid": os.getuid(),
                "gid": os.getgid(),
                "controller": "controller.service",
                "effective_config": str(effective),
                "staged_config": str(staged),
                "backup_config": str(backup),
                "receipt": str(root / "lane.json"),
            }
            bound = {
                "old_summary": old_summary,
                "staged_summary": staged_summary,
                "staged_probe": {"generation": 123},
            }
            refresh.rename_exchange(effective, staged)
            refresh.rename_noreplace(staged, backup)
            (effective / "credentials.db").write_bytes(b"substituted")
            with (
                patch.object(refresh, "receipt_path", return_value=Path(lane["receipt"])),
                patch.object(refresh, "require_workspace"),
                patch.object(refresh, "require_idle", return_value=[]),
            ):
                with self.assertRaisesRegex(refresh.RefreshError, "invalid post-exchange path state"):
                    refresh.install_lane(
                        {
                            "units": [],
                            "boot_id": "a" * 32,
                            "workspace": {"path": str(root)},
                        },
                        "d" * 64,
                        lane,
                        bound,
                    )

    @patch("scripts.refresh_idle_gcloud_lane_configs.os.path.ismount", return_value=False)
    def test_completion_requires_retained_snapshot_and_backup(self, _ismount) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            snapshot = root / "source.snapshot"
            backup = root / "lane-a.backup"
            staged = root / "lane-a.staged"
            preparation = root / "preparation.json"
            intent_path = root / "intent.json"
            lane_receipt = root / "lane.json"
            for path, contents in (
                (snapshot, b"source"),
                (backup, b"old"),
            ):
                path.mkdir(mode=0o700)
                (path / "credentials.db").write_bytes(contents)
            preparation.write_text("preparation")
            intent_path.write_text("intent")
            lane_receipt.write_text("lane")
            lane = {
                "label": "lane-a",
                "staged_config": str(staged),
                "backup_config": str(backup),
                "receipt": str(lane_receipt),
            }
            plan = {
                "boot_id": "a" * 32,
                "source_snapshot": str(snapshot),
                "lanes": [lane],
            }
            intent = {
                "source_snapshot": refresh.tree_summary(snapshot),
                "lanes": [{"label": "lane-a", "old_summary": refresh.tree_summary(backup)}],
            }
            plan_path = root / "plan.json"
            payload = {
                "schema": refresh.COMPLETION_SCHEMA,
                "status": "installed-and-validated",
                "observed_at_utc": "2026-10-10T00:00:00+00:00",
                "plan": str(plan_path),
                "plan_sha256": "d" * 64,
                "boot_id": plan["boot_id"],
                "preparation_receipt": str(preparation),
                "preparation_receipt_sha256": refresh.base.sha256_file(preparation),
                "intent_receipt": str(intent_path),
                "intent_receipt_sha256": refresh.base.sha256_file(intent_path),
                "lane_receipts": [{
                    "path": str(lane_receipt),
                    "sha256": refresh.base.sha256_file(lane_receipt),
                }],
                "lane_count": 1,
                "source_snapshot_retained": True,
                "backups_retained": True,
                "remote_mutations": False,
                "r2_mutations": False,
            }
            with (
                patch.object(refresh, "lane_receipt_matches", return_value={}),
                patch.object(refresh, "receipt_path", side_effect=lambda value, _label: Path(value)),
            ):
                refresh.validate_completion(
                    payload,
                    plan_path,
                    "d" * 64,
                    plan,
                    preparation,
                    intent_path,
                    intent,
                )
                backup.rename(root / "lane-a.backup.moved")
                with self.assertRaisesRegex(refresh.RefreshError, "lacks the retained backup"):
                    refresh.validate_completion(
                        payload,
                        plan_path,
                        "d" * 64,
                        plan,
                        preparation,
                        intent_path,
                        intent,
                    )


if __name__ == "__main__":
    unittest.main()
