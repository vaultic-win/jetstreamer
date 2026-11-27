import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).parents[1] / "horizon_foundation_delivery247_20261124" / "epoch266_overlap.py"
SPEC = importlib.util.spec_from_file_location("epoch266_overlap", SOURCE)
OVERLAP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OVERLAP)


class OverlapProfileTest(unittest.TestCase):
    def test_fixed_profile_and_preflight_digest(self):
        files = OVERLAP.files()
        profile = json.loads(files["profile.json"])
        preflight = json.loads(files["preflight.json"])
        self.assertEqual(
            OVERLAP.reference(OVERLAP.STATE / "profile.json", files["profile.json"]),
            preflight["evidence"][0],
        )
        self.assertEqual(preflight["evidence"][0]["sha256"],
                         "5f12d3ba864dd64b14add832a4e8c9d441e26d097862763a0bfa74d854418964")
        self.assertEqual(
            OVERLAP.reference(OVERLAP.STATE / "preflight.json", files["preflight.json"])["sha256"],
            "6fb5bee98e51ad666280e8aee0248d1078aac6739a641be0693948355c6d2e7e",
        )
        self.assertFalse(profile["publication_authorized"])
        self.assertFalse(profile["cursor_normalization_qualified"])
        self.assertFalse(profile["predecessor_native_tuple_qualified"])

    def test_scratch_remains_inside_guard_scope_and_output_persists(self):
        profile = json.loads(OVERLAP.files()["profile.json"])
        mount = profile["properties"]["TemporaryFileSystem"].split(":")[0]
        self.assertTrue(Path(mount).is_relative_to(OVERLAP.ROOT))
        self.assertEqual(profile["argv"][-1], f"--replay-scratch={mount}")
        self.assertFalse(Path(profile["persistent_archive"]).is_relative_to(mount))
        self.assertFalse(Path(profile["persistent_segment_manifest"]).is_relative_to(mount))
        self.assertEqual(int(profile["properties"]["MemoryMax"]),
                         profile["scratch_tmpfs_bytes"] + profile["non_tmpfs_producer_memory_bytes"])
        self.assertEqual(profile["properties"]["MemorySwapMax"], "0")
        self.assertEqual(profile["lossless_native_result"], OVERLAP.JOURNAL)
        self.assertEqual(profile["restore_receipt"], OVERLAP.RESTORE)

    def test_rounded_capitalization_is_rejected(self):
        native = {
            "slot": OVERLAP.FIRST - 1, "snapshot_generation": 1641767192954871,
            "capitalization": 512823375441850400, "snapshot_sha256": OVERLAP.SNAPSHOT["sha256"],
        }
        summary = {"native_result": native, "native_result_journal_bytes": OVERLAP.JOURNAL}
        with patch.object(OVERLAP, "read", side_effect=[summary, native]):
            with self.assertRaises(AssertionError):
                OVERLAP.validate_sources()


if __name__ == "__main__":
    unittest.main()
