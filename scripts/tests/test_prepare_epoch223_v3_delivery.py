import copy
import importlib.util
from pathlib import Path
import unittest


SPEC = importlib.util.spec_from_file_location(
    "delivery223", Path(__file__).parents[1] / "prepare_epoch223_v3_delivery.py")
DELIVERY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DELIVERY)


class ActualV3DeliveryBindings(unittest.TestCase):
    def evidence(self):
        verifier = {"path": "/fixture/jetstreamer-epoch223-private-verify", "sha256": "a" * 64}
        verified = {"path": "/fixture/verification.json", "sha256": "b" * 64}
        publication = {
            "schema": "jetstreamer-exact-epoch223-v3-publication-receipt-v1", "epoch": 223,
            "committed": True, "original_assembly_preserved": True,
            "full_verifier_sha256": DELIVERY.FULL, "plugin_pipeline_sha256": DELIVERY.PLUGIN,
            "private_runner_sha256": verifier["sha256"], "archive_sha256": "c" * 64,
            "archive_bytes": 123, "context": {"verification": verified},
            "remote_mutations": False, "r2_mutations": False,
            "runtime_registry_promoted": False, "retirement_authorized": False,
        }
        plan = {
            "schema": "jetstreamer-private-epoch223-v3-publication-plan-v1",
            "artifact_publication_authorized": True, "verifier": verifier,
            "verification": verified, "archive_sha256": publication["archive_sha256"],
            "archive_bytes": 123, "remote_mutations": False, "r2_mutations": False,
            "runtime_registry_promotion_authorized": False,
        }
        return publication, plan, verifier

    def test_old_delivery_authorities_or_another_actual_runner_are_rejected(self):
        publication, plan, verifier = self.evidence()
        DELIVERY.validate_publication(publication, plan, verifier)
        for field, value in [
            ("full_verifier_sha256", "3ce77a5573f0b91f8a624a98b6b210d8f7f3b5c06b802d7b8d2e1dbb456c4b95"),
            ("plugin_pipeline_sha256", "369773be29abe911ad4de5f263877a176e6b960a517367402019b4dd85f22bf6"),
            ("private_runner_sha256", "d" * 64), ("committed", False),
            ("original_assembly_preserved", False), ("retirement_authorized", True),
        ]:
            wrong = copy.deepcopy(publication)
            wrong[field] = value
            with self.assertRaises(ValueError, msg=field):
                DELIVERY.validate_publication(wrong, plan, verifier)

    def test_publication_plan_cannot_substitute_another_verified_archive(self):
        publication, plan, verifier = self.evidence()
        for field, value in [
            ("archive_sha256", "d" * 64), ("archive_bytes", 124),
            ("verification", {"path": "/fixture/another.json", "sha256": "e" * 64}),
            ("runtime_registry_promotion_authorized", True), ("r2_mutations", True),
        ]:
            wrong = copy.deepcopy(plan)
            wrong[field] = value
            with self.assertRaises(ValueError, msg=field):
                DELIVERY.validate_publication(publication, wrong, verifier)


if __name__ == "__main__":
    unittest.main()
