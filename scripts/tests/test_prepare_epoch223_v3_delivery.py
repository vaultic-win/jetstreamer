import importlib.util
from pathlib import Path
import shlex
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "delivery223", Path(__file__).parents[1] / "prepare_epoch223_v3_delivery.py")
DELIVERY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DELIVERY)


class OfflineV3DeliveryTemplate(unittest.TestCase):
    def metadata(self):
        return {"schema": "jetstreamer-epoch223-v3-delivery-template-input-v1",
                **{key: {"path": f"/unopened/{key}", "sha256": "a" * 64}
                   for key in ("publication_evidence", *DELIVERY.TOOLS)},
                **{key: f"/unopened/{key}" for key in DELIVERY.ROOTS}}

    def test_template_uses_v3_gate_tuple_without_opening_referenced_files(self):
        metadata = self.metadata()
        with patch.object(Path, "open", side_effect=AssertionError("file observation forbidden")):
            wrapper, proposal = DELIVERY.render(metadata)
        command = wrapper.split("\nexec ", 1)[1].strip()
        self.assertEqual(shlex.split(command), proposal["argv"])
        self.assertIn(f"--full-verifier-sha256={DELIVERY.FULL}", proposal["argv"])
        self.assertIn(f"--plugin-pipeline-sha256={DELIVERY.PLUGIN}", proposal["argv"])
        for role in ["full", "plugin"]:
            self.assertIn(f"--{role}-verifier-script-sha256={'a' * 64}", proposal["argv"])
        self.assertNotIn("--delete-local", proposal["argv"])
        self.assertTrue(proposal["template_only"])
        for key in ["input_integrity_validated", "source_or_publication_qualified",
                    "authoritative_receipt", "r2_decision_made", "deployment_authorized"]:
            self.assertFalse(proposal[key])

    def test_quoted_metadata_cannot_become_an_extra_shell_command(self):
        metadata = self.metadata()
        metadata["uploader"]["path"] = "/unopened/with spaces/`literal`$value"
        wrapper, proposal = DELIVERY.render(metadata)
        self.assertEqual(shlex.split(wrapper.split("\nexec ", 1)[1]), proposal["argv"])
        self.assertEqual(proposal["argv"][1], metadata["uploader"]["path"])


if __name__ == "__main__":
    unittest.main()
