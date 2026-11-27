from unittest import TestCase, main
from unittest.mock import patch

import assembly_reservation as assembly
import continuation_price as price


class IssuedPhaseTests(TestCase):
    def test_v46_keeps_original_exclusion(self):
        with patch.object(assembly.os.path, "lexists", return_value=False):
            self.assertEqual(assembly.phase_writer("phase", "prior", "owner"), ("owner", None))

    def test_v47_must_inherit_the_original_phase(self):
        active = {"old": "original", "producer_mutations": False, "ready": {"path": "ready"}}
        rebound = {
            "writer": "prior", "original": "listener", "phase": "changed", "producer_mutations": False,
        }
        ready = {"old_owner": "prior", "retained_143_listener": "listener", "retained_143_phase": "phase"}
        with (
            patch.object(assembly.os.path, "lexists", side_effect=lambda path: path.name == "FAILED166_CADENCE_V47_ACTIVE.json"),
            patch.object(assembly, "pinned", side_effect=[active, rebound]),
            patch.object(assembly, "evidence", return_value=(ready, None)),
        ):
            with self.assertRaisesRegex(ValueError, "did not inherit"):
                assembly.phase_writer("phase", "prior", "original")

    def test_price_only_deployment_cannot_quote_an_unissued_producer(self):
        with patch.object(price, "OPERATOR", price.ISSUED_PRICE):
            for phase in ("start", "read"):
                with self.subTest(phase=phase), self.assertRaisesRegex(ValueError, "only prices"):
                    price.price(phase)

    def test_issued_census_rejects_a_different_worker_before_reading_proc(self):
        actor = {"producer_invocation_id": "other"}
        release = {"guard_plan": "plan", "interface": "scope", "producer_invocation_id": "other"}
        progress = {"release": "release", "worker": {}, "producer_invocation_id": "other"}
        docs = {"release": release, "plan": {}, "scope": {}}
        with (
            patch.object(price, "read", return_value=(progress, None)),
            patch.object(price, "bound", side_effect=docs.__getitem__),
            patch.object(price.prior, "protected") as guard,
        ):
            with self.assertRaisesRegex(ValueError, "different issued"):
                price.issued_tree_bounds(actor)
            guard.assert_not_called()


if __name__ == "__main__":
    main()
