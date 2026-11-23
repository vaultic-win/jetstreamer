import copy
from pathlib import Path
import runpy
import unittest


HANDOFF = runpy.run_path(str(Path(__file__).with_name("v5n_boundary.py")))


class CompletionJoin(unittest.TestCase):
    def setUp(self):
        state = HANDOFF["STATE"]
        self.semantic = dict(schema="horizon-145-v5j-semantic-completion-v1", invocation_id=HANDOFF["IID"],
                             archive_bytes=105610995833, pid1_success="actual-cursor")
        for field, name in (("start", "recovery-started.json"), ("verified", "verified-frozen.json"),
                            ("extraction", "extraction-complete.json"), ("completion", "complete.json")):
            self.semantic[field] = HANDOFF["ref"](state / name, "a" * 64)
        self.inputs = dict(schema="horizon-145-v5j-publication-inputs-v1", public_origin=HANDOFF["READINESS"],
                           expected_slots=432000, local_first_slot=62640000, local_last_slot=63071999,
                           publication_authorized=False, epoch_145_publicly_verified=False,
                           semantic_pending=False, semantic=self.semantic)
        self.phase = dict(Id=HANDOFF["UNIT"], MainPID="0", stage="v5j-semantic-complete",
                          completion=self.semantic["completion"])

    def test_captured_completion_and_drained_native_owner_join(self):
        self.assertEqual(HANDOFF["join"](self.inputs, self.semantic, self.phase), self.semantic["completion"])

    def test_pending_can_be_inspected_without_dispatch(self):
        pending = dict(self.inputs, semantic=None, semantic_pending=True)
        self.assertIsNone(HANDOFF["join"](pending, None, None))
        with self.assertRaises(ValueError):
            HANDOFF["join"](pending, self.semantic, None)

    def test_missing_capture_or_altered_generation_rejects(self):
        with self.assertRaises(ValueError):
            HANDOFF["join"](self.inputs, None, None)
        for field, value in (("invocation_id", "afcf6cdd1ec0400ea2757f81472987b3"),
                             ("pid1_success", ""), ("archive_bytes", 0),
                             ("start", HANDOFF["ref"](HANDOFF["STATE"] / "complete.json", "a" * 64))):
            with self.subTest(field=field), self.assertRaises(ValueError):
                changed = dict(self.semantic, **{field: value})
                HANDOFF["join"](dict(self.inputs, semantic=changed), changed, self.phase)

    def test_even_a_captured_success_requires_unchanged_owner_and_completion(self):
        for field, value in (("MainPID", "123"), ("stage", "post-full"), ("Id", "other.service"),
                             ("completion", dict(self.semantic["completion"], sha256="b" * 64))):
            with self.subTest(field=field), self.assertRaises(ValueError):
                HANDOFF["join"](self.inputs, self.semantic, dict(self.phase, **{field: value}))
        crossed = copy.deepcopy(self.semantic)
        crossed["completion"]["sha256"] = "c" * 64
        with self.assertRaises(ValueError):
            HANDOFF["join"](self.inputs, crossed, self.phase)


if __name__ == "__main__":
    unittest.main()
