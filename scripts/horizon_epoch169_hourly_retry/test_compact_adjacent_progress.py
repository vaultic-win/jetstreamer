import unittest
from unittest.mock import patch

import compact_adjacent_progress as progress


class CompactProgressTest(unittest.TestCase):
    def test_pinned_native_reader_has_the_compact_interface_and_output_names(self):
        reference = {"INTERFACE": {"sha256": "a" * 64}}
        with patch.object(progress.writer, "bindings", return_value=reference):
            reader = progress.event_reader()
        settings = reader.__globals__
        self.assertEqual(settings["ROOT"], progress.original.BASE)
        self.assertEqual(settings["PIN"], reference["INTERFACE"]["sha256"])
        self.assertEqual(settings["NAME"], "ADJACENT169_FIRST_PROTECTED_BLOCK.json")
        self.assertEqual(settings["TRANSACTIONS"], "ADJACENT169_FIRST_PROTECTED_TRANSACTIONS.json")


if __name__ == "__main__":
    unittest.main()
