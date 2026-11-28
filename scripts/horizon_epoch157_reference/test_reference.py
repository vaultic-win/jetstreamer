"""Exercise the native reference protocol's write, transaction and request boundaries."""
import io
import struct
import unittest
from types import SimpleNamespace

from car import CORRECTIONS, original_block
from native import Body, Session, U32, U64, outcomes, vec, writes


def write(slot, version):
    return (struct.pack("<QQ", slot, version) + b"\0" + vec(bytes(32)) + U64.pack(0) +
            vec(bytes(32)) + b"\0" + U64.pack(0) + vec(b"payload") + vec(bytes(32)))


def chunk(slot, ix, seq, variant, value):
    body = struct.pack("<QIQQII", 1, 8, slot, ix, seq, variant) + value
    return U32.pack(len(body)) + body


class ReferenceTest(unittest.TestCase):
    def test_previous_and_current_writes_keep_one_cursor(self):
        raw = U64.pack(2) + write(30, 9) + write(32, 10)
        stream = Body(raw)
        self.assertEqual(writes(stream, 32, 30, 9), (2, 11, 32))
        stream.eof()
        for invalid in (write(29, 9), write(31, 9), write(30, 8)):
            with self.assertRaises(ValueError):
                writes(Body(U64.pack(1) + invalid), 32, 30, 9)
        with self.assertRaises(ValueError):
            writes(Body(U64.pack(2) + write(32, 9) + write(30, 10)), 32, 30, 9)

    def test_matching_signatures_include_custom_instruction_failures(self):
        sig = bytes(range(64))
        tx = b"\1" + sig
        prefix = b"\1" + vec(sig)
        raw = (U64.pack(2) + prefix + b"\0" + U64.pack(5000) + prefix + b"\1" +
               U32.pack(8) + b"\2" + U32.pack(25) + U32.pack(6021) + U64.pack(5000))
        stream = Body(raw)
        self.assertEqual(outcomes(stream, [tx, tx]), (2, 1))
        stream.eof()
        with self.assertRaises(ValueError):
            outcomes(Body(raw), [b"\1" + bytes(64), tx])

    def test_complete_native_response_and_reordered_negative_control(self):
        sig = bytes(range(64))
        tx = b"\1" + sig
        outcome = chunk(32, 0, 0, 0, U64.pack(1) + b"\1" + vec(sig) + b"\0" + U64.pack(5000))
        account = chunk(32, 0, 1, 1, U64.pack(2) + write(30, 9) + write(32, 10))
        end = chunk(32, 0, 2, 2, struct.pack("<QBQ", 33*64, 1, 11))
        for raw, valid in ((outcome + account + end, True), (account + outcome + end, False),
                           (outcome + account + end[:-1], False)):
            proc = SimpleNamespace(stdin=io.BytesIO(), stdout=io.BytesIO(raw))
            session = Session(proc)
            session.slot, session.cursor = 30, 9
            if valid:
                session.process(32, [(1, bytes(32), [tx])])
                self.assertEqual((session.slot, session.cursor, session.successful), (32, 11, 1))
            else:
                with self.assertRaises(ValueError):
                    session.process(32, [(1, bytes(32), [tx])])

    def test_corrections_match_the_original_finalized_headers(self):
        self.assertEqual(set(CORRECTIONS), {68254833, 68255841, 68261681})
        for slot, row in CORRECTIONS.items():
            self.assertEqual((row["parent"], row["blockhash"]),
                             (row["finalized_rpc"]["parentSlot"], row["finalized_rpc"]["blockhash"]))
            self.assertEqual(row["parent"], slot - 2)

    def test_truncated_car(self):
        with self.assertRaises(ValueError):
            original_block(bytes.fromhex("8080"), 32)


if __name__ == "__main__":
    unittest.main()
