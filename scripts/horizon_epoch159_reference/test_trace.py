import hashlib
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import source
import feature19
import trace
from native import Body, U32, U64, base58, outcomes, vec, writes


class TraceTest(unittest.TestCase):
    def test_feature_account_uses_actual_protocol_write_and_historical_slot(self):
        key = feature19.ACCOUNT
        self.assertEqual(base58(key), "3ccR6QpxGYsAbWyfevEtBNGfWV4xBffxRj2tD6A9i39F")
        self.assertEqual(base58(feature19.OWNER), "Feature111111111111111111111111111111111111")
        slot = feature19.FIRST
        valid = dict(
            actual=slot,
            pubkey=key,
            data=bytes.fromhex("018018180400000000"),
            lamports=953520,
            owner=feature19.OWNER,
            executable=0,
            rent=158,
            digest=feature19.BOUNDARY_HASH,
        )
        for changes in (
            {},
            {"actual": slot - 1},
            {"pubkey": bytes(32)},
            {"data": bytes(9)},
            {"data": valid["data"] + b"\x00"},
            {"lamports": 1},
            {"owner": bytes(32)},
            {"executable": 1},
            {"rent": 159},
            {"digest": bytes(32)},
        ):
            v = valid | changes
            frame = (
                U64.pack(v["actual"])
                + U64.pack(1234)
                + b"\0"
                + vec(v["pubkey"])
                + U64.pack(v["lamports"])
                + vec(v["owner"])
                + bytes([v["executable"]])
                + U64.pack(v["rent"])
                + vec(v["data"])
                + vec(v["digest"])
            )
            events = []
            body = Body(U64.pack(1) + frame)
            writes(body, slot, slot - 1, 1234, observe_account=lambda *a: feature19.observe(events, *a))
            body.eof()
            self.assertEqual(feature19.accepted(events), not changes)
            if not changes:
                self.assertEqual(events[0]["write_version"], 1234)
                self.assertFalse(feature19.accepted(events * 2))

    def test_capture_failed_and_successful_signed_incident_vote(self):
        tx = source.VOTE_WIRE
        sig = tx[1:65]
        self.assertEqual(base58(sig), source.VOTE["signature"])
        for status, error in [
            (b"\0", None),
            (
                b"\x01" + U32.pack(8) + b"\0" + U32.pack(25) + U32.pack(2),
                {"transaction_error": 8, "instruction_index": 0, "instruction_error": 25, "custom": 2},
            ),
        ]:
            result = []
            body = Body(U64.pack(1) + b"\1" + vec(sig) + status + U64.pack(5000))
            n, successful = outcomes(body, [tx], lambda *args: result.append(args))
            self.assertEqual((1, int(error is None)), (n, successful))
            self.assertEqual(result, [(tx, error, 5000)])
            body.eof()

    def test_capture_actual_slot_hashes_write(self):
        data = struct.pack("<QQ32s", 1, 50, bytes(range(32)))
        key = trace.SLOT_HASHES
        self.assertEqual(base58(key), "SysvarS1otHashes111111111111111111111111111")
        record = (
            U64.pack(51)
            + U64.pack(34)
            + b"\0"
            + vec(key)
            + U64.pack(1)
            + vec(bytes(32))
            + b"\0"
            + U64.pack(0)
            + vec(data)
            + vec(bytes(32))
        )
        rows = []
        self.assertEqual(
            writes(Body(U64.pack(1) + record), 52, 51, 34, lambda *args: rows.append(args)), (1, 35, 51)
        )
        self.assertEqual(rows, [(51, 34, key, data)])
        with self.assertRaises(ValueError):
            writes(Body(U64.pack(1) + record), 52, 51, 35)

    def test_boundary_hash_and_transaction_regrouping_rejected(self):
        entries = [(12500, hashlib.sha256(i.to_bytes(4, "little")).digest(), []) for i in range(128)]
        final = base58(entries[-1][1])
        css = hashlib.sha256(
            b"".join(source.encoded(n) + source.encoded(len(t)) for n, _, t in entries)
        ).hexdigest()
        row = dict(
            parent=30,
            parent_poh="original anchor",
            final_poh=final,
            entry_count=128,
            transactions=0,
            entries_sha256=css,
            boundaries=[dict(tick=i + 1, entry=i, hash=base58(entries[i][1])) for i in (63, 127)],
        )
        with patch.dict(source.GAPS, {32: row}, clear=True):
            source.bind_gap(32, 30, "original anchor", entries)
            mutated = list(entries)
            mutated[63] = (12500, entries[62][1], [])
            with self.assertRaisesRegex(ValueError, "RecentBlockhashes"):
                source.bind_gap(32, 30, "original anchor", mutated)
            with self.assertRaises(ValueError):
                source.bind_gap(32, 30, "different parent", entries)
            shortened = list(entries)
            shortened.pop(63)
            with self.assertRaises(ValueError):
                source.bind_gap(32, 30, "original anchor", shortened)
            with self.assertRaisesRegex(ValueError, "unreviewed"):
                source.bind_gap(38, 34, "x", entries)


if __name__ == "__main__":
    unittest.main()
