"""Authenticate original, bounded CAR entries before submitting their real hashes to protocol v5."""

import base64
import hashlib
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "horizon_epoch157_reference"))
# Production Python may have cbor2 installed. The Anza checkout also has a sealed
# copy of precisely the CPython 3.12 version qualified for the original CAR reader.
SEALED = Path("/home/sol/.jetstreamer-private/epoch157-terminal-reference-sealed-20261122-v1/package")
sys.path.append(str(SEALED))
from car import BASE, get_range, original_block, require, windows
from native import base58

CONFIG = json.loads((HERE / "inputs.json").read_bytes())
BOOT = 68_687_833
END = 68_688_001
GAPS = {row["slot"]: row for row in CONFIG["gaps"]}
VOTE = CONFIG["failing_vote"]
VOTE_WIRE = base64.b64decode(VOTE["transaction_base64"], validate=True)


def encoded(number):
    if number < 128:
        return bytes([number])
    width = (number.bit_length() + 7) // 8
    return bytes([128 + width]) + number.to_bytes(width, "little")


def original_windows():
    present = hashlib.sha256()
    all_windows = []
    for epoch, begin, end in ((158, BOOT + 1, 68_687_999), (159, 68_688_000, END)):
        data, length = get_range(
            f"{BASE}/{epoch}/epoch-{epoch}-slot-ranges.raw",
            (begin - epoch * 432000) * 12,
            (end - begin + 1) * 12,
        )
        require(
            length == 432000 * 12 and hashlib.sha256(data).hexdigest() == CONFIG["index"][str(epoch)],
            "original index changed",
        )
        rows = []
        for slot, (offset, size) in enumerate(struct.iter_unpack("<QI", data), begin):
            if not size:
                require(offset == 0, "bad absent range")
                continue
            require(
                59 <= offset and size <= 12 << 20 and (not rows or offset == rows[-1][1] + rows[-1][2]),
                "CAR range gap",
            )
            rows.append((slot, offset, size))
            present.update(struct.pack("<Q", slot))
        all_windows.extend((epoch, group) for group in windows(rows))
    require(present.hexdigest() == CONFIG["present_slots_sha256"], "finalized block coverage")
    return all_windows


def bind_gap(slot, parent, previous, entries):
    gap = GAPS.get(slot)
    if not gap:
        require(slot == parent + 1, "unreviewed block gap")
        return
    require(
        (parent, previous, base58(entries[-1][1]), len(entries))
        == (gap["parent"], gap["parent_poh"], gap["final_poh"], gap["entry_count"]),
        "gap finalized parent or endpoint changed",
    )
    entry_hash = hashlib.sha256(b"".join(encoded(n) + encoded(len(txs)) for n, _, txs in entries))
    require(
        entry_hash.hexdigest() == gap["entries_sha256"]
        and sum(len(txs) for _, _, txs in entries) == gap["transactions"],
        "gap archival entry layout",
    )
    boundary_rows = []
    ticks = work = 0
    for i, (n, digest, txs) in enumerate(entries):
        work += n
        if txs:
            require(work < 12500, "transaction reached tick boundary")
        else:
            require(work == 12500, "tick cadence differs")
            work = 0
            ticks += 1
            if ticks % 64 == 0:
                boundary_rows.append(dict(tick=ticks, entry=i, hash=base58(digest)))
    require(
        ticks == 64 * (slot - parent) and work == 0 and boundary_rows == gap["boundaries"],
        "original entry and archive RecentBlockhashes disagree",
    )


def original_blocks(expected_windows=None, record=None):
    """Validate each CID and final block ancestry. Bind each physical window on actual replay."""
    previous = CONFIG["bootstrap"]["checkpoint"]["last_blockhash"]
    last = BOOT
    gap_slots = []
    count = 0
    for i, (epoch, group) in enumerate(original_windows()):
        begin = group[0][1]
        end = group[-1][1] + group[-1][2]
        raw, total = get_range(f"{BASE}/{epoch}/epoch-{epoch}.car", begin, end - begin)
        row = dict(
            epoch=epoch,
            offset=begin,
            length=len(raw),
            total_car_bytes=total,
            sha256=hashlib.sha256(raw).hexdigest(),
        )
        if expected_windows is not None:
            require(
                i < len(expected_windows) and expected_windows[i] == row,
                "changed qualified original window",
            )
        if record is not None:
            record.append(row)
        for slot, offset, size in group:
            parent, entries = original_block(raw[offset - begin : offset - begin + size], slot)
            require(
                parent == last and entries and not entries[-1][2],
                "wrong original ancestry or final tick",
            )
            bind_gap(slot, parent, previous, entries)
            if slot in GAPS:
                gap_slots.append(slot)
            if slot == END:
                transactions = [tx for _, _, txs in entries for tx in txs]
                require(
                    transactions[VOTE["ordinal"]] == VOTE_WIRE
                    and transactions.count(VOTE_WIRE) == 1
                    and entries[VOTE["entry_index"]][2][VOTE["transaction_in_entry"]] == VOTE_WIRE
                    and base58(entries[-1][1]) == CONFIG["last_poh"],
                    "signed incident vote or endpoint changed",
                )
            yield slot, parent, entries
            previous = base58(entries[-1][1])
            last = slot
        count += 1
    require((last, count, sorted(gap_slots)) == (END, 7, sorted(GAPS)), "incomplete trace span")
    if expected_windows is not None:
        require(count == len(expected_windows), "qualified CAR window left unread")
