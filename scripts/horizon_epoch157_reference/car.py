"""Read pinned Old Faithful block ranges and resolve their original entry/transaction CIDs."""
import hashlib
import io
import json
from pathlib import Path
import re
import struct
import subprocess

import cbor2

BASE = "https://files.old-faithful.net"
CID_PREFIX = bytes.fromhex("01711220")
MAX_RANGE = 12 << 20
# Slice SHA-256, including every skipped slot. Captured independently of replay.
RANGES = {
    157: (68249461, 68255999, "bd385b75d583675ab04cdc59c745d7ddafc3df46c2d5919fa4473cf9e9fe7d0c"),
    158: (68256000, 68262721, "580d4d5de97d03d61c484ce9f9edc1a617629540492327dc179afae0eb653a56"),
}

# Hash of all produced slot numbers (little-endian u64), independently
# confirmed over these entire intervals against the pinned Compact V2 indices.
PRODUCED_SLOTS = {
    157: "344df4aff354f16481b3975e2afc2aada30ae571644c784071f4ab87a59d885a",
    158: "c21a3aa9f93704199b8d86ad890fed382d1191af8de8f23926f5e50e0240de74",
}


# All three corrections are private to this two-epoch diagnostic. The
# repository retains the exact CAR identity and independently finalized RPC
# header for each original. The public slot-range files remain unchanged.
CORRECTIONS = {v["slot"]: v for v in json.loads(
    Path(__file__).with_name("original_blocks.json").read_bytes())}


def require(value, message):
    if not value:
        raise ValueError(message)


def get_range(url, start, count):
    require(0 < count <= MAX_RANGE, "range bound")
    end = start + count - 1
    # HTTP/2 works on the public archive origin. Retain only final response
    # headers; the input length and Content-Range are mandatory on every GET.
    command = ["curl", "-fsS", "--proto", "=https", "--max-time", "90", "--retry", "2",
               "--max-filesize", str(count), "--range", f"{start}-{end}", "--dump-header",
               "-", "--output", "-", url]
    result = subprocess.run(command, capture_output=True, check=True, timeout=285)
    data = result.stdout
    headers, sep, body = data.partition(b"\r\n\r\n")
    while headers.startswith(b"HTTP/1.1 200 Connection established") or (
        headers.startswith(b"HTTP/") and len(body) > count and body.startswith(b"HTTP/")
    ):
        headers, sep, body = body.partition(b"\r\n\r\n")
    require(sep and re.match(rb"HTTP/\S+ 206(?:\s|$)", headers) and len(body) == count,
            "incomplete HTTP 206")
    ranges = re.findall(rb"(?im)^content-range:\s*bytes (\d+)-(\d+)/(\d+)\s*$", headers)
    require(len(ranges) == 1, "missing or duplicate Content-Range")
    first, last, total = map(int, ranges[0])
    require((first, last) == (start, end) and total > end, "incorrect Content-Range")
    return body, total


def index(epoch):
    first, last, digest = RANGES[epoch]
    url = f"{BASE}/{epoch}/epoch-{epoch}-slot-ranges.raw"
    raw, total = get_range(url, 12 * (first - epoch * 432000), 12 * (last - first + 1))
    require(total == 432000 * 12 and hashlib.sha256(raw).hexdigest() == digest, "index identity")
    rows = []
    for i, (offset, length) in enumerate(struct.iter_unpack("<QI", raw)):
        slot = first + i
        if slot in CORRECTIONS:
            require((offset, length) == (0, 0), "correction no longer matches original index")
            correction = CORRECTIONS[slot]
            offset, length = correction["offset"], correction["length"]
        elif not length:
            require(offset == 0, "invalid absent slot")
            continue
        require(0 < length <= MAX_RANGE and offset >= 59, "invalid CAR span")
        require(not rows or offset == rows[-1][1] + rows[-1][2], "incomplete physical CAR coverage")
        rows.append((first + i, offset, length))
    coverage = hashlib.sha256(b"".join(struct.pack("<Q", slot) for slot, _, _ in rows)).hexdigest()
    require(coverage == PRODUCED_SLOTS[epoch], "independent produced-slot census")
    return rows


def windows(rows):
    group = []
    for row in rows:
        if group and row[1] + row[2] - group[0][1] > MAX_RANGE:
            yield group
            group = []
        group.append(row)
    if group:
        yield group


def link(tag):
    require(isinstance(tag, cbor2.CBORTag) and tag.tag == 42 and
            isinstance(tag.value, bytes) and tag.value[:5] == b"\x00" + CID_PREFIX and
            len(tag.value) == 37, "unexpected DAG-CBOR link")
    return tag.value[5:]


def sections(raw):
    cursor = 0
    while cursor < len(raw):
        length = 0
        for shift in range(0, 35, 7):
            require(cursor < len(raw), "truncated CAR length")
            byte = raw[cursor]
            cursor += 1
            length |= (byte & 127) << shift
            if byte < 128:
                break
        else:
            raise ValueError("invalid CAR varint")
        end = cursor + length
        require(36 < length and end <= len(raw) and raw[cursor:cursor + 4] == CID_PREFIX,
                "invalid CAR section")
        cid = raw[cursor + 4:cursor + 36]
        body = raw[cursor + 36:end]
        require(hashlib.sha256(body).digest() == cid, "CAR CID mismatch")
        source = io.BytesIO(body)
        node = cbor2.load(source)
        require(source.tell() == len(body) and isinstance(node, list) and node, "CBOR framing")
        yield cid, node
        cursor = end


def original_block(raw, slot):
    arena = {}
    block = None
    for cid, node in sections(raw):
        require(block is None, "bytes after block")
        if node[0] == 2:
            block = node
        elif node[0] in (0, 1, 6):
            # Identical CIDs may recur (e.g. duplicate source records).
            arena[cid] = node
    require(block is not None and block[1] == slot and block[3], "wrong terminal CAR block")
    entries = []
    tx_index = 0
    for entry_link in block[3]:
        e = arena[link(entry_link)]
        require(e[0] == 1 and len(e[2]) == 32 and e[1] >= 0, "invalid PoH entry")
        txs = []
        for tx_link in e[3]:
            tx = arena[link(tx_link)]
            require(tx[0] == 0 and tx[3] == slot and
                    (len(tx) == 4 or tx[4] is None or tx[4] == tx_index), "transaction order")
            data = tx[1]
            pending = list(data[5] or []) if len(data) > 5 else []
            parts = [data[4]]
            seen = set()
            while pending:
                next_group = []
                for next_link in pending:
                    key = link(next_link)
                    require(key not in seen and len(seen) < 32, "invalid dataframe chain")
                    seen.add(key)
                    part = arena[key]
                    require(part[0] == 6, "invalid linked dataframe")
                    parts.append(part[4])
                    if len(part) > 5 and part[5]:
                        require(not next_group, "ambiguous dataframe continuation")
                        next_group = part[5]
                pending = next_group
            wire = b"".join(parts)
            require(data[0] == 6 and 65 <= len(wire) <= 1232, "invalid transaction body")
            txs.append(wire)
            tx_index += 1
        entries.append((e[1], e[2], txs))
    return block[4][0], entries


def blocks(epoch, start, stop):
    wanted = [r for r in index(epoch) if start <= r[0] <= stop]
    url = f"{BASE}/{epoch}/epoch-{epoch}.car"
    identity = None
    for window in windows(wanted):
        offset = window[0][1]
        end = window[-1][1] + window[-1][2]
        raw, total = get_range(url, offset, end - offset)
        require(identity is None or identity == total, "CAR length changed")
        identity = total
        for slot, pos, size in window:
            piece = raw[pos - offset:pos - offset + size]
            parent, entries = original_block(piece, slot)
            if slot in CORRECTIONS:
                correction = CORRECTIONS[slot]
                require(hashlib.sha256(piece).hexdigest() == correction["sha256"] and
                        (parent, entries[-1][1].hex()) == (correction["parent"], correction["poh_hex"]),
                        "original CAR correction changed")
            yield slot, parent, entries
