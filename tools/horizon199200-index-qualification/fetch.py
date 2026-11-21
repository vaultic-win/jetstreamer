#!/usr/bin/env python3
"""Capture the two original slot tables and 139 bounded CAR ranges for offline repair."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import urllib.request

BASE = "https://files.old-faithful.net"
INDEX_BYTES = 432_000 * 12
CAR_BYTES = 205_729_899


def sha(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def sync_directory(path):
    handle = os.open(path, os.O_DIRECTORY)
    try:
        os.fsync(handle)
    finally:
        os.close(handle)


def save_json(path, document):
    temporary = path.with_suffix(".json.part")
    with temporary.open("w") as output:
        json.dump(document, output, sort_keys=True)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    temporary.replace(path)
    sync_directory(path.parent)


def acquire(directory, name, url, size, expected=None, byte_range=None):
    path = directory / name
    receipt = directory / (name + ".json")
    if path.exists() and receipt.exists():
        previous = json.loads(receipt.read_bytes())
        identity = (name, url, size, byte_range)
        stored = tuple(previous[key] for key in ("name", "url", "length", "content_range"))
        digest = sha(path)
        if stored != identity or path.stat().st_size != size or digest != previous["sha256"]:
            raise ValueError(f"captured object changed: {name}")
        if expected is not None and digest != expected:
            raise ValueError(f"pinned digest changed: {name}")
        return previous

    headers = {"Accept-Encoding": "identity", "User-Agent": "horizon-index-qualification"}
    if byte_range:
        headers["Range"] = "bytes=" + byte_range.split(" ")[1].split("/")[0]
    request = urllib.request.Request(url, headers=headers)
    partial = directory / (name + ".part")
    digest = hashlib.sha256()
    count = 0
    with urllib.request.urlopen(request, timeout=25) as reply:
        if (reply.status != (206 if byte_range else 200)
                or reply.headers.get("Content-Range") != byte_range
                or reply.headers.get("Content-Encoding", "identity") != "identity"
                or reply.geturl() != url):
            raise ValueError(f"unexpected HTTP response for {name}")
        with partial.open("wb") as output:
            while count < size:
                chunk = reply.read(min(64 * 1024, size - count))
                if not chunk:
                    raise ValueError(f"truncated response for {name}")
                count += len(chunk)
                digest.update(chunk)
                output.write(chunk)
            if reply.read(1):
                raise ValueError(f"oversized response for {name}")
            if expected is not None and digest.hexdigest() != expected:
                raise ValueError(f"unrecognized source bytes for {name}")
            output.flush()
            os.fsync(output.fileno())
    record = dict(name=name, url=url, length=count, content_range=byte_range, sha256=digest.hexdigest())
    if path.exists() and sha(path) != record["sha256"]:
        raise ValueError(f"unreceipted local object differs from captured source: {name}")
    if receipt.exists() and json.loads(receipt.read_bytes()) != record:
        raise ValueError(f"new capture differs from retained receipt: {name}")
    partial.replace(path)
    save_json(receipt, record)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    plan = json.loads(Path(__file__).with_name("plan.json").read_bytes())
    indexes = args.directory / "indexes"
    capture = args.directory / "capture"
    indexes.mkdir(mode=0o700, parents=True, exist_ok=True)
    capture.mkdir(mode=0o700, exist_ok=True)
    proofs = []
    for epoch in plan["epochs"]:
        e = epoch["epoch"]
        name = f"epoch-{e}-slot-ranges.raw"
        acquire(indexes, name, f"{BASE}/{e}/{name}", INDEX_BYTES, epoch["raw_sha256"])
        end = epoch["car_bytes"]
        rows = [("header", 0, 59), ("footer", epoch["footer_at"], end)]
        rows.extend(("window", r["start"], r["end"]) for r in epoch["individual_windows"])
        for kind, lo, hi in rows:
            file = f"{e}-{kind}-{lo}-{hi}.car"
            proof = acquire(capture, file, f"{BASE}/{e}/epoch-{e}.car", hi - lo,
                            epoch["header_sha256"] if kind == "header" else None,
                            f"bytes {lo}-{hi - 1}/{end}")
            proofs.append(dict(proof, epoch=e, kind=kind, lo=lo, hi=hi))
    if len({r["name"] for r in proofs}) != 139 or sum(r["length"] for r in proofs) != CAR_BYTES:
        raise ValueError("capture plan is incomplete")
    manifest = capture / "RESULT.json"
    save_json(manifest, dict(plan_sha256=plan["capture_plan_sha256"], body_bytes=CAR_BYTES, source_ranges=proofs))
    print(sha(manifest), manifest)


if __name__ == "__main__":
    main()
