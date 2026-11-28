#!/usr/bin/env python3
"""Acquire exactly the immutable 257 CAR source windows. Main runs this in the charged fetch phase."""
import hashlib
import http.client
import json
import os
import ssl
import sys
import time
from pathlib import Path

HOST = "files.old-faithful.net"
RESOURCE = "/257/epoch-257.car"
CAR_SIZE = 392_183_478_837
TOTAL_BODIES = 118_427_890
PREFIX_SHA = "b05ac5e7b6c0d9b595c98bec38ba37b00d9183154eb5a922d6f69a05724affea"
PLAN_SHA = "b8459e69dbecdffc9086c7954f1ae2bdd8a841ac70f85e034d38cfb8ec708f3b"
SOURCE = Path(__file__).resolve().parent / "edge-windows.json"

def require(value, reason):
    if not value:
        raise ValueError(reason)

def acquire(output):
    encoded = SOURCE.read_bytes()
    require(hashlib.sha256(encoded).hexdigest() == PLAN_SHA, "plan bytes changed")
    windows = json.loads(encoded)
    require(len(windows) == 29 and sum(w["end"] - w["start"] for w in windows) == TOTAL_BODIES, "invalid transfer census")
    require(output.is_absolute() and output.parent.resolve(strict=True) == output.parent, "noncanonical output")
    output.mkdir(mode=0o700)
    deadline = time.monotonic() + 900
    validator = None
    resources = [("prefix-before",0,4096)] + [(str(w["edge"]),w["start"],w["end"]) for w in windows] + [("prefix-after",0,4096)]
    manifest = []
    for name, start, stop in resources:
        size = stop-start
        require(0 < size <= 6_971_573 and stop <= CAR_SIZE, "out of bounds")
        require(time.monotonic() < deadline, "transfer time budget")
        conn = http.client.HTTPSConnection(HOST,timeout=15,context=ssl.create_default_context())
        try:
            request = {"Range": f"bytes={start}-{stop-1}", "Accept-Encoding": "identity"}
            if validator: request["If-Range"] = validator
            conn.request("GET", RESOURCE, headers=request)
            res = conn.getresponse()
            fields = {}
            for field, value in res.getheaders():
                key = field.lower()
                require(key not in fields or key not in {"content-length","content-range","etag","content-encoding","content-type","transfer-encoding"}, "ambiguous entity headers")
                fields[key] = value
            require(res.status == 206 and fields.get("content-range") == f"bytes {start}-{stop-1}/{CAR_SIZE}" and fields.get("content-length") == str(size), "server did not return the exact range and size")
            require(fields.get("content-encoding","identity") == "identity" and "transfer-encoding" not in fields and fields.get("content-type") == "application/vnd.curl.car", "unexpected representation")
            etag = fields.get("etag")
            if name == "prefix-before" and etag and etag.startswith('"'):
                validator = etag
            if validator: require(etag == validator,"ETag changed")
            sha = hashlib.sha256()
            total = 0
            with (output / (name+".car")).open("xb") as body:
                while total < size:
                    require(time.monotonic() < deadline, "transfer time budget")
                    b = res.read(min(65536, size-total))
                    require(b,"short response")
                    body.write(b)
                    sha.update(b)
                    total += len(b)
                require(not res.read(1),"response exceeds bound")
                body.flush()
                os.fsync(body.fileno())
            digest=sha.hexdigest()
            if name.startswith("prefix"): require(digest==PREFIX_SHA,"CAR prefix identity")
            manifest.append({"name":name,"url":"https://"+HOST+RESOURCE,"request_range":request["Range"],"status":res.status,"content_range":fields["content-range"],"bytes":size,"sha256":digest,"etag":etag})
        finally:
            conn.close()
    with (output/"download.json").open("x") as file:
        json.dump({"schema":"horizon257-window-download-v1","plan_sha256":PLAN_SHA,"total_bytes":TOTAL_BODIES+8192,"resources":manifest},file,indent=2)
        file.flush()
        os.fsync(file.fileno())
    directory=os.open(output,os.O_DIRECTORY)
    try: os.fsync(directory)
    finally: os.close(directory)

if __name__=="__main__":
    require(len(sys.argv)==2,"usage: fetch-windows.py NEW_ABSOLUTE_DIRECTORY")
    os.umask(0o077)
    acquire(Path(sys.argv[1]))
