"""Compare byte-exact, expanded first-bucket slot frames before epoch 162 has a footer."""

from pathlib import Path
import ctypes
import hashlib
import json
import os
import subprocess
import sys
import threading

BASE = Path("/home/sol/.jetstreamer-private/epoch162-first-hourly-20261127-v1/ledger/epoch-162.diagnostic.jet")
STOCK = "d60611775200eccdc64357ee0928b0ae99321f31c665f310f42791afe9bf6f8f"
XX = ctypes.CDLL("libxxhash.so.0")
XX.XXH64_createState.restype = ctypes.c_void_p
for name, args, ret in [
    ("XXH64_reset", [ctypes.c_void_p, ctypes.c_uint64], ctypes.c_int),
    ("XXH64_update", [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t], ctypes.c_int),
    ("XXH64_digest", [ctypes.c_void_p], ctypes.c_uint64),
    ("XXH64_freeState", [ctypes.c_void_p], ctypes.c_int),
]:
    f = getattr(XX, name)
    f.argtypes = args
    f.restype = ret


def integer(f):
    a = f.read(1)
    if len(a) != 1:
        raise ValueError("missing lencode integer")
    x = a[0]
    if x < 128:
        return x
    n = x & 127
    if not 1 <= n <= 8:
        raise ValueError("invalid lencode width")
    b = f.read(n)
    if len(b) != n or b[-1] == 0 or (n == 1 and b[0] < 128):
        raise ValueError("noncanonical lencode integer")
    return int.from_bytes(b, "little")


def stream(path, stock=False):
    with Path(path).open("rb") as f:
        a = os.fstat(f.fileno())
        if stock:
            assert (a.st_dev, a.st_ino, a.st_size) == (64512, 110166596, 32145931) and hashlib.file_digest(
                f, "sha256"
            ).hexdigest() == STOCK
            f.seek(0)
        assert f.read(8) == b"JSHZN1\0\0"
        hlen = integer(f)
        hpos = f.tell()
        config = [integer(f) for _ in range(7)]
        assert 0 < hlen <= 16 << 20 and config[:3] == [2, 128, 162] and config[3] == 69984000 and config[4] >= 128
        f.seek(hpos + hlen)
        start = f.tell()
        first, count, codec, expanded, stored, xxh = [integer(f) for _ in range(6)]
        assert (first, count, codec) == (69984000, 128, 1) and 0 < expanded <= 1 << 30 and 0 < stored <= 256 << 20
        start_hash = f.read(32)
        assert len(start_hash) == 32
        payload = f.tell()
        assert payload + stored <= a.st_size, "first bucket has not closed"
        ctx = XX.XXH64_createState()
        assert ctx and XX.XXH64_reset(ctx, 0) == 0
        failure = []
        sh = hashlib.sha256()
        raw = hashlib.sha256()
        zstd = subprocess.Popen(
            ["/usr/bin/zstd", "-dcq", "-M64M"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

        def write():
            try:
                left = stored
                while left:
                    b = f.read(min(left, 256 << 10))
                    if not b:
                        raise ValueError("source truncated")
                    sh.update(b)
                    assert XX.XXH64_update(ctx, b, len(b)) == 0
                    zstd.stdin.write(b)
                    left -= len(b)
            except BaseException as e:
                failure.append(e)
            finally:
                zstd.stdin.close()

        t = threading.Thread(target=write)
        t.start()
        total = 0
        try:
            while b := zstd.stdout.read(256 << 10):
                total += len(b)
                if total > expanded:
                    raise ValueError("declared expanded bucket length exceeded")
                raw.update(b)
        finally:
            if total > expanded:
                zstd.kill()
            t.join()
        actual = XX.XXH64_digest(ctx)
        XX.XXH64_freeState(ctx)
        if failure:
            raise failure[0]
        assert zstd.wait() == 0 and not zstd.stderr.read() and actual == xxh and total == expanded
        b = os.fstat(f.fileno())
        assert (a.st_dev, a.st_ino, a.st_mtime_ns, a.st_size) == (b.st_dev, b.st_ino, b.st_mtime_ns, b.st_size)
        return dict(
            path=str(path),
            file_bytes=a.st_size,
            header_configuration=config,
            first=first,
            last=first + count - 1,
            first_bucket_offset=start,
            payload_offset=payload,
            complete_bucket_end=payload + stored,
            extra_bytes_after_first_bucket=a.st_size - payload - stored,
            poh_start_hash_hex=start_hash.hex(),
            stored_bytes=stored,
            stored_xxh64=f"{actual:016x}",
            stored_sha256=sh.hexdigest(),
            expanded_bytes=expanded,
            encoded_slot_stream_sha256=raw.hexdigest(),
        )


def check(a, b):
    for k in [
        "header_configuration",
        "first",
        "last",
        "poh_start_hash_hex",
        "expanded_bytes",
        "encoded_slot_stream_sha256",
    ]:
        if a[k] != b[k]:
            raise ValueError("different stock prefix " + k)


if __name__ == "__main__":
    assert len(sys.argv) in [1, 2]
    a = stream(BASE, stock=True)
    assert a["complete_bucket_end"] == a["file_bytes"], "stock cut no longer ends exactly at first frame"
    b = stream(sys.argv[1]) if len(sys.argv) == 2 else a
    check(a, b)
    try:
        check(a, dict(b, encoded_slot_stream_sha256="0" * 64))
    except ValueError:
        pass
    else:
        raise RuntimeError("digest mismatch accepted")
    print(
        json.dumps(
            dict(
                stock_sha256=STOCK,
                stock=a,
                candidate=b if len(sys.argv) == 2 else None,
                digest_covers="all expanded bytes in the first complete native slot-frame stream; equality is a strict prefix reference",
                checked_native_slot_count=0,
                accepted_private_output=False,
            ),
            indent=2,
            sort_keys=True,
        )
    )
