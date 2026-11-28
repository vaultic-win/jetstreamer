"""Inputs unique to the bounded epoch 159 vote-initialization feature differential."""

import hashlib
from pathlib import Path
import struct

FIRST = 68_688_000
ACCOUNT = bytes.fromhex("26d6bf1a2253ab30c7ee40659ca35dd995336d114180069c93cef1f6a09019ee")
ACTIVATED = b"\x01" + struct.pack("<Q", FIRST)
WORKER = Path(
    "/usr/local/lib/jetstreamer/epoch157-runtime-qualification-20261004-v1/jetstreamer-historical-worker-v1-5-19"
)
IMAGE = "55b09fd3cc1c67e10adcaf72d9ffa362fa3202156314dd092f6226bdabe31e94"
REVISION = "936ff7424e1306b0df07dabcd6863bf7896d2cb5"
RUNTIME = "epoch159-vote-feature-reference-20261123-v1"
UNIT = "horizon-epoch159-vote-feature-reference-20261123-v1.service"


VERIFIER = "horizon-holding-export145-20261121-v1.service"
PREVIOUS_INVOCATION = "fd406b11e15040cb9039dd9fdc48f63d"
SETTLEMENT = Path(
    "/var/lib/jetstreamer/horizon_runtime_data/epoch159-bounded-reference-20261123-v1/attempt-v1/scratch-retired.json"
)
SETTLEMENT_SHA = "c299a6b09f5f84d06abf83ef8a31393ea59d3a4024fa4c0da7bc0089949c9b58"
DONOR_UNITS = Path(
    "/var/lib/jetstreamer/horizon_runtime_data/epoch159-bounded-reference-20261123-v1/DONOR-IDLE-UNITS-checked.json"
)
DONOR_UNITS_SHA = "3425172e0e5f66dc8d6ac188f4b02e39e8c7727a8fca7fb512963d1796d09900"


OWNER = bytes.fromhex("03c0a0cdcb06d2daefae82d16fee7acf61ec737b23481b21946a767000000000")
BOUNDARY_HASH = bytes.fromhex("1feb1e461e2de4190952b931de1b8394dfbea5e11c61e9e62a7e84507c9dcf5d")


def observe(writes, slot, version, pubkey, data, lamports, owner, executable, rent_epoch, stored_hash):
    if pubkey != ACCOUNT:
        return
    if len(writes) == 4:
        raise ValueError("excess writes to historical check_init_vote_data feature")
    writes.append(
        dict(
            lamports=lamports,
            owner=owner.hex(),
            executable=executable,
            rent_epoch=rent_epoch,
            stored_hash=stored_hash.hex(),
            slot=slot,
            write_version=version,
            data_size=len(data),
            data_prefix=data[:9].hex(),
            data_sha256=hashlib.sha256(data).hexdigest(),
        )
    )


def accepted(writes):
    return (
        len(writes) == 1
        and writes[0]["slot"] == FIRST
        and writes[0]["lamports"] == 953520
        and writes[0]["owner"] == OWNER.hex()
        and not writes[0]["executable"]
        and writes[0]["rent_epoch"] == 158
        and writes[0]["stored_hash"] == BOUNDARY_HASH.hex()
        and writes[0]["data_size"] == len(ACTIVATED)
        and writes[0]["data_prefix"] == ACTIVATED.hex()
        and writes[0]["data_sha256"] == hashlib.sha256(ACTIVATED).hexdigest()
    )
