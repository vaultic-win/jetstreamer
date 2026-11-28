"""Fixed protocol-v5 client for the two deployed mainnet reference workers."""
import contextlib
import hashlib
import io
import os
import struct
import subprocess
from pathlib import Path

from car import require

WORKERS = {
    6: ("cf5fa883df75b23de82af52dc0e90c013f8e83397b445027e510a1137decc819",
        "01e4d0a1e9917701d1a148e1043b0ccf545c27f1"),
    8: ("b37733bcd5d84a5088445a6544b3348d0f878b0513d6b9dc90938936f397c0b5",
        "460c643f8e549d22c09a9cddc3b0f5be9c7b2204"),
}
DEPLOY = Path("/usr/local/lib/jetstreamer/deploy-epochs150-173-20261004-v4-epoch157-qualified")
GENESIS = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"
LIMIT = 64 << 20
U64 = struct.Struct("<Q")
U32 = struct.Struct("<I")
ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58(raw):
    zero = len(raw) - len(raw.lstrip(b"\0"))
    n = int.from_bytes(raw, "big")
    tail = []
    while n:
        n, k = divmod(n, 58)
        tail.append(ALPHABET[k])
    return "1" * zero + "".join(reversed(tail))


def vec(raw):
    return U64.pack(len(raw)) + raw


class Body(io.BytesIO):
    def take(self, n):
        require(0 <= n <= LIMIT, "invalid wire length")
        raw = self.read(n)
        require(len(raw) == n, "short wire value")
        return raw

    def u64(self):
        return U64.unpack(self.take(8))[0]

    def u32(self):
        return U32.unpack(self.take(4))[0]

    def flag(self):
        b = self.take(1)[0]
        require(b <= 1, "wire boolean")
        return b

    def vec(self, exact=None):
        n = self.u64()
        require(exact is None or n == exact, "wire vector length")
        return self.take(n)

    def eof(self):
        require(not self.read(1), "trailing wire bytes")


def writes(body, slot, previous_slot, cursor, observe=None, observe_account=None):
    count = body.u64()
    require(count <= LIMIT // 145, "write count")
    for _ in range(count):
        actual = body.u64()
        require(actual in (previous_slot, slot), "wrong write slot")
        previous_slot = actual
        require(body.u64() == cursor, "write version gap")
        cursor += 1
        if body.flag():
            body.vec(64)
        pubkey = body.vec(32)
        lamports = body.u64()
        owner = body.vec(32)
        executable = body.flag()
        rent_epoch = body.u64()
        data = body.vec()
        stored_hash = body.vec(32)
        if observe_account is not None:
            observe_account(actual, cursor - 1, pubkey, data, lamports, owner, executable, rent_epoch, stored_hash)
        if observe is not None:
            observe(actual, cursor - 1, pubkey, data)
    return count, cursor, previous_slot


def outcomes(body, expected, observe=None):
    count = body.u64()
    require(0 < count <= len(expected), "outcome count")
    successful = 0
    for tx in expected[:count]:
        # These are legacy packet transactions with a one-byte signature count.
        require(1 <= tx[0] < 128 and body.flag() and body.vec(64) == tx[1:65], "outcome signature")
        failed = body.flag()
        status = None
        if failed:
            error = body.u32()
            status = {"transaction_error": error}
            require(error <= 19, "unknown transaction error")
            if error == 8:
                status["instruction_index"] = body.take(1)[0]
                instruction = body.u32()
                status["instruction_error"] = instruction
                require(instruction <= 53, "unknown instruction error")
                if instruction == 25:  # InstructionError::Custom(u32)
                    status["custom"] = body.u32()
        else:
            successful += 1
        fee = body.u64()
        if observe is not None:
            observe(tx, status, fee)
    return count, successful


@contextlib.contextmanager
def worker(version, *, image=None):
    if image is None:
        digest, revision = WORKERS[version]
        path = DEPLOY / f"jetstreamer-historical-worker-v1-5-{version}"
    else:
        path, digest, revision = image
    require(hashlib.sha256(path.read_bytes()).hexdigest() == digest, "worker executable changed")
    env = dict(PATH="/usr/bin:/bin", LANG="C", RAYON_NUM_THREADS="8",
               SOLANA_RAYON_THREADS="8", JETSTREAMER_HISTORICAL_POH_THREADS="2")
    proc = subprocess.Popen([path], env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    session = Session(proc)
    try:
        body = session.call(0, struct.pack("<H", 5), 0)
        require(body.take(2) == b"\x05\x00" and body.vec().decode() == f"solana-v1.5.{version}" and
                body.u32() == 0 and body.vec().decode() == f"v1.5.{version}" and
                body.vec().decode() == revision and
                body.vec().decode() == "rustc 1.49.0 (e1884a8e3 2020-12-29)" and
                body.vec() == b"x86_64-unknown-linux-gnu" and body.vec().decode() == GENESIS,
                "worker handshake")
        body.eof()
        yield session
        session.call(5, b"", 5).eof()
        proc.stdin.close()
        require(proc.wait(timeout=300) == 0, "native worker failed to exit cleanly")
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        proc.stdout.close()
        proc.stdin.close()


class Session:
    def __init__(self, proc):
        self.proc = proc
        self.i = 0
        self.successful = 0

    def send(self, variant, raw):
        self.i += 1
        framed = struct.pack("<QI", self.i, variant) + raw
        require(len(framed) <= LIMIT, "request frame bound")
        self.proc.stdin.write(U32.pack(len(framed)) + framed)
        self.proc.stdin.flush()

    def response(self, variant):
        header = self.proc.stdout.read(4)
        require(len(header) == 4, "worker exited before response")
        size = U32.unpack(header)[0]
        require(12 <= size <= LIMIT, "response frame bound")
        raw = self.proc.stdout.read(size)
        require(len(raw) == size, "truncated response")
        body = Body(raw)
        require(body.u64() == self.i, "response request ID")
        tag = body.u32()
        if tag == 6:
            error = body.u32()
            raise ValueError(f"native error {error}: {body.vec().decode(errors='replace')}")
        require(tag == variant, "unexpected native response")
        return body

    def call(self, variant, raw, expected):
        self.send(variant, raw)
        return self.response(expected)

    def initialize(self, snapshot, genesis, scratch, slot, root_hash):
        pack_path = lambda p: vec(os.fsencode(p))
        body = self.call(1, pack_path(genesis) + U32.pack(0) + pack_path(snapshot) +
                         b"\x01" + pack_path(scratch), 1)
        require(body.vec().decode() == GENESIS and body.u32() == 0 and
                body.vec() == os.fsencode(snapshot) and base58(body.vec(32)) == root_hash and
                body.u64() == slot, "wrong restored state")
        body.vec(32)
        require(body.u64() == 64, "unexpected ticks per slot")
        self.cursor = body.u64()
        self.slot = slot
        body.eof()

    def checkpoint(self, slot, on_write=None, on_account=None):
        body = self.call(3, U64.pack(slot), 3)
        require(body.u64() == slot, "wrong checkpoint slot")
        state = dict(slot=slot, bank_hash=base58(body.vec(32)), accounts_hash=base58(body.vec(32)),
                     last_blockhash=base58(body.vec(32)), capitalization=body.u64(),
                     transaction_count=body.u64(), tick_height=body.u64())
        require(body.flag() and state["tick_height"] == (slot + 1) * 64, "incomplete checkpoint")
        state["write_count"], self.cursor, _ = writes(body, slot, slot, self.cursor, on_write, on_account)
        state["next_write_version"] = body.u64()
        require(state["next_write_version"] == self.cursor, "checkpoint cursor")
        body.eof()
        return state

    def process(self, slot, entries, on_outcome=None, on_write=None, on_account=None):
        for start in range(0, len(entries), 64):
            batch = entries[start:start + 64]
            request = bytearray(U64.pack(len(batch)))
            for ix, (count, digest, txs) in enumerate(batch, start):
                request.extend(struct.pack("<QQQ", slot, ix, count) + vec(digest) + U64.pack(len(txs)))
                for tx in txs:
                    request.extend(vec(tx))
            self.send(7, request)
            for ix, (_, _, txs) in enumerate(batch, start):
                sequence = completed = 0
                previous_slot = self.slot
                while True:
                    body = self.response(8)
                    require((body.u64(), body.u64(), body.u32()) == (slot, ix, sequence),
                            "entry response ordering")
                    kind = body.u32()
                    sequence += 1
                    if kind == 0:
                        n, successful = outcomes(body, txs[completed:], on_outcome)
                        completed += n
                        self.successful += successful
                    elif kind == 1:
                        _, self.cursor, previous_slot = writes(body, slot, previous_slot, self.cursor, on_write, on_account)
                    elif kind == 2:
                        ticks, complete = body.u64(), body.flag()
                        require(body.u64() == self.cursor, "entry cursor")
                        self.slot = slot
                        require(completed == len(txs) and
                                (ix != len(entries)-1 or (complete and ticks == (slot+1)*64)),
                                "native output coverage")
                    else:
                        raise ValueError("unknown chunk")
                    body.eof()
                    if kind == 2:
                        break
