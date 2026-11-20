"""Compare a captured native signed swap trace with its finalized RPC evidence."""

import argparse
import base64
import hashlib
import json
import re
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


# Pin the independent base64 getTransaction results, including the actual wire,
# slot, instruction error, and original unmodified logMessages array.
TARGETS = {
    171: ("6347d1890bfe144dafdef95eee7ce6e97067236357e383ca0f731112af9cce22", 602, 1104),
    172: ("da2f1f5228400afe251f5ba3a54d80acacfe33fa60707be78bc3fd21785fd347", 645, 984),
}
METER = re.compile(r"Program (\w+) consumed (\d+) of (\d+) compute units")
INVOKE = re.compile(r"Program (\w+) invoke \[(\d+)\]")
ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def base58(data):
    number = int.from_bytes(data, "big")
    digits = ""
    while number:
        number, index = divmod(number, 58)
        digits = ALPHABET[index] + digits
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + digits


def signed_evidence(epoch, path):
    raw = path.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == TARGETS[epoch][0], "RPC evidence digest")
    result = json.loads(raw)["result"]
    encoded, encoding = result["transaction"]
    require(encoding == "base64", "unexpected RPC wire encoding")
    wire = base64.b64decode(encoded, validate=True)
    fixture_dir = Path(__file__).with_name("fixtures")
    require(wire == (fixture_dir / f"epoch{epoch}-swap.bin").read_bytes(), "signed wire fixture")
    # Both original legacy messages have two signatures and a short key list.
    require(wire[0] == 2, "unexpected signature count")
    message = wire[129:]
    require(message[0] == 2 and 2 <= message[3] < 128, "legacy message header")
    for index in range(2):
        offset = 4 + 32 * index
        key = Ed25519PublicKey.from_public_bytes(message[offset:offset + 32])
        key.verify(wire[1 + index * 64:65 + index * 64], message)
    return result, base58(wire[1:65])


def flat_meter_baseline(observed, canonical):
    # Compare the full prefix through the last successful CPI. After the top
    # frame exhausts its budget, its consumption is capped in both traces.
    delta = 0
    stack = []
    rows = 0
    for index, (local, remote) in enumerate(zip(observed, canonical)):
        invoke = INVOKE.fullmatch(remote)
        meter = METER.fullmatch(remote)
        if invoke:
            require(local == remote, f"invocation at {index}")
            depth = int(invoke[2])
            if depth == 1:
                require(not stack, f"unfinished outer instruction at {index}")
                delta = 0
            require(depth == len(stack) + 1, f"CPI depth at {index}")
            stack.append((invoke[1], delta))
        elif meter:
            lm = METER.fullmatch(local)
            name, entry_delta = stack[-1]
            require(lm and lm[1] == meter[1] == name, f"meter identity at {index}")
            require(int(meter[3]) - int(lm[3]) == entry_delta, f"available CU at {index}")
            if len(stack) == 1 and int(meter[2]) == int(meter[3]):
                require(local == remote, f"exhausted frame at {index}")
                require(index == len(canonical) - 2, "unexpected terminal frame")
                return rows
            require(int(lm[2]) - int(meter[2]) == delta - entry_delta, f"consumed CU at {index}")
            rows += 1
        else:
            require(local == remote, f"log content at {index}")
            if remote.startswith("Program log: "):
                delta += 100 - len(remote[len("Program log: "):].encode())
            elif remote.endswith(" success"):
                require(remote == f"Program {stack.pop()[0]} success", f"return at {index}")
    raise ValueError("missing terminal exhausted frame")


def compare_native(path, epoch, rpc, signature):
    _, entry, ordinal = TARGETS[epoch]
    tag = f"epoch{epoch} trace "
    prefix = f"{tag}slot={rpc['slot']} entry={entry} transaction={ordinal} signature={signature} "
    instruction, error = rpc["meta"]["err"]["InstructionError"]
    expected = f"execution=Some(Err(InstructionError({instruction}, {error}))) logs=Some("
    seen = 0
    with path.open() as captured:
        for line in captured:
            if tag not in line:
                continue
            pos = line.index(tag)
            trace = line[pos:].rstrip("\n")
            require(trace.startswith(prefix + expected) and trace.endswith(")"), "native target or execution")
            logs = json.loads(trace[len(prefix + expected):-1])
            require(logs == rpc["meta"]["logMessages"], "native/full finalized logs differ")
            seen += 1
    require(seen == 1, f"expected one original target trace, found {seen}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("epoch", type=int, choices=TARGETS)
    parser.add_argument("finalized_rpc", type=Path)
    check = parser.add_mutually_exclusive_group(required=True)
    check.add_argument("--prior-closure", type=Path, help="check the epoch 172 unpatched differential")
    check.add_argument("--native-log", type=Path, help="compare patched native trace to every finalized log")
    check.add_argument("--wire-only", action="store_true", help="verify the signed input only")
    args = parser.parse_args()
    rpc, signature = signed_evidence(args.epoch, args.finalized_rpc)
    if args.prior_closure:
        require(args.epoch == 172, "only epoch 172 has a captured unpatched differential")
        raw = args.prior_closure.read_bytes()
        require(hashlib.sha256(raw).hexdigest() == "854539f0d9450b388e136092567438134efaab19f0570dee7bdeb4fcf53120c7", "closure digest")
        cmp = json.loads(raw)["signed_target_comparison"]
        require(cmp["signature"] == signature and cmp["target_slot"] == rpc["slot"], "original target")
        rows = flat_meter_baseline(cmp["trace"]["logs"], rpc["meta"]["logMessages"])
        require(rows == 9, f"expected 9 unsaturated metering rows, found {rows}")
        print("unpatched epoch 172: all nine unsaturated CU rows follow flat versus byte metering")
    elif args.native_log:
        compare_native(args.native_log, args.epoch, rpc, signature)
        print(f"epoch {args.epoch}: native execution and all finalized logs match")
    else:
        print(f"epoch {args.epoch}: both signatures and original checked-in wire verified")


if __name__ == "__main__":
    main()
