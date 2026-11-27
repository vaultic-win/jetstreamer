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
    167: ("fe41e88c8105553aa38c3021f51be130648d6a0fdd1234adbc9e73269ce78baf", 143, 179),
    168: ("99006b75641f0b72e11672bcf408b3e7aff3ca8198ce983c89a6883f26a5ad61", 433, 532),
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
    signers = 1 if epoch in (167, 168) else 2
    require(wire[0] == signers, "unexpected signature count")
    message = wire[1 + 64 * signers:]
    require(message[0] == signers and signers <= message[3] < 128, "legacy message header")
    for index in range(signers):
        offset = 4 + 32 * index
        key = Ed25519PublicKey.from_public_bytes(message[offset:offset + 32])
        key.verify(wire[1 + index * 64:65 + index * 64], message)
    return result, base58(wire[1:65])


def flat_meter_baseline(observed, canonical, *, canonical_success=False):
    # The native counter stops at the budget on exhaustion. Compare every
    # unsaturated inner call before checking the exit of the outer instruction.
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
            if canonical_success and len(stack) == 1 and index == len(canonical) - 2:
                used, budget = int(meter[2]), int(meter[3])
                require(used < budget < used + delta and int(lm[2]) == budget,
                        "flat logging costs must exhaust the successful outer frame")
                require(canonical[index + 1:] == [f"Program {name} success"], "canonical outer result")
                suffix = observed[index + 1:]
                require(len(suffix) == 2 and re.fullmatch(
                    rf"Program failed to complete: exceeded maximum number of instructions allowed \({budget}\) at instruction #\d+",
                    suffix[0]) and suffix[1] == f"Program {name} failed: Program failed to complete",
                    "native outer result")
                return rows
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
    status = rpc["meta"]["err"]
    expected = "execution=Some(Ok(())) logs=Some("
    if status is not None:
        instruction, error = status["InstructionError"]
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
    check.add_argument("--prior-closure", type=Path, help="check the original epoch 168 or 172 metering differential")
    check.add_argument("--native-log", type=Path, help="compare patched native trace to every finalized log")
    check.add_argument("--wire-only", action="store_true", help="verify the signed input only")
    args = parser.parse_args()
    rpc, signature = signed_evidence(args.epoch, args.finalized_rpc)
    if args.prior_closure:
        require(args.epoch in (168, 172), "no captured unpatched differential for this epoch")
        raw = args.prior_closure.read_bytes()
        if args.epoch == 168:
            require(hashlib.sha256(raw).hexdigest() == "29672efbaff97d23a9a9d45a824840cb2d4cf43c6f5e8427ed3b532b41a38de2", "closure digest")
            binding = json.loads(raw)["native_trace"]
            evidence = Path(binding["path"]).read_bytes()
            require(hashlib.sha256(evidence).hexdigest() == binding["sha256"], "native trace digest")
            cmp = json.loads(evidence)
            require((cmp["entry"], cmp["transaction"]) == TARGETS[168][1:], "native trace position")
            require(cmp["trace"]["execution"] == "Some(Err(InstructionError(0, ProgramFailedToComplete)))"
                    and rpc["meta"]["err"] is None, "expected epoch 168 status differential")
            debug_logs = cmp["trace"]["logs"]
            require(debug_logs.startswith("Some(") and debug_logs.endswith(")"), "native logs")
            logs = json.loads(debug_logs[5:-1])
        else:
            require(hashlib.sha256(raw).hexdigest() == "854539f0d9450b388e136092567438134efaab19f0570dee7bdeb4fcf53120c7", "closure digest")
            cmp = json.loads(raw)["signed_target_comparison"]
            logs = cmp["trace"]["logs"]
        require(cmp["signature"] == signature and cmp["target_slot"] == rpc["slot"], "original target")
        rows = flat_meter_baseline(logs, rpc["meta"]["logMessages"], canonical_success=args.epoch == 168)
        require(rows == 9, f"expected 9 unsaturated metering rows, found {rows}")
        print(f"unpatched epoch {args.epoch}: all nine unsaturated CU rows follow flat versus byte metering")
    elif args.native_log:
        compare_native(args.native_log, args.epoch, rpc, signature)
        print(f"epoch {args.epoch}: native execution and all finalized logs match")
    else:
        print(f"epoch {args.epoch}: all signatures and original checked-in wire verified")


if __name__ == "__main__":
    main()
