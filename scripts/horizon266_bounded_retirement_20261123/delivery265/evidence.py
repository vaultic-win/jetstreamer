"""Seal the eight original RPC records and exercise their bindings in the uploader namespace."""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys


def verify(expectation):
    records = expectation["independent_evidence"]
    assert expectation["epoch"] == 265 and len(records) == 8
    assert not expectation.get("successor")
    for record in records:
        p = Path(record["path"])
        assert p.resolve(strict=True) == p
        with p.open("rb") as stream:
            meta = os.fstat(stream.fileno())
            assert stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and not meta.st_mode & 0o222, p
            assert hashlib.file_digest(stream, "sha256").hexdigest() == record["sha256"], p
            assert p.stat().st_ino == meta.st_ino
    return [record["sha256"] for record in records]


def repair():
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from successor_fit import CG, D, M, V, bound, funds, partition, pin, price, ref

    root = D / "horizon-upload-265-ordinary-v215"
    directory = D / "horizon265-sealed-rpc-repair-v216"
    package = V / directory.name
    source_dir = Path("/home/ubuntu/.jetstreamer-private/boundary-collector265-20261120-v1/epoch-265")
    end = bound(ref(root / "terminal.json"))
    book = bound(end["issuer"])
    assert not (end["ready"] or end["reservation_released"] or (CG / book["service"]).exists())
    assert set(end["remote"]) == {"epoch-265.epoch-status.json"}
    assert (root / "operation.log").read_text().rstrip().endswith("evidence must be root-owned and immutable")
    plan = bound(book["plan"])
    binding = plan["epoch_expectations"]["265"]
    expectation = bound(binding)
    assert binding["sha256"] == "5f0a003fb1134a855ddfd5d1bd2d6b9bb628fb85cedfdc53a25be1668da4a88b"
    with partition.take():
        completed = directory / "completion.json"
        if completed.exists():
            return ref(completed)
        if not directory.exists():
            allocation = price(256*M, 2*M, 2*M, closed_disk=True)
            ledger = D / ("horizon-bounded265-residual-" + directory.name)
            ledger.mkdir(mode=0o700)
            assigned = funds.put(ledger / "assignment.json", allocation)
            directory.mkdir(mode=0o700)
            funds.put(directory / "booking.json", dict(assignment=assigned, failed=ref(root / "terminal.json"), plan=book["plan"]))
        assert bound(ref(directory / "booking.json"))["failed"] == ref(root / "terminal.json")
        members, mounts = [], []
        for row in expectation["independent_evidence"]:
            original = Path(row["path"])
            assert original.parent == source_dir and bound(row)
            members.append(dict(source=str(original), name=original.name, sha256=row["sha256"], mode=0o444))
            mounts.append(str(package / original.name) + ":" + str(original))
        assert len(set(mounts)) == len(members) == 8
        if not package.exists():
            seal_plan = directory / "seal.json"
            value = dict(schema="jetstreamer-sealed-deployment-plan-v1", destination=str(package), members=members)
            if not seal_plan.exists():
                funds.put(seal_plan, value)
            assert bound(ref(seal_plan)) == value
            sealer = pin(V / "horizon251-published-sealer-20261118-v1/horizon251-sealer",
                         "faf7aa8270b3472969bf394d4486cdf94445e30e4f15bc6acd38bed56880877a")
            subprocess.run([sealer["path"], str(seal_plan), "--plan-sha256", ref(seal_plan)["sha256"],
                            "--self-sha256", sealer["sha256"]], check=True)
        for row in members:
            p = package / row["name"]
            assert p.stat().st_uid == 0 and p.stat().st_mode & 0o777 == 0o444 and ref(p)["sha256"] == row["sha256"]
        mount = "BindReadOnlyPaths=" + " ".join(mounts)
        props = [p for p in book["properties"] if p.startswith(("Protect", "NoNewPrivileges=", "CapabilityBoundingSet=",
                                                                "AmbientCapabilities=", "ReadWritePaths="))]
        props.extend([mount, "MemoryMax=128M", "MemorySwapMax=0", "AllowedCPUs=8", "CPUQuota=100%", "RuntimeMaxSec=30"])
        command = ["/usr/bin/python3", "-IB", str(Path(__file__).resolve()), "verify", binding["path"]]
        out = subprocess.check_output(["systemd-run", "--quiet", "--pipe", "--wait", "--collect",
                                      "--unit=horizon265-sealed-rpc-check-v216", *["--property="+p for p in props], *command])
        assert json.loads(out) == [r["sha256"] for r in expectation["independent_evidence"]]
        return funds.put(completed, dict(booking=ref(directory / "booking.json"), seal=ref(package / "deployment-seal-receipt.json"),
                                         plan=book["plan"], expectation=binding, bind_property=mount, hashes=json.loads(out)))


if __name__ == "__main__":
    assert __debug__ and os.geteuid() == 0
    if sys.argv[1:] == ["repair"]:
        print(repair())
    else:
        action, path = sys.argv[1:]
        assert action == "verify"
        print(json.dumps(verify(json.loads(Path(path).read_bytes()))))
