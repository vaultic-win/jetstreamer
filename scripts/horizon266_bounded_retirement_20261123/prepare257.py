"""Price a cold 257 restore alongside 265 and prepare its units on the released CPUs."""
import json
import os
from pathlib import Path
import subprocess
import sys

from successor_fit import CG, D, M, V, bound, funds, partition, pin, price, props, ref

PRODUCER = "horizon-257-native-input-20261120-v1.service"
PRIOR = V / "horizon-native257-prepared-cold-2c0d1a5f-v156-v1/prepared.json"
NEW_ATTEMPT = "cold-closed266-with265-v1"
BOOTSTRAP_SHA = "ef1218b00bbaf827061a27e8e04ae1b7b52b9a2ecb9d149ddd6dd022ac6dcd06"


def staged_units(preparation, cpus, directory):
    result = {}
    for name, member in preparation["units"].items():
        source = Path(member["path"])
        assert ref(source) == member
        assert (Path("/etc/systemd/system") / name).resolve(strict=True) == source
        state = props(name, ["ActiveState", "InvocationID", "Job", "DropInPaths"])
        assert state == dict(ActiveState="inactive", InvocationID="", Job="", DropInPaths="")
        unit = source.read_text().replace(preparation["attempt"], NEW_ATTEMPT)
        if name == PRODUCER:
            old = "CPUAffinity=" + " ".join(map(str, preparation["cpu_affinity"]))
            assert unit.splitlines().count(old) == 1
            unit = unit.replace(old, "CPUAffinity=" + " ".join(map(str, cpus)))
        target = directory / name
        with target.open("x") as output:
            output.write(unit)
            os.fchmod(output.fileno(), 0o400)
        result[name] = ref(target)
    assert len(result) == 4 and PRODUCER in result
    subprocess.run(["systemd-run", "--quiet", "--pipe", "--wait", "--collect",
                    "--unit=" + directory.name + "-verify.service",
                    "--property=MemoryMax=256M", "--property=MemorySwapMax=0",
                    "--property=AllowedCPUs=8", "--property=CPUQuota=100%",
                    "--property=RuntimeMaxSec=45", "--property=TasksMax=32",
                    "--property=ProtectSystem=strict", "--property=ProtectHome=read-only",
                    "--property=PrivateTmp=yes", "--property=PrivateNetwork=yes",
                    "--property=NoNewPrivileges=yes",
                    "/usr/bin/systemd-analyze", "verify", "--man=no",
                    *[row["path"] for row in result.values()]], check=True, timeout=55)
    return result


def resources(fit):
    uploader = bound(fit["closed265_delivery"])
    release = bound(uploader["donor"])
    assert release["original"] == fit["issued"] and release["terminal"] == fit["closed266"]
    assert uploader["donor"]["sha256"] == "c2112c2cf4d97797dbf9d1d2c347c2e00c954c14eedba5572b621aa22e7588af"
    extent = fit["extent"]
    assert extent["identity"] == release["current"]["identity"]
    assert extent["first"]["blocks"] == extent["second"]["blocks"] == release["retained_backing_bytes"]
    assert Path("/sys/block/loop18/ro").read_text().strip() == "1"
    donor = bound(release["original"])
    assert uploader["reserve_after"] == donor["producer"] - uploader["gross"]
    bootstrap = pin(D / "horizon257-after-closed266-v215-a1/assessment.json",
                    BOOTSTRAP_SHA)
    original = bound(bootstrap)
    ram, disk = original["candidate_ram"], original["candidate_disk"]
    assert ram <= uploader["reserve_after"] and not uploader["automatic_release"]
    # price() already charges 265's RAM. Its disk was carved out of the
    # drained loop, so charge it explicitly when removing that loop's growth.
    floor = fit["protected_floor"] - extent["remaining"] + release["qa_bytes"] + uploader["disk"] + fit["disk"]
    memory_margin = fit["serialized_phase_margin"] - ram
    disk_margin = extent["free"] - floor - disk
    assert memory_margin >= 0 and disk_margin >= 0, (memory_margin, disk_margin)
    cpus = donor["cpu"]
    peers = {}
    for name in fit["after"]:
        if not (CG / name).exists():
            assert fit["before"][name] == fit["middle"][name] == fit["after"][name] == 0
            continue
        manager = props(name, ["MainPID", "InvocationID", "ActiveState"])
        pid = int(manager["MainPID"])
        mask = sorted(os.sched_getaffinity(pid))
        assert manager["ActiveState"] == "active" and pid in map(int, (CG / name / "cgroup.procs").read_text().split())
        assert props(name, list(manager)) == manager and set(cpus).isdisjoint(mask)
        peers[name] = dict(manager, cpus=mask)
    if uploader["service"] not in peers:
        terminal = bound(ref(D / "horizon-upload-265-ordinary-v215/terminal.json"))
        assert terminal["issuer"] == fit["closed265_delivery"] and not terminal["reservation_released"]
        assert not (CG / uploader["service"]).exists()
    assert cpus == list(range(8))
    return dict(bootstrap=bootstrap, release=uploader["donor"], delivery=fit["closed265_delivery"],
                cpus=cpus, live_peers=peers, protected_floor=floor, required_ram=ram,
                required_disk=disk, memory_margin=memory_margin, disk_margin=disk_margin)


def main():
    assert __debug__ and os.geteuid() == 0
    attempt, = sys.argv[1:]
    assert attempt.isascii() and attempt.isalnum()
    name = "horizon257-cold-units-with265-" + attempt
    destination = D / name
    with partition.take():
        allocation = price(256 * M, 4 * M, 2 * M)
        model = resources(allocation)
        prepared = pin(PRIOR, "64fc8661d632ac235813e447a5bb5fa3a1df35aa6d3d81d16b866a1c2249d21c")
        ledger = D / ("horizon-bounded265-residual-" + name)
        destination.mkdir(mode=0o700)
        ledger.mkdir(mode=0o700)
        assignment = funds.put(ledger / "assignment.json", allocation)
        units = staged_units(bound(prepared), model["cpus"], destination)
        receipt = funds.put(destination / "preparation.json", dict(
            assignment=assignment, resources=model, previous_preparation=prepared, units=units,
            attempt=NEW_ATTEMPT, units_installed=False, producer_started=False))
        print(json.dumps(receipt))


if __name__ == "__main__":
    main()
