"""Switch the four inactive 257 units using the qualified native prepare operation."""
import os
from pathlib import Path
import subprocess
import sys
import time

from prepare257 import D, M, NEW_ATTEMPT, PRIOR, V, bound, funds, partition, pin, price, props, ref, resources

SYSTEM = Path("/etc/systemd/system")
PREPARED = V / f"horizon-native257-prepared-{NEW_ATTEMPT}/prepared.json"
STAGED = D / "horizon257-cold-units-with265-a2/preparation.json"
SEALER = V / "horizon251-published-sealer-20261118-v1/horizon251-sealer"
SEAL_HASH = "faf7aa8270b3472969bf394d4486cdf94445e30e4f15bc6acd38bed56880877a"
GIT = ["git", "-c", "safe.directory=/home/ubuntu/workspace/jetstreamer",
       "-C", "/home/ubuntu/workspace/jetstreamer"]


def inactive(name):
    state = props(name, ["ActiveState", "InvocationID", "Job", "DropInPaths"])
    assert state == dict(ActiveState="inactive", InvocationID="", Job="", DropInPaths=""), (name, state)


def check_links(members):
    for name, binding in members.items():
        inactive(name)
        path = (SYSTEM / name).readlink()
        assert path == Path(binding["path"]) and ref(path) == binding


def rollback(original, staged):
    for name, binding in original["units"].items():
        inactive(name)
        link = SYSTEM / name
        old = Path(binding["path"])
        assert ref(old) == binding
        if link.is_symlink():
            actual = link.readlink()
            if actual == old:
                continue
            expected = Path(str(old).replace(original["attempt"], NEW_ATTEMPT))
            assert actual == expected and ref(actual)["sha256"] == staged["units"][name]["sha256"]
            link.unlink()
        link.symlink_to(old)
    check_links(original["units"])


def finish(directory, intent, staged):
    proof = bound(ref(PREPARED))
    assert proof["review"] == intent["review"] and proof["gate"] == intent["image"]
    assert proof["attempt"] == NEW_ATTEMPT and proof["cpu_affinity"] == intent["allocation"]["cpus"]
    assert {k: v["sha256"] for k, v in proof["units"].items()} == {
        k: v["sha256"] for k, v in staged["units"].items()}
    check_links(proof["units"])
    state = props("horizon-257-native-input-20261120-v1.service", ["CPUAffinity"])
    assert proof["cpu_affinity"] == list(range(8))
    assert state["CPUAffinity"] in ("0-7", "0 1 2 3 4 5 6 7"), state
    return funds.put(directory / "completion.json", dict(intent=ref(directory / "intent.json"),
                     prepared=ref(PREPARED), producer_started=False, manager=state))


def issue(directory, source, check):
    package = pin(STAGED, "002b1c881c783b5e6b450b6d2170c8798cd3e5703c1e4e7f7a3e7285a8abf936")
    staged = bound(package)
    original = bound(staged["previous_preparation"])
    assert staged["previous_preparation"] == ref(PRIOR) and staged["attempt"] == NEW_ATTEMPT
    unit = directory.name + ".service"
    if (directory / "completion.json").exists():
        return ref(directory / "completion.json")
    if (directory / "intent.json").exists():
        intent = bound(ref(directory / "intent.json"))
        if PREPARED.exists():
            return finish(directory, intent, staged)
        assert props(unit, ["MainPID", "Job", "ActiveState"])["ActiveState"] in ("failed", "inactive")
        rollback(original, staged)
        raise RuntimeError("Recovered the prior inactive units. Inspect the original native execution before retry.")
    check_links(original["units"])
    old_book = bound(pin(D / "horizon257-inert-prepare-cold-v156-v1/booking.json",
                         "350ed79d3704615d5b559a10d3f43fc5aebe039db7a4ae4188a6bb57d5e00063"))
    publication = ref(source / "publication.json")
    pub = bound(publication)
    head = subprocess.check_output([*GIT, "rev-parse", "origin/account-updates"], text=True).strip()
    assert 0 <= time.time() - pub["fetched_unix_seconds"] < 1800 and pub["remote_head"] == head
    prestart = ref(source / "prestart.json")
    assert bound(prestart)["source_publication"] == publication
    assert next(r for r in pub["artifacts"] if r["role"] == "launcher")["artifact"] == original["gate"] == old_book["image"]
    fit = price(512*M, 256*M, 256*M, prepare257=True)
    allocation = resources(fit)
    assert allocation["cpus"] == staged["resources"]["cpus"]
    if check:
        return allocation
    assert not PREPARED.exists()
    ledger = D / ("horizon-bounded265-residual-" + directory.name)
    review_package = V / (directory.name + "-review")
    execution = V / ("horizon-native257-execution-" + directory.name)
    assert not (directory.exists() or ledger.exists() or execution.exists() or review_package.exists())
    assert ref(SEALER)["sha256"] == SEAL_HASH
    directory.mkdir(mode=0o700)
    ledger.mkdir(mode=0o700)
    assignment = funds.put(ledger / "assignment.json", fit)
    review = bound(original["review"])
    review.update(attempt=NEW_ATTEMPT, cpu_affinity=allocation["cpus"], recorded_unix_seconds=int(time.time()),
                  source_publication=publication, prestart_qualification=prestart)
    draft = funds.put(directory / "review.json", review)
    plan = funds.put(directory / "seal.json", dict(schema="jetstreamer-sealed-deployment-plan-v1",
                     destination=str(review_package), members=[dict(name="review.json", source=draft["path"],
                     sha256=draft["sha256"], mode=0o444)]))
    subprocess.run([SEALER, plan["path"], "--plan-sha256", plan["sha256"], "--self-sha256", SEAL_HASH], check=True)
    review = ref(review_package / "review.json")
    assert review["sha256"] == draft["sha256"]
    properties = [v.replace("AllowedCPUs=57", "AllowedCPUs=8")
                  for v in old_book["argv"] if v.startswith("--property=")]
    argv = ["systemd-run", "--quiet", "--wait", "--unit="+unit, *properties, original["gate"]["path"],
            "prepare", review["path"], review["sha256"], original["gate"]["sha256"], str(execution)]
    intent = dict(assignment=assignment, allocation=allocation, stage=package, review=review,
                  image=original["gate"], execution=str(execution), unit=unit, argv=argv)
    funds.put(directory / "intent.json", intent)
    try:
        check_links(original["units"])
        for name in original["units"]:
            (SYSTEM / name).unlink()
        subprocess.run(argv, check=True)
        return finish(directory, intent, staged)
    except Exception:
        if not PREPARED.exists() and props(unit, ["ActiveState"])["ActiveState"] in ("failed", "inactive"):
            rollback(original, staged)
        raise


if __name__ == "__main__":
    assert __debug__ and os.geteuid() == 0
    mode, attempt, source = sys.argv[1:]
    assert mode in ("check", "prepare") and attempt.isalnum() and attempt.isascii()
    with partition.take():
        print(issue(D / ("horizon257-closed266-native-prepare-" + attempt), Path(source), mode == "check"))
