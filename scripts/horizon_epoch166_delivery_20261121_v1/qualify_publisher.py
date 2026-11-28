"""Exercise the synchronous publisher through the qualified source receiver."""
import contextlib
import json
import os
from pathlib import Path
import subprocess
import time


@contextlib.contextmanager
def capture(run):
    with contextlib.ExitStack() as stack:
        for fd, name in [(1, "stdout"), (2, "stderr")]:
            stream = stack.enter_context((run / name).open("wb"))
            saved = os.dup(fd)
            stack.callback(os.close, saved)
            stack.callback(os.dup2, saved, fd)
            os.dup2(stream.fileno(), fd)
        yield


def qualify(receiver, fixture_consumer, work, authority, live_hash, terminal,
            source, lock, watched, native, native_hash, producer, publication_unit):
    def read(path):
        return json.loads(path.read_bytes())

    def put(path, value):
        data = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
        path.write_bytes(data)
        path.chmod(0o400)
        return receiver.sha(data)

    epoch = producer.epoch
    archive = source / f"epoch-{epoch}.jet"
    current = read(work / "fit.json")
    floor = current["protected_home"]
    os.environ.update({
        "FIXTURE_AUTHORITY": str(authority),
        "FIXTURE_LIVE_SHA": live_hash,
        "FIXTURE_LOCK": json.dumps(receiver.inode(lock.stat())),
    })
    wrapper = work / "claim-fixture.py"
    wrapper.write_text('''#!/usr/bin/python3 -I
import fcntl, json, os, sys
fault, elf, *args = sys.argv[1:]
h = json.loads(os.environ["HORIZON_SOURCE_HANDOFF"])
if fault == "wrong-fd":
    h["archive_fd"], h["sidecar_fd"] = h["sidecar_fd"], h["archive_fd"]
elif fault == "unlocked":
    fcntl.flock(h["epoch_lock_fd"], fcntl.LOCK_UN)
elif fault == "wrong-terminal":
    h["terminal_sha256"] = "0" * 64
elif fault == "wrong-batch":
    h["receipt_sha256"] = "0" * 64
os.environ["HORIZON_SOURCE_HANDOFF"] = json.dumps(h)
os.execv(elf, [elf, *args])
''')
    wrapper.chmod(0o555)
    digest = receiver.sha(wrapper.read_bytes())
    checks = {}
    cases = [
            ("wrong-fd", "source descriptor differs"),
            ("unlocked", "receiver lacks original exclusive claim"),
            ("wrong-terminal", "proof digest mismatch"),
            ("wrong-batch", "terminal archive or batch identity changed"),
            ("wrong-size", "publication admission differs"),
            ("unfunded", "admitted HOME floor unavailable"),
            ("expired", "publication admission differs"),
            ("stale", "publication admission differs"),
            ("conflict", "proof digest mismatch"),
            ("dispatch", "invalid HORIZON_S3_ENDPOINT"),
            ("positive", None)]
    pre_cut = "258560f902d07e217c96a042b7e78d5c2cb105a9"
    post_cut = "eba5d1b596cd454811c466fde7a25a2ecb4b19ef"
    bounded = "58709604dfa4c97336c2e1f6fac53b862ed6f17f"
    reader_cases = {}
    if epoch in receiver.PEERS or os.environ.get("HORIZON_QA_TRANSITION_READER") == "1":
        reader_cases = {
            "original-branch": (pre_cut, None, "907c5b3c26837c75c5c62f76bb124ff4fd8fe642", None),
            "candidate-branch": (post_cut, None, post_cut, None),
            "premature-candidate": (pre_cut, "candidate", None, "reader revision is outside the publication branch"),
            "stale-reader": (post_cut, "previous", None, "qualified reader inputs differ"),
        }
        if os.environ.get("HORIZON_QA_BOUNDED_READER") == "1":
            reader_cases.update({
                "bounded-branch": (bounded, None, bounded, None),
                "premature-bounded": (post_cut, "bounded", None, "reader revision is outside the publication branch"),
                "stale-reconnect": (bounded, "candidate", None, "qualified reader inputs differ"),
            })
        cases.extend((name, test[3]) for name, test in reader_cases.items())

    for fault, expected in cases:
        for name in ("FIXTURE_READER_REVISION", "FIXTURE_QUALIFIED_READER"):
            os.environ.pop(name, None)
        if fault in reader_cases:
            revision, forced, _, _ = reader_cases[fault]
            os.environ["FIXTURE_READER_REVISION"] = revision
            if forced:
                os.environ["FIXTURE_QUALIFIED_READER"] = forced
        run = work / fault
        run.mkdir(mode=0o700)
        for name in ("scratch", "receipts"):
            (run / name).mkdir(mode=0o700)
        now = int(time.time())
        recorded = now - 181 if fault == "stale" else now
        need = (1 << 62) if fault == "unfunded" else floor
        capacity = run / "capacity.json"
        cap_sha = put(capacity, {
            "protected_bytes": need,
            "available_bytes": max(need, current["home_free"]),
            "observed_unix_seconds": recorded,
            "invocation_id": os.environ["INVOCATION_ID"],
            "all_existing_commitments_retained": True,
        })
        admission_sha = put(run / "admission.json", {
            "schema": f"horizon-epoch{epoch}-committed-publication-admission-v1",
            "epoch": epoch,
            "operation": "current-reader-sync-retain-local",
            "publication_authorized": False,
            "unit": publication_unit,
            "invocation_id": os.environ["INVOCATION_ID"],
            "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "recorded_unix_seconds": recorded,
            "valid_until_unix_seconds": now - 1 if fault == "expired" else now + 90,
            "source_directory": str(source),
            "transaction_id": terminal["transaction_id"],
            "terminal_sha256": receiver.sha((authority / "TERMINAL_SUCCESS.json").read_bytes()),
            "archive_bytes": archive.stat().st_size + (fault == "wrong-size"),
            "archive_sha256": terminal["local_archive"]["sha256"],
            "minimum_free_bytes": need,
            "capacity": {"path": str(capacity), "sha256": cap_sha},
        })
        os.environ["FIXTURE_PUBLICATION"] = str(run)
        mode = "dispatch-fixture" if fault == "dispatch" else "prepare"
        plan_path = run / "current-reader-plan.json"
        if fault == "conflict":
            put(plan_path, {"epoch": 999})

        def attempt():
            # The receiver remains the immediate owner of the inherited flock.
            with capture(run):
                receiver.receive(
                    authority, live_hash, receiver.inode(lock.stat()), watched,
                    native, native_hash, wrapper, digest,
                    [fault, str(fixture_consumer), mode, admission_sha], producer)
        if expected:
            try:
                attempt()
            except subprocess.CalledProcessError:
                observed = (run / "stderr").read_text()
                assert expected in observed, (fault, observed)
            else:
                raise AssertionError(f"{fault} reached successful completion")
            assert plan_path.exists() == (fault in ("conflict", "dispatch"))
            if fault == "conflict":
                assert read(plan_path) == {"epoch": 999}
            checks[fault] = expected
            continue

        attempt()
        result = read(run / "stdout")
        plan = read(plan_path)
        plan_inode = receiver.inode(plan_path.stat())
        attempt()
        assert read(run / "stdout") == result and receiver.inode(plan_path.stat()) == plan_inode
        assert result["archive_bytes"] == archive.stat().st_size == plan["maximum_archive_bytes"]
        assert plan["epoch_expectations"].keys() == {str(epoch)} and plan["minimum_free_bytes"] == floor
        assert result["arguments"] == [
            "sync", str(source), "--epochs", f"{epoch}-{epoch}",
            "--receipt-directory", str(run / "receipts"),
            "--current-reader-plan", str(plan_path),
            "--current-reader-plan-sha256", receiver.sha(plan_path.read_bytes()),
            "--concurrency", "1", "--part-size-mib", "8"]
        assert result["r2_mutations"] is False and result["transaction"] == terminal["transaction_id"]
        if fault in reader_cases:
            assert plan["reader_commit"] == reader_cases[fault][2]
            checks[fault] = {"commit": plan["reader_commit"], "qualification": plan["qualification"],
                             "pipeline": plan["pipeline"], "plan_sha256": result["plan_sha256"]}
            continue
        checks["plan_sha256"] = result["plan_sha256"]
        checks["positive"] = "prepared twice with an identical plan on the same inode"
    put(work / "publisher-qualification.json", checks)
