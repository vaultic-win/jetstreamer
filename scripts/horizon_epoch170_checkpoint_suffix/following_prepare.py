"""Prepare the private 73,766,970–73,787,145 deployment from Anza's accepted source and local build."""

import argparse
import json
import os
import re
import stat
import subprocess
from datetime import datetime
from hashlib import file_digest, sha256
from pathlib import Path

ROOT = Path("/var/lib/jetstreamer/horizon_runtime_data")
DEST = ROOT / "epoch170-from-73766969-20261127-v1"
PREVIOUS = ROOT / "epoch170-from-73746882-20261127-v1"
SOURCE_SHA = "fd2a07ec1a136a57b7613168ff4e22931e575c6fc97a68d3c1c21921335c0e8a"
CAPTURE_SHA = "1f84466d9ec0697cd1b2e4c367f557ec63370935af882ef5d4d5379fd5082920"
SEALER = Path(
    "/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment"
)
SEALER_SHA = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3"
UNIT = "horizon-qualify-170-from-73766969-20261127-v1.service"
ALIAS = Path("/run/horizon-170-from-73766969-v1")
SLOTS = [73_766_969, 73_773_645, 73_780_397, 73_787_145]
RELATIVE = Path("scripts/horizon_epoch170_checkpoint_suffix")


def need(ok, message):
    if not ok:
        raise ValueError(message)


def reference(path):
    path = Path(path)
    with path.open("rb") as source:
        digest = file_digest(source, "sha256").hexdigest()
    return {"path": str(path), "sha256": digest}


def read(ref):
    path = Path(ref["path"])
    need(path.resolve(strict=True) == path, "indirect receipt path")
    body = path.read_bytes()
    need(sha256(body).hexdigest() == ref["sha256"], "receipt changed: " + str(path))
    return json.loads(body)


def save(path, document):
    b = (json.dumps(document, indent=2) + "\n").encode()
    from closed_successor import persist

    persist(path, b)
    return reference(path)


def seal(destination, members, plan):
    rows = [
        {
            "name": name,
            "source": str(path),
            "sha256": reference(path)["sha256"],
            "mode": mode,
        }
        for name, (path, mode) in members.items()
    ]
    binding = save(
        plan,
        {
            "schema": "jetstreamer-sealed-deployment-plan-v1",
            "destination": str(destination),
            "members": rows,
        },
    )
    need(reference(SEALER)["sha256"] == SEALER_SHA, "native deployment sealer changed")
    if not destination.exists():
        subprocess.run(
            [
                str(SEALER),
                str(plan),
                "--plan-sha256",
                binding["sha256"],
                "--self-sha256",
                SEALER_SHA,
            ],
            check=True,
        )
    sealed = reference(destination / "deployment-seal-receipt.json")
    confirmed = read(sealed)
    declared = {entry["name"]: (entry["sha256"], entry["mode"]) for entry in rows}
    actual = {
        entry["name"]: (entry["sha256"], int(entry["mode"], 8))
        for entry in confirmed["members"]
    }
    need(
        confirmed["destination"] == str(destination)
        and confirmed["plan_sha256"] == binding["sha256"]
        and confirmed["sealer_sha256"] == SEALER_SHA
        and not any(
            confirmed[field]
            for field in (
                "remote_mutations",
                "replay_launch_authorized",
                "publication_authorized",
            )
        )
        and actual == declared
        and all(
            reference(destination / name)["sha256"] == digest
            and stat.S_IMODE((destination / name).stat().st_mode) == mode
            for name, (digest, mode) in declared.items()
        ),
        "sealed files differ from the plan",
    )
    return sealed


def git(root, *args):
    return subprocess.check_output(
        ["/usr/bin/git", "-c", "safe.directory=" + str(root), "-C", str(root), *args]
    )


def source_files(packet):
    need(
        packet["range"] == [SLOTS[0] + 1, SLOTS[-1]]
        and packet["bootstrap_slot"] == SLOTS[0]
        and packet["bootstrap_required_bytes"] == 2_149_673_902,
        "different following interval",
    )
    votes = packet["independently_verified_votes"]
    need([v["slot"] for v in votes] == SLOTS, "following checkpoints out of order")
    names = []
    files = {}
    for point in votes:
        slot = point["slot"]
        md = read(point["gcs"])
        vote = read(point["vote"])
        name = Path(md["name"]).name
        need(
            md["bucket"] == "mainnet-beta-ledger-us-ny5"
            and name == point["name"]
            and re.fullmatch(
                r"snapshot-" + str(slot) + r"-[1-9A-HJ-NP-Za-km-z]+\.tar\.zst", name
            )
            and vote["slot"] == slot
            and vote["bank_hash"] == point["bank_hash"]
            and vote["last_blockhash"] == point["blockhash"],
            "different snapshot or confirmed vote",
        )
        names.append(name)
        files[f"metadata-{slot}.json"] = (Path(point["gcs"]["path"]), 0o444)
        files[f"reference-{slot}.json"] = (Path(point["vote"]["path"]), 0o444)
    checkpoint = packet["checkpoint_list"]
    path = Path(checkpoint["path"])
    need(
        reference(path) == checkpoint and path.read_text().splitlines() == names,
        "wrong checkpoint-name list",
    )
    files["epoch-hashes.txt"] = (path, 0o444)
    return files


def accepted_input(packet_ref, packet, parent_ref):
    parent = read(parent_ref)
    source = Path(packet_ref["path"]).parent
    intake_root = ROOT / "epoch170-following-bootstrap-20261127-v1"
    native_ref = parent["receipt"]
    native = read(native_ref)
    start_path = Path(parent["start"]["path"])
    need(
        Path(parent_ref["path"]) == intake_root / "INPUT_CUSTODY.json"
        and start_path.parent == intake_root
        and re.fullmatch(r"START_[0-9]+\.json", start_path.name)
        and Path(native_ref["path"]) == source / "payload/GENERATION_CUSTODY.json"
        and parent["source_packet"] == packet_ref
        and parent["GCS"] == packet["bootstrap_metadata"]
        and parent["remote_writes"] is False,
        "following bootstrap belongs to another intake",
    )
    start = read(parent["start"])
    acceptance = read(start["admission"])
    need(
        start["unit"] == "horizon-input-170-73766969-gcs-v1.service"
        and acceptance["fit"] is True
        and acceptance["source_packet"] == packet_ref
        and acceptance["remote_writes"] is False,
        "different or unadmitted GCS transfer",
    )
    md = read(packet["bootstrap_metadata"])
    remote = native["remote_object"]
    observed = native["file"]
    uri = f"gs://{md['bucket']}/{md['name']}#{md['generation']}"
    need(
        native["schema"] == "jetstreamer-bound-gcs-snapshot-restore-v1"
        and native["versioned_uri"]
        == remote["versioned_uri"]
        == md["storage_url"]
        == uri
        and native["script_sha256"] == packet["restore_source"]["sha256"]
        and native["snapshot_slot"] == SLOTS[0]
        and native["generation"] == remote["generation"] == int(md["generation"])
        and remote["bucket"] == md["bucket"]
        and remote["name"] == md["name"]
        and native["remote_mutations"] is False
        and native["r2_mutations"] is False
        and remote["size"]
        == observed["size"]
        == int(md["size"])
        == packet["bootstrap_required_bytes"]
        and remote["crc32c_base64"] == observed["crc32c_base64"] == md["crc32c_hash"]
        and remote["md5_base64"] == observed["md5_base64"] == md["md5_hash"]
        and re.fullmatch("[0-9a-f]{64}", observed["sha256"])
        and observed["sha256"] == parent["actual_sha256"],
        "unverified bootstrap payload",
    )
    path = Path(native["destination"])
    st = path.lstat()
    identity = [st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns]
    need(
        path.resolve(strict=True) == path == source / "payload" / Path(md["name"]).name
        and stat.S_ISREG(st.st_mode)
        and st.st_nlink == 1
        and st.st_uid == observed["uid"]
        and stat.S_IMODE(st.st_mode) == observed["mode"]
        and not st.st_mode & 0o077
        and st.st_dev == Path("/home/sol").stat().st_dev
        and identity == [observed[k] for k in ("device", "inode", "size", "mtime_ns")],
        "single-copy bootstrap inode differs from its custody receipt",
    )
    when = native["observed_at_utc"]
    observed_at = datetime.fromisoformat(when)
    need(
        observed_at.tzinfo is not None
        and start["observed"] <= observed_at.timestamp() <= parent["time"],
        "unbound custody timestamp",
    )
    return {
        "destination": str(path),
        "file_identity": identity,
        "single_copy": True,
        "completed_utc": when,
        "archive_sha256": observed["sha256"],
        "native": native_ref,
        "custody": parent_ref,
        "versioned_uri": uri,
    }


def package(args):
    capture = read(
        {"path": str(DEST / "PREDECESSOR_CAPTURE_ACTIVE.json"), "sha256": CAPTURE_SHA}
    )
    need(capture["pidfd_target"] == 354777, "unexpected predecessor")
    packet_ref = {"path": str(args.packet), "sha256": SOURCE_SHA}
    packet = read(packet_ref)
    files = source_files(packet)
    intake = accepted_input(packet_ref, packet, reference(args.custody))
    build = read(reference(args.native_build))
    git(
        args.repository,
        "merge-base",
        "--is-ancestor",
        args.commit,
        "refs/remotes/origin/account-updates",
    )
    remote = (
        git(args.repository, "rev-parse", "refs/remotes/origin/account-updates")
        .decode()
        .strip()
    )
    for name, digest in build["source"].items():
        need(
            sha256(git(args.repository, "show", f"{args.commit}:{name}")).hexdigest()
            == digest
            and sha256(git(args.repository, "show", f"{remote}:{name}")).hexdigest()
            == digest
            and reference(args.repository / name)["sha256"] == digest,
            "different native source: " + name,
        )
    need(
        set(build["outputs"]) == {"guard", "gate"}
        and all(
            reference(args.native_build.parent / n)["sha256"] == h
            for n, h in build["outputs"].items()
        )
        and set(build["tests"])
        == {"old-gate", "following-gate-test", "existing-guard-tests", "guard-tests"}
        and all(
            reference(args.native_build.parent / (n + ".tests"))["sha256"] == h
            for n, h in build["tests"].items()
        ),
        "incomplete native build or tests",
    )
    terminal = read(reference(args.build_terminal))
    need(
        terminal["exit"] == 0
        and terminal["evidence"]["build"] == reference(args.native_build)
        and terminal["evidence"]["journal"]["INVOCATION_ID"] == build["invocation"],
        "unconfirmed native build",
    )
    template = RELATIVE / "continuation" / (UNIT + ".in")
    unit = git(args.repository, "show", f"{args.commit}:{template}").decode()
    need(
        unit.count("@BOOTSTRAP_SOURCE@") == 1
        and args.work.stat().st_dev == Path("/home/sol").stat().st_dev,
        "unknown service or staging filesystem",
    )
    need(
        os.geteuid() == 0
        and args.work.stat().st_uid == 0
        and stat.S_IMODE(args.work.stat().st_mode) == 0o700,
        "unsafe package work directory",
    )
    spec = args.work / UNIT
    from closed_successor import persist

    persist(spec, unit.replace("@BOOTSTRAP_SOURCE@", intake["destination"]).encode())
    input_file = args.work / "following-input.json"
    save(input_file, intake)
    provenance = args.work / "BUILD.json"
    save(
        provenance,
        {
            "commit": args.commit,
            "branch": "origin/account-updates",
            "native_build": reference(args.native_build),
            "native_terminal": reference(args.build_terminal),
            "source": build["source"],
            "outputs": build["outputs"],
            "tests": build["tests"],
            "compiler": build["compiler"],
            "guard": build["outputs"]["guard"],
            "gate": build["outputs"]["gate"],
        },
    )
    files.update({n: (args.native_build.parent / n, 0o555) for n in ("guard", "gate")})
    files.update(
        {
            UNIT: (spec, 0o444),
            "source-packet.json": (args.packet, 0o444),
            "following-input.json": (input_file, 0o444),
            "bootstrap-custody.json": (Path(intake["native"]["path"]), 0o444),
            "build.json": (provenance, 0o444),
        }
    )
    return seal(DEST / "package", files, args.work / "package-plan.json")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for value in (
        "repository",
        "work",
        "packet",
        "custody",
        "native-build",
        "build-terminal",
    ):
        parser.add_argument("--" + value, type=Path, required=True)
    parser.add_argument("--commit", required=True)
    print(json.dumps(package(parser.parse_args())))


if __name__ == "__main__":
    main()
