"""Bind the 73,773,646–73,780,397 replay to the sealed checkpoint pair and custody."""
import argparse
import json
from pathlib import Path
import re
import stat
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import following_prepare as f

PREVIOUS = f.ROOT / "epoch170-from-73766969-ram-20261128-v1"
ROOT = f.ROOT / "epoch170-from-73773645-ram-20261128-v1"
PINS = f.ROOT / "epoch170-from-73766969-20261127-v1" / "package"
OLD_UNIT = f"horizon-qualify-{PREVIOUS.name.removeprefix('epoch')}.service"
UNIT = f"horizon-qualify-{ROOT.name.removeprefix('epoch')}.service"
OLD_ALIAS = "/run/horizon-170-from-73766969-v1"
ALIAS = "/run/horizon-170-from-73773645-v1"
SLOTS = (73_773_645, 73_780_397)
GENERATIONS = (1_634_787_459_945_463, 1_634_787_462_637_589)
LENGTHS = (2_156_130_725, 2_145_581_770)
OLD_IID = "732e022b564c49e5890c4cd3a86b8169"
PIN_SEAL = dict(path=str(PINS / "deployment-seal-receipt.json"),
                sha256="92a81746c557e4200adbf7b779cdb0c1e6fa520934fc32cea38d8acd6c3a0b7a")
OLD_SCOPE = dict(path=str(PREVIOUS / "AFTER_FLOOR_WRITER_INTERFACE.json"),
                 sha256="a4ca94b87bb1a301d76eacab1b3421dd52f96b5a4e5d0074b73dd6a3d3a63078")
OLD_SEAL = dict(path=str(PREVIOUS / "package/deployment-seal-receipt.json"),
                sha256="f7c2d3fa967b1a8a64fdaf04a13e4bca67e28917d5d8c887674109fb2b764edb")
EXIT = dict(path=str(PREVIOUS / "hourly-exit/PID1_EXIT.json"),
            sha256="13ec25f4cad9b00312079867522e7a86151ef27f41f5af532b17d0764b641349")
BANK_FIELDS = ("slot", "bank_hash", "accounts_hash", "last_blockhash", "capitalization",
               "transaction_count", "tick_height", "slot_complete")


def sealed_member(seal_ref, name):
    seal = f.read(seal_ref)
    package = Path(seal_ref["path"]).parent
    f.need(seal["destination"] == str(package) and Path(name).name == name,
           "different checkpoint package")
    member, = [row for row in seal["members"] if row["name"] == name]
    ref = dict(path=str(package / name), sha256=member["sha256"])
    f.need(f.reference(ref["path"]) == ref, "changed sealed member " + name)
    return ref


def source():
    previous = f.read(OLD_SCOPE)
    f.need(previous["profile"]["sealed_package"] == OLD_SEAL and previous["last"] == SLOTS[0],
           "different preceding interval")
    packet = f.read(sealed_member(PIN_SEAL, "source-packet.json"))
    proofs = {item["slot"]: item for item in packet["independently_verified_votes"]}
    endpoints = []
    for slot, generation, length in zip(SLOTS, GENERATIONS, LENGTHS, strict=True):
        metadata = sealed_member(PIN_SEAL, f"metadata-{slot}.json")
        vote = sealed_member(PIN_SEAL, f"reference-{slot}.json")
        md, signed = f.read(metadata), f.read(vote)
        name = Path(md["name"]).name
        f.need(name == proofs[slot]["name"]
               and re.fullmatch(fr"snapshot-{slot}-[1-9A-HJ-NP-Za-km-z]+\.tar\.zst", name)
               and md["bucket"] == "mainnet-beta-ledger-us-ny5"
               and (int(md["generation"]), int(md["size"])) == (generation, length)
               and md["storage_url"] == f"gs://{md['bucket']}/{md['name']}#{generation}"
               and md["crc32c_hash"] and md["md5_hash"] and md["etag"]
               and signed["slot"] == slot and signed["containing_slot"] > slot
               and signed["vote_signature"] and signed["bank_hash"] == proofs[slot]["bank_hash"]
               and signed["last_blockhash"] == proofs[slot]["blockhash"],
               "different GCS generation or signed checkpoint")
        anchors = {key: signed[key] for key in ("block", "finalized_transaction", "native_decode")}
        for ref in anchors.values():
            f.read(ref)
        endpoints.append(dict(slot=slot, name=name, metadata=metadata, vote=vote,
                              storage_url=md["storage_url"], length=length,
                              crc32c=md["crc32c_hash"], md5=md["md5_hash"],
                              bank_hash=signed["bank_hash"], last_blockhash=signed["last_blockhash"]))
    f.need(previous["profile"]["checkpoints"] == [endpoints[0]["name"]],
           "bootstrap differs from the earlier terminal")
    run = Path(previous["run"]).with_name("from-73773645-to-73780397-ram-v1")
    return dict(schema="horizon-170-next-private-hourly-source-v1", previous=OLD_SCOPE,
                pins=PIN_SEAL, previous_native_exit=EXIT, route=UNIT, run=str(run), alias=ALIAS,
                first=SLOTS[0] + 1, last=SLOTS[1], positions=SLOTS[1] - SLOTS[0],
                endpoints=endpoints, producer_memory=56 << 30, scratch_noswap_tmpfs=40 << 30,
                home_tree_cap=8 << 30, guard_memory=1 << 30, control_home=64 << 20,
                archive_publication_authorized=False, replay_launch_authorized=False)


def predecessor(comparison_ref, bootstrap):
    proof = f.read(comparison_ref)
    exit_record = f.read(EXIT)
    release, actor = f.read(proof["release"]), f.read(proof["actor"])
    terminal = exit_record["properties"]
    point = proof["checkpoints"][-1]
    archive = proof["evidence"]["closed_segment"]
    manifest = f.read(archive["manifest"])
    path = Path(archive["path"])
    info = path.lstat()
    identity = [info.st_dev, info.st_ino, info.st_size, *divmod(info.st_mtime_ns, 1_000_000_000),
                *divmod(info.st_ctime_ns, 1_000_000_000)]
    scope = f.read(OLD_SCOPE)
    f.need(proof["schema"] == "horizon-170-successor-closed-checkpoint-comparison-v1"
           and proof["interface"] == actor["interface"] == release["interface"] == OLD_SCOPE
           and exit_record["actor"] == actor and exit_record["release"] == proof["release"]
           and actor["producer_invocation_id"] == terminal["InvocationID"] == OLD_IID
           and terminal["ActiveState"] == "inactive" and terminal["Result"] == "success"
           and terminal["ExecMainStatus"] == "0" and terminal["MainPID"] == terminal["ControlPID"] == "0"
           and proof["evidence"]["comparison"] == "closed"
           and proof["evidence"]["pid1_exit"]["native"] == terminal
           and proof["evidence"]["signed_endpoint"] == bootstrap["vote"]
           and proof["canonical_publication_authorized"] is False
           and path == Path(scope["run"]) / "ledger/epoch-170.diagnostic.jet"
           and path.resolve(strict=True) == path and identity == archive["identity"]
           and stat.S_ISREG(info.st_mode) and info.st_uid == 1001 and info.st_nlink == 1
           and manifest["archive_sha256"] == archive["sha256"]
           and manifest["output_slot_start"] == 73_766_970 and manifest["output_slot_count"] == 6_676
           and manifest["terminal"] == point and point["slot_complete"]
           and all(point[key] == bootstrap[key] for key in ("slot", "bank_hash", "last_blockhash")),
           "preceding interval has no accepted terminal and matching private archive")
    return {key: point[key] for key in BANK_FIELDS}


def local_bootstrap(custody_ref, endpoint):
    record = f.read(custody_ref)
    remote, local = record["remote_object"], record["file"]
    md = f.read(endpoint["metadata"])
    path = Path(record["destination"])
    info = path.stat()
    f.need(record["schema"] == "jetstreamer-bound-gcs-snapshot-restore-v1"
           and record["versioned_uri"] == remote["versioned_uri"] == endpoint["storage_url"]
           and record["generation"] == remote["generation"] == GENERATIONS[0]
           and record["snapshot_slot"] == endpoint["slot"] and remote["name"] == md["name"]
           and remote["bucket"] == md["bucket"]
           and remote["size"] == local["size"] == info.st_size == endpoint["length"]
           and remote["crc32c_base64"] == local["crc32c_base64"] == endpoint["crc32c"]
           and remote["md5_base64"] == local["md5_base64"] == endpoint["md5"]
           and record["r2_mutations"] is False and record["remote_mutations"] is False
           and path.resolve(strict=True) == path and path.name == endpoint["name"]
           and path.is_relative_to(Path("/home/sol")) and info.st_dev == Path("/home/sol").stat().st_dev
           and stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == local["uid"] == 1001
           and stat.S_IMODE(info.st_mode) == local["mode"] and not info.st_mode & 0o077
           and [info.st_dev, info.st_ino, info.st_mtime_ns] == [local[k] for k in ("device", "inode", "mtime_ns")],
           "bootstrap is absent, changed, or from another generation")
    digest = f.reference(path)
    after = path.stat()
    f.need(digest["sha256"] == local["sha256"]
           and (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
           == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
           "payload differs from the verified bootstrap digest")
    return digest


def service(packet, snapshot_path):
    previous = f.read(OLD_SCOPE)
    member = sealed_member(OLD_SEAL, OLD_UNIT)
    template = Path(member["path"]).read_text()
    boot, end = packet["endpoints"]
    scope = f.read(previous["following_input"])
    old_snapshot = scope["destination"]
    old_name = Path(old_snapshot).name
    old_bind = f"BindReadOnlyPaths={old_snapshot}:{OLD_ALIAS}/{old_name}"
    f.need(template.count(old_bind) == 1 and str(snapshot_path).endswith("/" + boot["name"])
           and template.count("from slot 73766969 through 73773645") == 1,
           "unexpected previous service arguments")
    bind = f"BindReadOnlyPaths={snapshot_path}:{OLD_ALIAS}/{boot['name']}"
    body = template.replace(old_bind, bind)
    body = body.replace("from slot 73766969 through 73773645", f"from slot {boot['slot']} through {end['slot']}")
    body = body.replace(previous["run"], packet["run"])
    body = body.replace(str(PREVIOUS) + "/", str(ROOT) + "/")
    body = body.replace(OLD_ALIAS + "/", ALIAS + "/")
    f.need(str(PREVIOUS) + "/" not in body and previous["run"] not in body and OLD_ALIAS + "/" not in body
           and f"ExecStart={ALIAS}/gate\n" in body and f"MemoryMax={packet['producer_memory']}\n" in body,
           "foreign service output, guard boundary or memory allowance")
    return body


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--comparison", nargs=2, metavar=("PATH", "SHA256"))
    parser.add_argument("--custody", nargs=2, metavar=("PATH", "SHA256"))
    args = parser.parse_args()
    packet = source()
    if args.comparison or args.custody:
        f.need(args.comparison and args.custody, "the closed predecessor and exact custody must both be supplied")
        comparison = dict(zip(("path", "sha256"), args.comparison, strict=True))
        custody = dict(zip(("path", "sha256"), args.custody, strict=True))
        packet["preceding_terminal"] = predecessor(comparison, packet["endpoints"][0])
        packet["bootstrap"] = local_bootstrap(custody, packet["endpoints"][0])
        packet["bootstrap_custody"] = custody
        packet["closed_comparison"] = comparison
        packet["service"] = service(packet, packet["bootstrap"]["path"])
        packet["checkpoint_names"] = "".join(p["name"] + "\n" for p in packet["endpoints"])
    print(json.dumps(packet, sort_keys=True))
