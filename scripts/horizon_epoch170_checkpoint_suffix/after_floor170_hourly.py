"""Prepare the next authenticated hourly window from the stopped disk replay's inputs."""
from pathlib import Path

import after_ram170_tree as prior
from derive_gap_price import one
import following_prepare as f

ROOT = prior.ROOT.parent / "epoch170-from-73766969-ram-20261128-v1"
UNIT = "horizon-qualify-170-from-73766969-ram-20261128-v1.service"
PREVIOUS = prior.ROOT.parent / "epoch170-from-73766969-20261127-v1"
FIRST, LAST = 73_766_969, 73_773_645
TMPFS, RAM, HOME = 40 << 30, 56 << 30, 8 << 30
BUILD = "f990dd8ed98a72f86e39e521336ed804d90040e759644dc22e33e3a38ccfdd7c"
PREDECESSOR = dict(path=str(prior.ROOT / "THIRD_TERMINAL_AND_CUSTODY.json"),
                   sha256="9b19751acffdde6dad4714f0079dd7e3bd7a9949fcdfbbc9fc9e8e74013680fd")
PACKAGE = dict(path=str(PREVIOUS / "package/deployment-seal-receipt.json"),
               sha256="92a81746c557e4200adbf7b779cdb0c1e6fa520934fc32cea38d8acd6c3a0b7a")
STOP = dict(path=str(prior.ROOT / "AFTER_RAM_FLOOR_STOP_CUSTODY.json"),
            sha256="21a333d8be96e870a3c5d1d8f088c5d0e2965a29b26e254a2f3b68092e2a9c2b")
DRAIN = dict(path=str(prior.ROOT / "AFTER_RAM_FLOOR_STOP_DRAIN.json"),
             sha256="2f99cf89c5add2bc2c3e9ddc8af300aa6f08578bdc2ca2e4367d8665db88c683")
RETIRE = dict(path=str(ROOT.parent / "epoch170-after-ram-floor-accounts-20261128-v1/state/after-ram/COMPLETE.json"),
              sha256="168c6f1b6bb4aa3c5f0000a92a574ecf208262f8488a2b0c41ae80aec5ea3212")


def source():
    manifest = f.read(PACKAGE)
    directory = PREVIOUS / "package"
    members = {row["name"]: row["sha256"] for row in manifest["members"]}
    f.need(manifest["destination"] == str(directory) and len(members) == len(manifest["members"]),
           "different accepted disk replay package")

    def member(name):
        f.need(Path(name).name == name, "indirect source member")
        result = dict(path=str(directory / name), sha256=members[name])
        f.read(result)
        return result

    previous = f.read(prior.SCOPE)
    custody = f.read(previous["following_input"])
    closed = f.read(STOP)
    drain = f.read(DRAIN)
    retired = f.read(RETIRE)
    grant = f.read(prior.RELEASE)
    predecessor = f.read(PREDECESSOR)
    first_hash, last_hash, *_ = (directory / "epoch-hashes.txt").read_text().splitlines()
    f.need(f.reference(directory / "epoch-hashes.txt")["sha256"] == members["epoch-hashes.txt"]
           and previous["profile"]["sealed_package"] == PACKAGE
           and previous["predecessor_custody"] == PREDECESSOR["path"]
           and closed["actor"] == grant["actor"] and closed["release"] == prior.RELEASE
           and closed["matched_bootstrap"] == predecessor["actual_terminal"]
           and closed["matched_bootstrap"]["slot"] == previous["bootstrap"] == FIRST
           and drain["custody"] == STOP and drain["release"] == prior.RELEASE and drain["guard_drained"]
           and retired["original_iid"] == closed["producer_invocation_id"] and retired["scope_empty"]
           and not retired["archive_or_snapshot_removed"] and not closed["verified_complete_segment"]
           and not closed["terminal_checkpoint_accepted"]
           and previous["profile"]["checkpoints"][0] == last_hash,
           "different stopped 170 or accepted predecessor")
    archive = Path(custody["destination"])
    info = archive.stat()
    f.need(archive.name == first_hash and info.st_size == 2_149_673_902
           and custody["file_identity"] == [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns]
           and custody["archive_sha256"] == "7de9fd4205ee8241c4bc5aaec54523199f749fa2b73eb3322508fc3adba9706f",
           "missing original 170 bootstrap")
    endpoints = []
    for slot, name in [(FIRST, first_hash), (LAST, last_hash)]:
        metadata = member(f"metadata-{slot}.json")
        vote = member(f"reference-{slot}.json")
        storage = f.read(metadata)
        signed = f.read(vote)
        f.need(name.startswith(f"snapshot-{slot}-") and storage["name"].split("/")[-1] == name
               and signed["slot"] == slot and signed["containing_slot"] > slot
               and signed["vote_signature"] and signed["bank_hash"] and signed["last_blockhash"],
               "different hourly 170 checkpoint")
        for key in ("block", "finalized_transaction", "native_decode"):
            f.read(signed[key])
        endpoints.append(dict(slot=slot, name=name, metadata=metadata, vote=vote,
                              bank_hash=signed["bank_hash"], last_blockhash=signed["last_blockhash"]))
    f.need(endpoints[0]["bank_hash"] == predecessor["actual_terminal"]["bank_hash"]
           and endpoints[0]["last_blockhash"] == predecessor["actual_terminal"]["last_blockhash"],
           "signed bootstrap does not match the previous terminal")
    return dict(schema="horizon-170-after-floor-hourly-source-v1", predecessor=PREDECESSOR, failed=STOP,
                drain=DRAIN, scratch_retirement=RETIRE, previous_scope=prior.SCOPE, previous_package=PACKAGE,
                immutable_bootstrap=previous["following_input"], private_partial=closed["partial"],
                first=FIRST+1, last=LAST, positions=LAST-FIRST, endpoints=endpoints,
                additional_input_copies=0, admission_or_release=False, publication_authorized=False)


def service(scope):
    previous = f.read(scope["previous_scope"])
    old = Path(previous["run"])
    run = old.with_name("from-73766969-to-73773645-ram-v1")
    spec = f.read(previous["layout"])["service"]
    old_file = PREVIOUS/"package"/prior.UNIT
    f.need(f.reference(old_file) == spec and spec["sha256"] == "f0dd83969c1bc51ae71ccf5de02db7b9e7515b9e200e12d93c525336ba9177c1",
           "different 170 unit source")
    body = old_file.read_text().replace(str(old), str(run))
    f.need(body.count(str(PREVIOUS)+"/package/") == 2, "different private bind layout")
    body = body.replace(str(PREVIOUS)+"/package/", str(ROOT)+"/package/")
    body = one(body, str(PREVIOUS)+"/barrier:", str(ROOT)+"/barrier:")
    body = one(body, "through 73787145", "through 73773645")
    body = one(body, "MemoryMax=51539607552", f"MemoryMax={RAM}")
    body = one(body, "MemoryHigh=49392123904", f"MemoryHigh={RAM-(4<<30)}")
    mount = "TemporaryFileSystem=/dev/shm:rw,nosuid,nodev,noexec,mode=1777,size=64M"
    scratch = f"TemporaryFileSystem={run}/scratch:rw,nosuid,nodev,exec,noswap,mode=0700,uid=1001,gid=1003,size={TMPFS}"
    return one(body, mount, mount+"\n"+scratch), run


def package(stage, build):
    stage = Path(stage)
    scope = source()
    proof = f.read(dict(path=str(build/"BUILD.json"), sha256=BUILD))
    f.need(proof["invocation"] == "28addaaf0ae74bc1b2ea3a25cff2b6ec" and set(proof["outputs"]) == {"gate","guard"},
           "different post-floor gate or guard build")
    members = {}
    for name, digest in proof["outputs"].items():
        binary = build/name
        f.need(f.reference(binary)["sha256"] == digest, "changed binary " + name)
        members[name] = binary, 0o555
    members["build.json"] = build/"BUILD.json", 0o444
    f.save(stage/"hourly-source.json", scope)
    members["hourly-source.json"] = stage/"hourly-source.json", 0o444
    hashes = stage/"epoch-hashes.txt"
    hashes.write_text("".join(endpoint["name"]+"\n" for endpoint in scope["endpoints"]))
    members[hashes.name] = hashes, 0o444
    unit = stage/UNIT
    body, run = service(scope)
    unit.write_text(body)
    members[UNIT] = unit, 0o444
    return members, run
