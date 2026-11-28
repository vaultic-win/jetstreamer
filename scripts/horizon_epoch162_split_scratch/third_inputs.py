"""Bind the second epoch 162 segment to the two adjacent generation-pinned snapshots."""
from pathlib import Path
import stat

from second_interval import bind, digest, load, need, reference


RT = Path("/var/lib/jetstreamer/horizon_runtime_data")
PRIVATE = Path("/home/sol/.jetstreamer-private")
PRIOR = RT / "epoch162-second-replay-20261128-v3"
BASE = RT / "epoch162-third-replay-20261128-v1"
INPUT = PRIVATE / "epoch162-next-input-20261128.j9SpisbY"
PREVIOUS = PRIOR / "split-v1/TERMINAL.json"
PREVIOUS_SHA = "b43c8d3a1df6a2b3aa11c4d64076b59cbea6fe0cb735ed12159fb24034339577"
SCOPE_SHA = "95f362d418f76ceb40e979e49a2ae4e0bc3dec6eefae5b74ff98f206c877e8f4"
WITNESS = INPUT / "TERMINAL_BANK_WITNESS.json"
WITNESS_SHA = "7af0483755d00617ea91328de4b0f160311261427423f63f37c4a5a8c74fe377"
NAMES = INPUT / "checkpoints.txt"
SLOTS = (69_998_119, 70_004_937)
GENERATIONS = (1634787212936874, 1634787254699764)
SIZES = (1787097490, 1788689408)
PINS = ("eecff6d11c54a4482f75891b27ea76be08f28576e9d9a8569f3f0c359405181a",
        "39054b7710dee5aead6c947ed1c21b424dfb44893dd75bc0e86f0d8929a9b541")
BANK_FIELDS = ("slot", "bank_hash", "last_blockhash", "capitalization", "transaction_count",
               "tick_height", "slot_complete")


def validate_source(pin, witness, slot, generation, size, filename):
    available = witness["source"]
    keys = ("bucket", "name", "storage_url", "generation", "etag", "size", "md5_hash", "crc32c_hash")
    need(all(available[k] == pin[k] for k in keys), "different historical snapshot generation")
    bank, raw = witness["bank"], witness["raw_archive_readback"]
    need(bank["slot"] == slot and bank["epoch"] == 162 and bank["slot_complete"] is True
         and bank["tick_height"] == bank["max_tick_height"]
         and int(pin["generation"]) == generation and int(pin["size"]) == raw["bytes"] == size
         and pin["storage_url"] == f"gs://{pin['bucket']}/{pin['name']}#{generation}"
         and pin["md5_hash"] == raw["md5_hash"] and pin["crc32c_hash"] == raw["crc32c_hash"]
         and filename == Path(pin["name"]).name == f"snapshot-{slot}-{witness['accounts_hash']}.tar.zst",
         "source and frozen Bank disagree")


def checkpoints():
    prior = load(PRIOR / "SCOPE.json", SCOPE_SHA)
    end = load(PREVIOUS, PREVIOUS_SHA)
    old_ref = prior["terminal"]["terminal_witness"]
    witnesses = [bind(old_ref), load(WITNESS, WITNESS_SHA)]
    pins = [load(INPUT / name, sha) for name, sha in zip(("bootstrap.json", "terminal.json"), PINS)]
    names = NAMES.read_text().splitlines()
    need(digest(NAMES) == "b3ae4791dea438f6d62ed922eb30ea0936d75b31d24e77c7132eabf22470050b"
         and len(names) == 2, "different checkpoint names")
    for values in zip(pins, witnesses, SLOTS, GENERATIONS, SIZES, names):
        validate_source(*values)
    archive = end["archive"]
    manifest = archive["typed_manifest"]
    point = manifest["terminal"]
    need(end["private_checkpoint_matched"] and end["pid1"]["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448"
         and manifest["epoch"] == 162 and archive["sha256"] == manifest["archive_sha256"]
         and manifest["output_slot_start"] + manifest["output_slot_count"] - 1 == SLOTS[0]
         and all(point[k] == witnesses[0]["bank"][k] for k in BANK_FIELDS)
         and point["accounts_hash"] == witnesses[0]["accounts_hash"]
         and point["write_count"] == end["terminal_bank"]["observed_writes"]
         and point["next_write_version"] == end["terminal_bank"]["observed_next_write_version"],
         "preceding segment does not end at this bootstrap")
    return prior, pins, witnesses, names


def local_bootstrap(pin, witness):
    receipt_path = INPUT / "incoming/BOOTSTRAP_CUSTODY.json"
    receipt_ref = reference(receipt_path)
    receipt = bind(receipt_ref)
    path = INPUT / "incoming" / Path(pin["name"]).name
    st = path.lstat()
    payload = receipt["file"]
    remote = receipt["remote_object"]
    need(receipt["schema"] == "jetstreamer-bound-gcs-snapshot-restore-v1"
         and receipt["destination"] == str(path) and receipt["snapshot_slot"] == SLOTS[0]
         and receipt["generation"] == remote["generation"] == GENERATIONS[0]
         and receipt["versioned_uri"] == remote["versioned_uri"] == pin["storage_url"]
         and receipt["script_sha256"] == "38a2b4bf9d3e854694e114caaf04ca92599dc131ce2db4d407962c190d7c325a"
         and receipt["gcloud_account"] == "gce-ci@principal-lane-200702.iam.gserviceaccount.com"
         and not receipt["r2_mutations"] and not receipt["remote_mutations"]
         and payload["sha256"] == witness["raw_archive_readback"]["sha256"]
         and payload["crc32c_base64"] == remote["crc32c_base64"] == pin["crc32c_hash"]
         and payload["md5_base64"] == remote["md5_base64"] == pin["md5_hash"]
         and remote["size"] == payload["size"] == SIZES[0]
         and path.resolve(strict=True) == path and stat.S_ISREG(st.st_mode) and st.st_nlink == 1
         and (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_uid) ==
             tuple(payload[k] for k in ("device", "inode", "size", "mtime_ns", "uid"))
         and stat.S_IMODE(st.st_mode) == payload["mode"] == 0o600,
         "different private bootstrap custody")
    return path, receipt_ref
