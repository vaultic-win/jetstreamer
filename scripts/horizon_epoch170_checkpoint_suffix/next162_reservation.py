"""Carry the verified first 162 segment and price the next interval on the same compute loan."""
from hashlib import file_digest
import os
from pathlib import Path
import stat


G = 1 << 30
CONTROL = 64 << 20
OUTPUT = 3 * G
ROOT = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch162-first-hourly-completion-20261127-v2")
VERIFIED = {
    "path": str(ROOT / "SPLIT162_FIRST_DERIVED_SEGMENT_VERIFIED.json"),
    "sha256": "445b05009592b381506701162673494fe3d6deb3851a33adade0f4e44d6a64ad",
}


def identity(st):
    return [st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns]


def custody(peer):
    valid = peer["bound"](VERIFIED)
    manifest = peer["bound"](valid["typed_manifest"])
    next_input = peer["bound"](valid["next_bootstrap_preparation"])
    segment = valid["validated_derived_segment"]
    manager = peer["idle"](valid["unit"])
    need = peer["need"]
    need(manager["ActiveState"] == valid["manager_drain"]["ActiveState"] == "inactive"
         and valid["manager_exit_zero"]["INVOCATION_ID"] == valid["invocation"]
         and valid["manager_exit_zero"]["_PID"] == "1"
         and valid["manager_exit_zero"]["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448"
         and valid["native_validator"]["_SYSTEMD_INVOCATION_ID"] == valid["invocation"]
         and manifest == segment["derived_manifest"] and manifest["epoch"] == 162
         and manifest["terminal"]["slot"] == next_input["replay_positions"][0] - 1 == 69_991_076
         and manifest["terminal"]["accounts_hash"] == next_input["bootstrap"]["account_hash"]
         and manifest["terminal"]["bank_hash"] == next_input["bootstrap"]["bank_hash"]
         and next_input["replay_positions"] == [69_991_077, 69_998_119]
         and segment["verified_slot_count"] == manifest["output_slot_count"] == 7077
         and not segment["materialized"] and valid["source_files_preserved"]
         and not valid["resource_credit_bytes"], "different verified first 162 segment or next interval")
    # The capped frames and their source manifest are inside the retained private image.
    image = valid["read_only_source_image"]
    source = Path(image["path"])
    recorded = source.lstat()
    need(source.resolve(strict=True) == source and stat.S_ISREG(recorded.st_mode)
         and recorded.st_uid == 0 and recorded.st_nlink == 1 and not recorded.st_mode & 0o222
         and identity(recorded) == image["identity"]
         and Path(segment["source_capped_archive"]["path"]).parent == source.parent / "ledger",
         "first 162 capped source image changed")
    stock = segment["source_stock_frame"]
    stock_path = Path(stock["path"])
    with stock_path.open("rb") as handle:
        before = os.fstat(handle.fileno())
        digest = file_digest(handle, "sha256").hexdigest()
        need(stock_path.resolve(strict=True) == stock_path and stat.S_ISREG(before.st_mode)
             and before.st_nlink == 1 and identity(before) == identity(stock_path.lstat())
             and digest == stock["sha256"], "first 162 stock frame changed")
    return dict(verification=VERIFIED, derived_manifest=valid["typed_manifest"],
                derived_archive_sha256=segment["derived_archive_sha256"], retained_image=image,
                retained_stock=dict(path=str(stock_path), sha256=digest, identity=identity(before)),
                next_preparation=valid["next_bootstrap_preparation"], interval=next_input["replay_positions"],
                first_producer=segment["source_capped_archive"]["producer_invocation"],
                verification_invocation=valid["invocation"])


def reserve(peer, proof, base, row, final):
    bound = custody(peer)
    need = peer["need"]
    need(row is not None and row["phase"] == "terminal" and row["epoch"] == 162
         and row["invocation_id"] == bound["first_producer"] and row["donor"] == peer["DONOR"]
         and "prospective_162_interval_two" not in final, "first 162 loan is unavailable or already reused")
    profile = row["profile"]
    loan = proof["donor"]
    need(profile["producer_memory_max"] == 62 * G and profile["guard_memory_max"] == G
         and profile["producer_memory_max"] + profile["guard_memory_max"] ==
             profile["combined_ram"] == loan["usable_166_ram"]
         and profile["producer_cpu_micros"] == 2_000_000 and profile["guard_cpu_micros"] == 1_000_000
         and profile["producer_cpu_micros"] + profile["guard_cpu_micros"] <= loan["usable_166_cpu_micros"]
         and profile["swap_bytes"] == 0 and row["realized_ram"] == final["realized_162_ram"] == 0
         and final["ram_margin"] == base["ram_margin"], "first 162 compute reservation changed")
    need(profile["home_image"] == peer["IMAGE"] == 8 * G and profile["control"] == peer["CONTROL"] == CONTROL
         and final["required_home"] == final["guard_floor"] + base["remaining_output"] + peer["IMAGE"]
         and final["home_margin"] == base["available_home"] - final["required_home"],
         "prior retained output or protected floor changed")
    charge = OUTPUT + CONTROL
    final["required_home"] += charge
    final["home_margin"] -= charge
    final["fits"] = bool(base["fits"] and final["fits"] and min(final["ram_margin"], final["home_margin"]) >= 0)
    final["prospective_162_interval_two"] = dict(
        **bound, donor=peer["DONOR"], previous_profile=profile, retained_first_image_allowance=peer["IMAGE"],
        additional_output=OUTPUT, additional_control=CONTROL, additional_home=charge,
        additional_compute=0, producer_and_guard_already_charged=True, resource_credit_bytes=0,
        live_owner_admitted=False)
