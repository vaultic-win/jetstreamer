"""Reconcile a second compact 169 interval while keeping both predecessor segments charged."""
from pathlib import Path
import os
import runpy
import stat


def custody(peer, fleet):
    previous = fleet["current_private169_adjacent_hourly"]
    model = peer["bound"](INTERFACE)
    need(model["previous"] == TERMINAL and model["previous_held"] == HELD
         and model["previous_grant"] == GRANT and model["previous_lease"] == DONOR,
         "different predecessor custody")
    end, held, grant, lease = (peer["bound"](r) for r in (TERMINAL, HELD, GRANT, DONOR))
    archive = end["archive"]
    image = Path(end["image_path"])
    s = image.lstat()
    need(previous["unit"]["Id"] == held["producer_unit"] == OLD_UNIT
         and previous["phase"] == "terminal" and previous["terminal"] == end["pid1"]
         and end["pid1"]["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448"
         and previous["producer_invocation_id"] == held["producer_invocation_id"] == grant["iid"] == OLD_IID
         and previous["held_owner"] == grant["held"] == end["held"] == HELD
         and end["grant"] == GRANT and lease["profile"] == grant["profile"] == previous["profile"]
         and previous["donor"] == lease["donor"] and end["private_checkpoint_matched"]
         and not end["complete_epoch"] and not end["canonical_writes"] and not end["resource_credit_bytes"]
         and image.resolve(strict=True) == image and stat.S_ISREG(s.st_mode)
         and s.st_uid == 0 and not s.st_mode & 0o222 and s.st_nlink == 1
         and end["image"] == held["mounts"]["image"] == [s.st_dev,s.st_ino,s.st_size]
         and s.st_size == OUTPUT and archive["bytes"] == 1_924_893_119
         and archive["sha256"] == archive["typed_manifest"]["archive_sha256"] == "5e3cb1f4e8c6eb768544e51a4afe0fd2b73eca744f068cd776edbc9a4500176f"
         and archive["manifest_sha256"] == "c266d07c3b9b18d6d151e20cfe5f8ecd853a1a799ed097a5285e325538d74bec"
         and archive["typed_manifest"]["terminal"]["slot"] == 73_252_243,
         "retained 169 inode, manifest or private checkpoint changed")
    timer = "horizon-guard-169-from-73245218-20261128-v1"
    for name in (OLD_UNIT, timer+".timer", timer+".service"):
        peer["idle"](name)
    return dict(terminal=TERMINAL, previous_invocation=OLD_IID, held=HELD, grant=GRANT, lease=DONOR,
                image=str(image), identity=end["image"], archive_sha256=archive["sha256"],
                bytes=archive["bytes"], manifest_sha256=archive["manifest_sha256"])


def apply(native, before, after):
    stable(before, after)
    cap = native["adjacent_169_effective_cap"]
    old = native["adjacent_169_after"]
    need("next_169_before" not in native and cap["selected"] and cap["interface"] == OLD_INTERFACE
         and cap["producer_max"] == 48*G and cap["guard_max"] == G and cap["replaced_reserved_bytes"] == 8*G
         and cap["previous_required_ram"]-8*G == native["required_ram"] and not cap["resource_credit_bytes"]
         and old["phase"] == "terminal" and old["owner"]["invocation_id"] == OLD_IID
         and old["owner"]["lease"] == DONOR and old["enrollment"] and old["resident"] == 0
         and not native["adjacent_169_owner"] and native["adjacent_169_resident_bytes"] == 0
         and native["ram_margin"] == native["available_ram"]-native["required_ram"]
         and not native["resource_credit_bytes"], "169 compute is occupied or its compact booking changed")
    lower = min(before["resident"], after["resident"])
    need(0 <= lower <= 48*G and (not lower or before["phase"] == "worker" and before["owner"]["release"])
         and (not before["owner"] or before["enrolled"] and before["enrollment"]),
         "unqualified next 169 resident population")
    native.update(next_169_before=before, next_169_after=after, next_169_owner=live(after),
                  next_169_resident_bytes=lower)
    native["required_ram"] -= lower
    native["ram_margin"] += lower


def checked_reserve(whole, prospective):
    prior = whole["adjacent_169_accounting"]
    need(prior["charged"] and prior["phase"] == "terminal" and prior["owner"]["lease"] == DONOR
         and prior["owner"]["invocation_id"] == OLD_IID and prior["additional_home"] == OUTPUT+CONTROL
         and prior["resident_bytes"] == prior["additional_ram"] == 0,
         "the previous 169 image and controls must remain funded")
    reserve(whole, prospective)


def final_runway(whole):
    # The publication allocator runs after the 143 guard calculation and can
    # add its metadata to required_home. Carry that cost into the same maximum.
    original = whole["original_172_accounting"]
    need(original == whole["base_169"]["native"]["raw"]["joint"]["original_172_accounting"]
         and original["phase"] in ("finalizing","committed") and original["retained_home_cap"] == 288*G
         and original["producer_ram"] == 68*G and original["guard_ram"] == G
         and original["reservation_ending_bytes"] == original["resource_credit_bytes"] == 0,
         "172 finalization lost its original booking")
    publication = whole["publication168_allocation"]
    added = publication["additional_home"]
    before = whole["epoch143_protected_runway_required_home"]
    floor = whole["epoch143_protected_sibling_floor"] + whole["epoch143_remaining_replay_home"]
    need(publication["additional_ram"] == 0 and not publication["resource_credit_bytes"]
         and added == (publication["metadata_bytes"] if publication["charged"] else 0)
         and before == max(whole["required_home"]-added, floor),
         "unaccounted HOME change after the protected 143 runway")
    whole["epoch143_protected_runway_required_home"] = max(whole["required_home"], floor)
    return whole
