"""Price interval two against the complete current roster and its frozen predecessor."""
import hashlib
import os
from pathlib import Path
import runpy
import time

G = 1 << 30
M = 1 << 20
RT = Path("/var/lib/jetstreamer/horizon_runtime_data")
BASE = RT / "epoch162-second-replay-20261128-v1"
FIRST = RT / "epoch162-first-hourly-completion-20261127-v2"
PKG = BASE / "issued-split-v2"
HERE = Path(__file__).resolve().parent
OPERATOR = "56a55825cbbf968f201a3dd80ce84de9de1919f515386f0e8e304527172342e2"
FIRST_VERIFIED = "445b05009592b381506701162673494fe3d6deb3851a33adade0f4e44d6a64ad"
FIRST_INVOCATION = "e08ac6700a714ea0bf2d08a40516fc7e"
FROZEN = dict(path=str(FIRST / "FIRST162_CLOSED_IMAGE_GROWTH_CUSTODY.json"),
              sha256="cc70ce6ea6370abcace4135716c985176a05f4e3bfea19bf718eb4f0e5275f1e")


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def geometry(native, free, available, held_floor):
    old = native["existing_162"]
    frozen = native["frozen_first_162_image"]
    reserve = native["prospective_162_interval_two"]
    control, output = 64*M, 3*G
    need(frozen["custody"] == FROZEN and frozen["verification"]["sha256"] == FIRST_VERIFIED
         and frozen["source"] == reserve["retained_image"]
         and frozen["occupied_home_bytes"] == 1791680512
         and frozen["rounded_output"] == 1787240448 and frozen["separate_staging_cap"] == control
         and frozen["prospective_materialization_bytes"] == frozen["rounded_output"]+control
         and frozen["net_reduction"] == 8*G-frozen["prospective_materialization_bytes"]
         and frozen["guard_floor_unchanged"] <= native["guard_floor"] and frozen["resource_credit_bytes"] == 0,
         "first 162 frozen custody, retained allocation or materialization reserve changed")
    need(old["phase"] == "terminal" and old["invocation_id"] == reserve["first_producer"] == FIRST_INVOCATION
         and old["realized_ram"] == 0 and old["profile"]["combined_ram"] == native["donor_compute"]["usable_166_ram"] == 63*G
         and old["profile"]["home_image"] == reserve["first_image_predecessor_reservation"] == 8*G
         and reserve["retained_first_image_allowance"] == 0 and reserve["interval"] == [69991077,69998119]
         and reserve["producer_and_guard_already_charged"] and reserve["additional_compute"] == 0
         and reserve["additional_output"] == output and reserve["additional_control"] == control
         and reserve["additional_home"] == output+control and not reserve["resource_credit_bytes"],
         "first/second 162 compute or output reservation changed")
    # The common producer quote includes this lane's entire output and control.
    # Keep all other booked bytes plus the control in its native disk-guard floor.
    accounting = native.get("second_162_accounting")
    remaining = accounting["remaining_output"] if accounting else output
    need(type(remaining) is int and 0 <= remaining <= output, "invalid remaining second image allocation")
    if accounting is None or not native.get("second_162_actor"):
        need(remaining == output, "unissued second image acquired disk credit")
    floor = max(native["guard_floor"], native["required_home"]-remaining, held_floor)
    required = floor+remaining
    home = min(free,native["available_home"]) - required
    ram = min(available,native["available_ram"]) - native["required_ram"]
    return dict(guard_floor=floor,required_home=required,remaining=remaining,home_margin=home,
                required_ram=native["required_ram"],ram_margin=ram,fits=bool(native["fits"] and min(home,ram)>=0))


def quote(phase, held_invocation, profile, enrollment):
    need(os.geteuid() == 0 and __debug__ and HERE == BASE/"second-price-v3", "use the sealed interval-two price")
    seal = PKG/"deployment-seal-receipt.json"
    need(hashlib.sha256(seal.read_bytes()).hexdigest() == OPERATOR, "changed issuing operator")
    l = runpy.run_path(str(PKG/"layout.py"))
    spec = l["bound"](enrollment)
    own = l["bound"](spec["whole_roster"])
    directory = Path(own["destination"])
    need(directory.parent == FIRST and directory.name.startswith("issued-price-v")
         and directory/"deployment-seal-receipt.json" == Path(spec["whole_roster"]["path"]),
         "unregistered common provider")
    for m in own["members"]:
        p = directory/m["name"]
        need(p.parent == directory and l["digest"](p) == m["sha256"], "changed common provider member")
    native = runpy.run_path(str(directory/"capacity.py"))["whole_roster"]()
    scope = l["scope"]()
    l["bound"](FROZEN)
    need(scope["previous"] == native["frozen_first_162_image"]["verification"] and l["bound"](scope["previous"])["source_files_preserved"]
         and native["package"] == spec["whole_roster"] and native["writer"] == spec["writer_active"]
         and l["bound"](native["fleet"])["owner"] == "/root" and profile == l["profile"](36)
         and profile["home_image"] == 3*G and profile["control"] == 64*M and profile["combined_ram"] == 63*G
         and not native["resource_credit_bytes"], "changed roster, writer or interval profile")
    base = native["base_169"]
    peers = base["native"]
    need(base["accounting"]["old_six_owner_lineage"]["static_169_memory"] == 69*G
         and peers["planned_169_retry"]["additional_ram"] >= 8*G and peers["planned_169_retry"]["original_169_guard_retained"]
         and peers["ram_retry_cost"]["producer_memory_max"] >= 56*G and peers["ram_retry_cost"]["original_guard_still_budgeted"]
         and base["accounting"]["verification168_listener"]["scanner_ram_from_serial"] == 2*G,
         "169, 170 or 168 reservation missing from the common price")
    peer169 = peers["independent_retry169"]
    peer_phase = peer169["phase"] if peer169 else "precharged"
    need(peer_phase in ("precharged","held","bootstrap","worker","terminal"), "foreign 169 owner")
    held_floor = 0
    if phase == "postguard":
        actor, ref = l["pinned"](l["DATA"]/"HELD_OWNER.json")
        need(actor["producer_invocation_id"] == l["manager"](l["UNIT"])["InvocationID"] == held_invocation
             and held_owner_matches(native, actor, ref)
             and actor["mounts"]["image"] == l["identity"](l["IMAGE"])[:3], "second 162 held actor not priced")
        held_floor = l["bound"](actor["guard_plan"])["minimum_free_bytes"]
    else:
        need(phase == "prestart" and held_invocation is None and not l["IMAGE"].exists(), "second prestart is occupied")
    disk = os.statvfs(BASE)
    free = disk.f_bavail*disk.f_frsize
    ram = next(int(line.split()[1])*1024 for line in Path("/proc/meminfo").read_text().splitlines() if line.startswith("MemAvailable:"))
    return dict(schema="horizon-162-split-fleet-price-v1",phase=phase,unit=l["UNIT"],scratch_gib=36,profile=profile,
        held_invocation=held_invocation,donor=native["donor"],enrollment=enrollment,exclusive_166_lease=True,
        peers={"169":{"phase":peer_phase}},boot_id=l["BOOT"].read_text().strip(),fleet=native["fleet"],writer=native["writer"],
        second_162_predecessor=scope["previous"],whole_roster=native,available_ram=ram,current_free_home=free,
        resource_credit_bytes=0,recorded_unix=time.time(),**geometry(native,free,ram,held_floor))


def held_owner_matches(native, actor, held_ref):
    """Require the common provider's separately authenticated native held occupant."""
    live = native.get("second_162_actor")
    return bool(live and live["phase"] == "held" and live["held_owner"] == held_ref
                and live["producer_invocation_id"] == actor["producer_invocation_id"])
