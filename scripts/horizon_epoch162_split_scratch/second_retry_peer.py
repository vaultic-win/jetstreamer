"""Price the 162 retry on the existing loan and preserve the drained, unreleased predecessor."""
from pathlib import Path
import runpy
from types import FunctionType


G = 1 << 30
CONTROL = 64 << 20
OUTPUT = 3 * G
ROOT = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch162-second-replay-20261128-v2")
PKG = ROOT / "issued-split-v3"
UNIT = "horizon-qualify-162-second-replay-20261128-v2.service"
FIELD = "current_private162_second_retry"
INTERFACE = dict(path=str(ROOT / "RETRY_INTERFACE_V3.json"),
                 sha256="2192e657ff4cf56a9404dc41cf5d3223cb437afa3eb7225676b4116d95c18712")
PROVIDER = dict(path=str(PKG / "deployment-seal-receipt.json"),
                sha256="051fcc7f5a7ef31a8fa6fb31372d029c83428e5c4eceb1eecc6dd7235fd64393")
READER = dict(path=str(PKG / "status162.py"),
              sha256="7fb5906b790419dee2f89bde43941603212153cb92db3817343093aceb030e5c")
PREVIOUS = "0a4f55edf2b14df6a8a99a41d09834fc"
OLD_UNIT = "horizon-qualify-162-second-replay-20261128-v1.service"
CLOSURE = dict(path=str(ROOT / "UNRELEASED_PREDECESSOR.json"),
               sha256="7e29859237415f95d8d8d7b070df842900dadc09f4829c4983ac97c02f10d038")
OLD_MODULE = dict(path=str(ROOT.parent / "epoch162-first-hourly-completion-20261127-v2/issued-price-v12/second162_peer.py"),
                  sha256="b5770fbf8d097611a1d6f9e3bd9ad950303e6cde893741679d29ea1027998211")


def old_module(peer):
    peer["frozen"](OLD_MODULE["path"], OLD_MODULE)
    return runpy.run_path(OLD_MODULE["path"])


def confirm_previous(peer, before):
    need = peer["need"]
    closure = peer["bound"](CLOSURE)
    old = before["owner"]
    need(before["enrolled"] and before["phase"] == "terminal" and old and old["phase"] == "terminal"
         and closure["invocation_id"] == old["invocation_id"] == PREVIOUS
         and old["unit"]["Id"] == closure["old_unit"] == OLD_UNIT and not old["unit"]["ControlGroup"]
         and old["actor"] == closure["held"] and old["terminal"] == closure["native_end"]
         and peer["bound"](closure["terminal"])["pid1"] == old["terminal"]
         and peer["bound"](closure["stop"])["terminal"]["pid"] == 0
         and before["floor"] == closure["guard_floor"] and not old["release"]
         and closure["no_grant"] and closure["no_worker"] and not closure["resource_credit_bytes"],
         "previous 162 gate is not the drained unreleased actor")
    for suffix in (".service", ".timer"):
        peer["idle"]("horizon-guard-162-second-replay-20261128-v1" + suffix)
    return dict(closure=CLOSURE, owner=old, retired_guard_floor=before["floor"])


def predecessor_view(peer, fleet):
    """Only hide the authenticated second diagnostic row from the first interval reader."""
    registered = [r for r in fleet["actual_active_private_diagnostics"] if r["epoch"] == 162]
    if not registered:
        return fleet
    row = fleet.get(FIELD)
    peer["need"](row and registered == [row] and row["epoch"] == 162 and row["unit"]["Id"] == UNIT
                 and row["phase"] in ("held", "bootstrap", "worker") and not row["archive_publication_authorized"]
                 and not row["canonical_replay_claimed"] and not row["resource_credit_bytes"],
                 "foreign 162 diagnostic beside the original terminal")
    held, ref = peer["read"](ROOT / "split-v1/HELD_OWNER.json")
    peer["need"](ref == row["held_owner"] and held == row["actor"] and held["producer_unit"] == UNIT
                 and held["producer_invocation_id"] == row["producer_invocation_id"] == row["unit"]["InvocationID"],
                 "different recorded second 162 actor")
    return dict(fleet, actual_active_private_diagnostics=[
        r for r in fleet["actual_active_private_diagnostics"] if r["epoch"] != 162
    ])


def first_peer(original):
    original = old_module(original)["first_peer"](original)

    def current(fleet):
        return original["current"](predecessor_view(original, fleet))

    def recheck(fleet, row):
        return original["recheck"](predecessor_view(original, fleet), row)

    # charge() reads its own accepted fleet. Rebind just that function's
    # recheck so its terminal arithmetic and original validation are retained.
    charge = FunctionType(original["charge"].__code__, dict(original, recheck=recheck))
    return dict(original, current=current, recheck=recheck, charge=charge)


def registered_writer(peer, writer):
    active = peer["bound"](writer)
    ready = peer["bound"](active["ready"])
    if "second162_retry_reader" not in ready and "second162_retry_provider" not in ready:
        return False
    directory = Path(active["new"]["program"]).parent
    reader = dict(path=str(directory / "second162_retry_status.py"), sha256=READER["sha256"])
    peer["need"](ready["second162_retry_reader"] == reader and ready["second162_retry_provider"] == PROVIDER
                 and ready["package"]["path"] == str(directory / "deployment-seal-receipt.json")
                 and peer["read"](directory / "second162_retry_provider.json")[0] == PROVIDER,
                 "cadence does not own this second 162 reader")
    peer["frozen"](reader["path"], reader)
    return True


def sample(peer, fleet, writer):
    earlier = old_module(peer)["sample"](peer, predecessor_view(peer, fleet), writer)
    history = confirm_previous(peer, earlier)
    return dict(sample_retry(peer, fleet, writer), unreleased_predecessor=history)


def sample_retry(peer, fleet, writer):
    need = peer["need"]
    interface = peer["bound"](INTERFACE)
    need(interface["field"] == FIELD and interface["unit"] == UNIT
         and interface["provider"] == PROVIDER and interface["reader"] == READER and interface["closure"] == CLOSURE
         and interface["first_slot"] == 69_991_077 and interface["last_slot"] == 69_998_119,
         "different second 162 reader or interval")
    seal = peer["bound"](PROVIDER)
    installed = {m["name"]: m for m in seal["members"]}
    need(seal["destination"] == str(PKG) and installed["status162.py"]["sha256"] == READER["sha256"],
         "different second 162 operator")
    peer["frozen"](READER["path"], READER)
    observer = runpy.run_path(READER["path"])
    need(observer["PKG"] == PKG and observer["FIELD"] == FIELD, "unexpected second 162 observer")
    enrolled = registered_writer(peer, writer)
    row = observer["current"](fleet)
    if row is None:
        peer["idle"](UNIT)
        timer = "horizon-guard-162-second-replay-20261128-v2"
        peer["idle"](timer + ".service")
        peer["idle"](timer + ".timer")
        return dict(enrolled=enrolled, phase="precharged", owner=None, floor=0, remaining=OUTPUT, resident=0)
    need(enrolled, "second 162 actor lacks the writer enrollment")
    layout = observer["api"]()
    profile = layout.profile(36)
    actor = row["actor"]
    intent = peer["bound"](actor["intent"])
    lease, lease_ref = peer["read"](layout.DATA / "LEASE.json")
    pre = peer["bound"](lease["prestart"])
    enrollment, enrolled_ref = peer["read"](ROOT / "SPLIT162_ENROLLMENT.json")
    need(intent["prestart"] == lease["prestart"] and intent["lease"] == lease_ref
         and lease["owner_enrollment"] == pre["enrollment"] == enrolled_ref
         and intent["unit"] == lease["unit"] == pre["unit"] == actor["producer_unit"] == UNIT
         and enrollment["operator"] == PROVIDER and enrollment["whole_roster"] == pre["whole_roster"]["package"]
         and pre["exclusive_166_lease"] and pre["fits"] and pre["phase"] == "prestart"
         and pre["held_invocation"] is None and not intent["canonical_publication_authorized"]
         and pre["boot_id"] == lease["boot_id"] == actor["boot_id"] == layout.BOOT.read_text().strip()
         and row["donor"] == lease["donor"] == pre["donor"] == enrollment["donor"] == peer["DONOR"]
         and pre["profile"] == lease["profile"] == intent["profile"] == row["profile"] == profile
         and profile["home_image"] == OUTPUT and profile["control"] == CONTROL and profile["combined_ram"] == 63*G
         and profile["producer_memory_max"] == 62*G and profile["guard_memory_max"] == G and profile["swap_bytes"] == 0,
         "second 162 actor did not receive the existing loan")
    protected = peer["bound"](actor["guard_plan"])
    iid = row["producer_invocation_id"]
    need(protected["unit"] == UNIT and protected["invocation_id"] == iid == actor["producer_invocation_id"]
         and row["held_owner"]["path"] == str(layout.DATA / "HELD_OWNER.json"),
         "second 162 guard belongs to a different producer")
    floor = protected["minimum_free_bytes"]
    remaining = OUTPUT
    resident = 0
    phase = row["phase"]
    if phase != "terminal":
        disk = row["disk"]
        need(disk["floor"] == floor and disk["maximum"] == OUTPUT and disk["fixed_control"] == CONTROL
             and 0 <= disk["remaining"] <= OUTPUT and phase in ("held", "bootstrap", "worker"),
             "different second 162 guard or output bounds")
        remaining = disk["remaining"]
        if phase == "worker":
            need(row["worker"] and row["release"] and row["guard"], "unprotected second 162 worker")
            resident = peer["resident"](layout, row)
    else:
        need(row["terminal"] and not row["unit"]["ControlGroup"], "second 162 terminal not drained")
    owner = dict(epoch=162, phase=phase, unit=row["unit"], invocation_id=iid, lease=lease_ref,
                 actor=row["held_owner"], guard_plan=actor["guard_plan"], release=row.get("release"),
                 worker=row.get("worker"), mounts=row.get("mounts"), terminal=row["terminal"])
    return dict(enrolled=enrolled, phase=phase, owner=owner, floor=floor, remaining=remaining, resident=resident)


def apply(need, base, final, before, after):
    need("second_162_accounting" not in final and before["owner"] == after["owner"]
         and before["phase"] == after["phase"] and before["floor"] == after["floor"]
         and before["enrolled"] == after["enrolled"] and before["unreleased_predecessor"] == after["unreleased_predecessor"], "second 162 owner or writer changed during the quote")
    charge = final["prospective_162_interval_two"]
    need(charge["additional_output"] == OUTPUT and charge["additional_control"] == CONTROL
         and charge["additional_home"] == OUTPUT + CONTROL and charge["additional_compute"] == 0
         and final["frozen_first_162_image"]["prospective_materialization_bytes"] == 1_854_349_312
         and charge["retained_first_image_allowance"] == 0 and final["realized_162_ram"] == 0
         and final["home_margin"] == base["available_home"] - final["required_home"],
         "changed original or second 162 future reservations")
    occupied = min(before["resident"], after["resident"])
    remaining = max(before["remaining"], after["remaining"])
    floor = before["floor"]
    need(0 <= occupied <= 62*G and 0 <= remaining <= OUTPUT and floor >= 0
         and (before["phase"] == "worker" or occupied == 0)
         and (before["phase"] in ("held", "bootstrap", "worker") or remaining == OUTPUT),
         "invalid second 162 resource observations")
    required = max(final["required_home"] - OUTPUT, floor) + remaining
    final["required_home"] = required
    final["guard_floor"] = max(final["guard_floor"], floor)
    final["home_margin"] = base["available_home"] - required
    final["ram_margin"] += occupied
    # The native base has one RAM and one disk predicate. A guarded second
    # worker can only realize its own already reserved producer pages.
    need(base["fits"] == (min(base["home_margin"], base["ram_margin"]) >= 0),
         "unrecognized base price before applying second 162 residency")
    final["fits"] = min(base["home_margin"], base["ram_margin"] + occupied,
                        final["home_margin"], final["ram_margin"]) >= 0
    charge["live_owner_admitted"] = before["phase"] in ("held", "bootstrap", "worker")
    owner = before["owner"]
    final["second_162_actor"] = (dict(phase=owner["phase"], unit=owner["unit"], held_owner=owner["actor"],
                                     producer_invocation_id=owner["invocation_id"]) if owner else None)
    final["second_162_accounting"] = dict(interface=INTERFACE, reader=READER, provider=PROVIDER,
                                          phase=before["phase"], owner=before["owner"], enrolled=before["enrolled"],
                                          unreleased_predecessor=before["unreleased_predecessor"],
                                          armed_floor=floor, remaining_output=remaining, retained_control=CONTROL,
                                          resident_lower_bytes=occupied, full_output_reservation=OUTPUT,
                                          additional_compute=0, resource_credit_bytes=0)
