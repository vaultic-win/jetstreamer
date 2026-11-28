"""Account for one bounded third image on the closed 166 loan, retaining both earlier segments."""
import os
from pathlib import Path
import stat

G = 1 << 30
OUTPUT = 3*G
CONTROL = 64 << 20
ROOT = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch162-third-replay-20261128-v1")
PRIOR = ROOT.with_name("epoch162-second-replay-20261128-v3")
UNIT = "horizon-qualify-162-third-replay-20261128-v1.service"
PREVIOUS_UNIT = "horizon-qualify-162-second-replay-20261128-v3.service"
FIELD = "current_private162_third_hourly"
TERMINAL = dict(path=str(PRIOR/"split-v1/TERMINAL.json"),
                sha256="b43c8d3a1df6a2b3aa11c4d64076b59cbea6fe0cb735ed12159fb24034339577")
IMAGE = Path("/home/sol/.jetstreamer-private")/PRIOR.name/"mutable.ext4"


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def prior_fleet(peer, fleet):
    """Project the third lane out of previous readers only after validating its exact recorded actor."""
    row = fleet.get(FIELD)
    if not row or row["phase"] == "terminal":
        return fleet
    active = fleet["actual_active_private_diagnostics"]
    need(row["phase"] in ("held","bootstrap","worker") and [r for r in active if r["epoch"] == 162] == [row]
         and row["unit"]["Id"] == UNIT and not row["canonical_replay_claimed"] and not row["archive_publication_authorized"]
         and not row["resource_credit_bytes"], "unregistered third 162 fleet row")
    actor, ref = peer["read"](ROOT/"split-v1/HELD_OWNER.json")
    need(ref == row["held_owner"] and actor == row["actor"] and actor["producer_unit"] == UNIT
         and actor["producer_invocation_id"] == row["unit"]["InvocationID"] == row["producer_invocation_id"],
         "different third held owner in fleet")
    return dict(fleet, actual_active_private_diagnostics=[r for r in active if r["epoch"] != 162])


def custody(peer, earlier):
    owner = earlier["owner"]
    end = peer["bound"](TERMINAL)
    held, grant = (peer["bound"](end[k]) for k in ("held","grant"))
    iid = "c64af2c83b994e299e375b44dee7ce21"
    need(earlier["enrolled"] and earlier["phase"] == "terminal" and owner["phase"] == "terminal"
         and owner["unit"]["Id"] == held["producer_unit"] == PREVIOUS_UNIT
         and owner["invocation_id"] == held["producer_invocation_id"] == grant["iid"] == iid
         and owner["actor"] == grant["held"] == end["held"] and held["guard_plan"] == owner["guard_plan"]
         and owner["terminal"] == end["pid1"] and end["private_checkpoint_matched"]
         and not end["canonical_writes"] and not end["resource_credit_bytes"]
         and end["archive"]["typed_manifest"]["terminal"]["slot"] == 69_998_119,
         "second 162 is not the accepted terminal")
    digest = end["archive"]["sha256"]
    st = IMAGE.lstat()
    need(IMAGE.resolve(strict=True) == IMAGE and str(IMAGE) == end["image_path"] and stat.S_ISREG(st.st_mode)
         and st.st_uid == 0 and st.st_nlink == 1 and not st.st_mode & 0o222
         and [st.st_dev,st.st_ino,st.st_size] == end["image"] == [64512,119080492,OUTPUT]
         and end["archive"]["bytes"] == 1_662_214_309 and digest == end["archive"]["typed_manifest"]["archive_sha256"]
         and digest == "728f3c0ef56670b4747dc0ad4dfc5f084e10d793c907ef9c5639ddb22b1c4ac9",
         "second 162 accepted image or manifest changed")
    for unit in (PREVIOUS_UNIT, "horizon-guard-162-second-replay-20261128-v3.timer",
                 "horizon-guard-162-second-replay-20261128-v3.service"):
        peer["idle"](unit)
    return dict(terminal=TERMINAL, invocation_id=iid, held=end["held"], grant=end["grant"],
                image=end["image"], path=str(IMAGE), archive_sha256=digest,
                archived_failures=earlier["unreleased_predecessor"])


def enrollment(peer, interface):
    path = ROOT/"SPLIT162_ENROLLMENT.json"
    if not os.path.lexists(path):
        return None
    spec, ref = peer["read"](path)
    info = peer["bound"](interface)
    source = peer["bound"](spec["whole_roster"])
    signer = peer["bound"](spec["writer_active"])
    ready = peer["bound"](signer["ready"])
    need(spec["schema"] == "horizon-private-162-third-enrollment-v1"
         and spec["interface"] == interface and spec["operator"] == info["provider"] == ready["third162_provider"]
         and spec["second_terminal"] == ready["third162_predecessor"] == info["previous"] == TERMINAL
         and ready["third162_interface"] == interface and spec["donor"] == peer["DONOR"]
         and Path(spec["capacity"]["path"]) == Path(source["destination"])/"third162_price.py"
         and any(m["name"] == "third162_price.py" and m["sha256"] == spec["capacity"]["sha256"] for m in source["members"]),
         "unknown third 162 booking")
    return ref


def occupant(second, third):
    a, b = second["owner"],third["owner"]
    need(a and a["unit"]["Id"] == PREVIOUS_UNIT and a["phase"] == "terminal" and
         (not b or b["unit"]["Id"] == UNIT), "two 162 producers claim the loan")
    return b or a


def compare_samples(before, after):
    keys = ("phase", "owner", "enrolled", "floor", "enrollment", "custody")
    need(all(before[k] == after[k] for k in keys), "third 162 changed across the native census")
    need(before["floor"] >= 0 and all(0 <= r["remaining"] <= OUTPUT for r in (before,after))
         and (before["phase"] in ("held","bootstrap","worker")
              or before["remaining"] == after["remaining"] == OUTPUT), "unbounded third 162 output")
    return max(before["remaining"], after["remaining"])


def apply_resident(base, final, before, after):
    compare_samples(before,after)
    measured = [s["resident"] for s in (before,after)]
    need("third162_producer_residency" not in final and final["second_162_accounting"]["phase"] == "terminal"
         and final["second_162_accounting"]["resident_lower_bytes"] == final["realized_162_ram"] == 0
         and all(type(v) is int and 0 <= v <= 62*G for v in measured), "repeated third-162 RAM charge")
    lower = min(measured)
    if any(measured):
        owner = before["owner"]
        need(before["phase"] == "worker" and owner["phase"] == "worker" and owner["unit"]["Id"] == UNIT
             and owner["actor"] and owner["release"] and owner["worker"] and owner["guard_plan"],
             "resident pages are not in the issued third worker")
    floors = (base["home_margin"],final["home_margin"])
    amounts = (base["ram_margin"],final["ram_margin"])
    need(base["fits"] == (min(floors[0],amounts[0]) >= 0) and final["fits"] == (min(*floors,*amounts) >= 0),
         "unknown gate before native third-162 residency")
    final["ram_margin"] += lower
    final["fits"] = min(*floors,min(amounts)+lower) >= 0
    final["third162_producer_residency"] = dict(observed_bytes=measured,realized_bytes=lower,
        held_owner=before["owner"]["actor"] if before["owner"] else None,producer_cap=62*G)


def reserve(quote, before, after, prospective):
    remaining = compare_samples(before,after)
    previous = quote["second_162_accounting"]
    booked = after["enrollment"]
    charged = bool(booked) or prospective
    need("third_162_accounting" not in quote and previous["phase"] == "terminal" and previous["remaining_output"] == OUTPUT
         and previous["retained_control"] == CONTROL and quote["prospective_162_interval_two"]["additional_home"] == OUTPUT+CONTROL
         and previous["unreleased_predecessor"] == after["custody"]["archived_failures"] and not quote["resource_credit_bytes"]
         and quote["donor_compute"]["usable_166_ram"] == 63*G and quote["donor_compute"]["usable_166_cpu_micros"] == 5_750_000
         and (not after["owner"] or booked and after["enrolled"]), "closed custody, 166 loan or third enrollment changed")
    cost = remaining+CONTROL if charged else 0
    quote["third_162_predecessor"] = after["custody"]["terminal"]
    quote["third_162_accounting"] = dict(phase=after["phase"], owner=after["owner"], writer_enrolled=after["enrolled"],
        enrollment=booked, prospective=bool(prospective and not booked), previous=after["custody"], charged=charged,
        maximum_output=OUTPUT, retained_control=CONTROL, remaining_output=remaining, additional_home=cost,
        observed_floor=after["floor"], additional_ram=0, additional_cpu=0,
        resident_credit=quote["third162_producer_residency"]["realized_bytes"])
    quote["required_home"] += cost
    quote["home_margin"] -= cost
    quote["fits"] = quote["fits"] and quote["home_margin"] >= 0
    return quote


def protect_live(whole):
    """Reserve simultaneous growth above the installed, independently enforced floors."""
    lane = whole["third_162_accounting"]
    if not lane["charged"] or lane["phase"] == "terminal":
        return whole
    hourly = whole["after_floor170_accounting"]
    runway170 = hourly["home_growth"] if hourly["replacement_selected"] else whole["after_ram170_accounting"]["home_growth_bytes"]
    floor = max([whole.get("epoch143_installed_guard_floor") or 0, *whole["observed_sibling_guard_floors"]])
    need(runway170 in (8*G,36*G) and 0 <= lane["remaining_output"] <= OUTPUT, "different concurrent replay runway")
    required = max(whole["epoch143_protected_runway_required_home"],floor+whole["epoch143_remaining_replay_home"]+
                   runway170+lane["remaining_output"])
    whole["third162_joint_guard_requirement"] = required
    whole["home_margin"] = min(whole["home_margin"],whole["available_home"]-required)
    whole["fits"] = whole["fits"] and whole["home_margin"] >= 0
    return whole


def protect_hourly_170(candidate, whole):
    """A newly armed 170 floor must leave the issued third image usable as well."""
    lane = whole["third_162_accounting"]
    if not lane["charged"] or lane["phase"] == "terminal":
        return candidate
    required = max(candidate["required_home"],candidate["guard_floor"] + candidate["protected_143_remaining"]
                   + candidate["candidate_170_growth_bytes"] + lane["remaining_output"])
    margin = min(candidate["home_margin"], candidate["available_home"]-required-candidate["shared_drawdown_allowance"])
    return dict(candidate,required_home=required,home_margin=margin,fits=candidate["fits"] and margin >= 0,
                protected_162_remaining=lane["remaining_output"])
