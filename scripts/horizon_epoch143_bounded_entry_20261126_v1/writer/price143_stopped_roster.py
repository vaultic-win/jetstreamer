#!/usr/bin/python3 -IB
"""Use the complete stopped-roster provider for 143's existing hourly booking."""

import argparse
import hashlib
from pathlib import Path
import json
import runpy
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import continuation_price
import rollover143 as roll

core = continuation_price.prior
G = 1 << 30
M = 1 << 20
TREE = 64 * G
EVIDENCE = 64 * M
RAM = 41 * G
PROVIDER = core.RT / "epoch162-first-hourly-completion-20261127-v2/issued-price-v5"
SEAL = "6bff49a31525ee2e1cdd5861a9d1d30e43686ddc79e5932bf7a85f5a3df35a96"


def complete_roster():
    path = PROVIDER / "deployment-seal-receipt.json"
    seal, ref = core.read(path, SEAL)
    core.need(seal["destination"] == str(PROVIDER), "foreign stopped-roster provider")
    for member in seal["members"]:
        file = PROVIDER / member["name"]
        raw = file.read_bytes()
        core.need(file.parent == PROVIDER and file.resolve(strict=True) == file and
                  file.stat().st_uid == 0 and not file.stat().st_mode & 0o222 and
                  len(raw) == member["bytes"] and hashlib.sha256(raw).hexdigest() == member["sha256"],
                  "unsealed stopped-roster member " + member["name"])
    quote = runpy.run_path(str(PROVIDER / "capacity.py"))["whole_roster"]()
    core.need(quote["package"] == ref, "stopped-roster provider changed")
    return quote


def criteria(whole, fleet, held):
    base = whole["base_169"]
    raw = base["native"]["raw"]
    joint = raw["joint"]
    actors = {owner["epoch"]: owner for owner in base["observed_actors"]}
    native162 = whole["existing_162"]
    housing = base["accounting"]["rooms"]
    verification = base["accounting"]["verification168_listener"]
    core.need(whole["schema"] == "horizon-168-post-assembly-six-owner-price-v1"
              and raw["phase"] == "stopped" and whole["fleet"] == fleet
              and whole["resource_credit_bytes"] == base["resource_credit_bytes"] == raw["resource_credit_bytes"] == 0
              and whole["available_home"] - whole["required_home"] == whole["home_margin"]
              and whole["available_ram"] - whole["required_ram"] == whole["ram_margin"]
              and whole["fits"] == (whole["home_margin"] >= 0 and whole["ram_margin"] >= 0)
              and joint["producer_allowance"] == 48 * G and joint["guard_sibling_allowance"] == G
              and raw["reserved_following_170_growth_bytes"] == joint["candidate_growth"] == 36 * G
              and raw["failed_170"]["retained_producer_ram"] == 48 * G
              and raw["failed_170"]["retained_guard_ram"] == G
              and raw["assembly168"]["state"] == "queued-or-drained"
              and housing["holding_ram_available_from_serial"] == verification["scanner_ram_from_serial"] == 2 * G
              and native162 and native162["phase"] in ("held", "bootstrap", "worker")
              and set(actors) == ({143, 146, 162, 167, 172} if held else {146, 162, 167, 172})
              and actors[162]["invocation_id"] == native162["invocation_id"],
              "stopped-roster quote lost an active owner or full reservation")
    replacement = raw["replacement143"]
    if held:
        core.need(replacement and replacement["iid"] == held and replacement["mode"] == "gate"
                  and actors[143]["invocation_id"] == held and replacement["cap"] == TREE
                  and 0 <= replacement["low"] <= TREE
                  and raw["guarded_hourly_remaining"] == TREE - replacement["low"],
                  "143 stopped-roster quote lost the exact held guard")
    else:
        core.need(replacement is None and raw["guarded_hourly_remaining"] == TREE,
                  "stopped-roster quote lost the full pending 143 tree")
    return raw, joint, replacement


def price(fleet, sha, held=None, projection=False):
    fleet_ref = dict(path=fleet, sha256=sha)
    _, contract = core.read(roll.ROOT / "contract-v1/LAUNCH_PROFILE.json", roll.SHA)
    closed = roll.first_closed(core)
    whole = complete_roster()
    raw, joint, own = criteria(whole, fleet_ref, held)
    # The shared quote includes 143's entire envelope before start. The held
    # sample can deduct realized usage; keep the entire allowance for release.
    home = whole["home_margin"] - (own["low"] if own else 0)
    ram = whole["ram_margin"] - raw["hourly_ram_resident"]
    retained_home = whole["available_home"] - home - TREE - EVIDENCE
    retained_ram = whole["available_ram"] - ram - RAM
    # This is the fixed input floor the shared equation uses before adding
    # 143's growth. The independent owner caps remain reserved in retained_home.
    floor = max(joint["required_home"] - 36 * G - (44 * G + EVIDENCE),
                *(core.bound(ref)["minimum_free_bytes"] for ref in joint["guard_samples"].values()))
    core.need(core.current_fleet()[1] == fleet_ref and floor >= 9470567509909
              and (not own or own["floor"] >= floor), "143 floor or accepted fleet changed")
    return dict(schema="horizon-epoch143-first-hourly-replacement-fit-v1", recorded_unix_seconds=int(time.time()),
                fleet=fleet_ref, contract=contract, closed141=closed, projection_only=projection,
                held_invocation=held, candidate_guard_sample=own and own["sample"], candidate_home_bytes=TREE+EVIDENCE,
                candidate_ram_bytes=RAM, candidate_cpu_quota_micros=3_000_000, phase170="stopped",
                next_170_reserved=raw["reserved_following_170_growth_bytes"], whole_roster=whole,
                retained_required_home_bytes=retained_home, retained_required_ram_bytes=retained_ram,
                available_home_bytes=whole["available_home"], available_ram_bytes=whole["available_ram"],
                home_margin_bytes=home, ram_margin_bytes=ram, guard_floor_bytes=floor,
                disk_fits=not projection and home >= 0, memory_fits=not projection and ram >= 0,
                resource_credit_bytes=0, archive_publication_authorized=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("fleet")
    parser.add_argument("sha")
    parser.add_argument("held", nargs="?")
    parser.add_argument("--project", action="store_true")
    args = parser.parse_args()
    print(json.dumps(price(args.fleet,args.sha,args.held,args.project)))
