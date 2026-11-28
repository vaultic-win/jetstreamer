"""Calculate a non-admitting fourth-interval proposal from the issued 169 held price and exact third custody."""
import argparse
from copy import deepcopy
import json
from pathlib import Path
import runpy
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import fourth162_price as source
from fourth_interval import BASE, RT, bind, need, reference

HELD = RT/"epoch169-from-73245218-20261128-v1/split-v1"
POST = dict(path=str(HELD/"POST_GUARD.json"),sha256="c5a18bdf26cc096b05ef83a2c66778012ec2e67a34c2c5a9903409fb94d28133")
G = 1 << 30


def module(files,name):
    result = {"__name__":"qualification","__file__":str(source.NEW/name)}
    exec(compile(files[name][0],name,"exec"),result)
    return result


def project(revision):
    from issue_fourth162 import confirm
    confirm(revision)
    source.writer.published(revision,[Path(__file__)])
    interface,info = source.writer.contract(source.INTERFACE_SHA)
    files = source.members(revision)
    fourth = module(files,"fourth162_peer.py")
    price = module(files,"fourth162_price.py")
    adjacent = module(files,"adjacent169_peer.py")
    original = bind(POST)
    whole = deepcopy(original["whole_roster"])
    grant = bind(reference(HELD/"GRANT.json"))
    need(grant["postguard"] == POST and original["fits"] and whole["package"] == dict(path=str(source.OLD/"deployment-seal-receipt.json"),sha256=source.PIN)
         and whole["writer"]["sha256"] == source.writer.ACTIVE and not whole["preparation_only"]
         and whole["third_162_accounting"]["phase"] == "terminal" and whole["adjacent_169_accounting"]["phase"] == "held",
         "changed 169 grant or base census")
    peer = runpy.run_path(str(RT/"epoch169-hourly-admission-20261123-v1/issued-split-v1/peer162.py"))
    previous = whole["base_169"]["native"]["third_162_before"]
    custody = fourth["custody"](peer,previous)
    need(info["previous"] == custody["terminal"] and info["bootstrap"]["verified_local_custody"]["sha256"] ==
         "31a86562dc3a724cc3e2ad712b382f547663ef73af2cd6839b8685bce8973154", "input custody changed")
    # Recover V34 immediately before its joint-floor minimum. Charging new
    # HOME to a previously floor-limited margin counts the same control twice.
    earlier_margin = min(whole["epoch143_pre_floor_home_margin"],
                         whole["available_home"]-whole["epoch143_installed_guard_floor"],
                         whole["available_home"]-whole["epoch170_installed_guard_floor"])
    earlier_margin -= whole["third_162_accounting"]["additional_home"] + whole["adjacent_169_accounting"]["additional_home"]
    need(whole["after_ram170_accounting"]["home_increment"] == 0 and whole["fits"]
         and min(earlier_margin,whole["available_home"]-whole["epoch143_protected_runway_required_home"],
                 whole["available_home"]-whole["adjacent169_joint_guard_requirement"]) == whole["home_margin"],
         "existing V34 margin did not reproduce")
    whole["home_margin"] = earlier_margin
    row = dict(enrolled=False,phase="precharged",owner=None,remaining=3*G,floor=0,resident=0,enrollment=None,custody=custody)
    whole["fourth162_producer_residency"] = dict(realized_bytes=0)
    fourth["reserve"](whole,row,row,True)
    # V34 already accounted for the actual 169 held floor. Reapply its native
    # guard-floor algebra to the updated commitment before computing both joint runways.
    protected = max(9_470_567_509_909,whole["required_home"]-whole["epoch143_remaining_replay_home"],
                    *whole["observed_sibling_guard_floors"])
    required = max(whole["required_home"],protected+whole["epoch143_remaining_replay_home"])
    whole.update(epoch143_protected_sibling_floor=protected,epoch143_protected_runway_required_home=required,
                 home_margin=min(whole["home_margin"],whole["available_home"]-required),
                 fits=whole["fits"] and whole["available_home"]>required)
    fourth["protect_live"](whole)
    adjacent["protect"](whole)
    history = bind(price["HISTORY"])
    result = price["geometry"](whole,"prestart",None,whole["available_home"],whole["available_ram"],
                               history["worst_observed_90s_free_byte_decrease"],proposal=True)
    return dict(schema="horizon-162-fourth-frozen-placement-v1",source_revision=revision,price=POST,grant=reference(HELD/"GRANT.json"),
                interface=interface,scope=info["scope"],previous=custody["terminal"],bootstrap=info["bootstrap"]["verified_local_custody"],
                terminal_bank=info["terminal"]["terminal_witness"],native=info["guard_validation"],writer=whole["writer"],
                observed_unix=whole["recorded_unix_seconds"],fleet=whole["fleet"],retained_169=whole["adjacent_169_accounting"],
                prior_162=whole["third_162_accounting"],assembly_167=whole["epoch167_private_assembly"],permanent_resource_credit=0,
                added_home=whole["fourth_162_accounting"]["additional_home"],scratch_tmpfs=36*G,
                producer_memory=62*G,guard_memory=G,producer_cpu_micros=2_000_000,guard_cpu_micros=1_000_000,
                available_home=whole["available_home"],available_ram=whole["available_ram"],geometry=result,
                fresh_admission=False,production_started=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("revision")
    args = parser.parse_args()
    proposal = project(args.revision)
    layout = runpy.run_path(str(BASE/"operator-v1/layout.py"))
    output = layout["save"](BASE/("FOURTH_FROZEN_PLACEMENT_"+args.revision[:12]+".json"),proposal,0o400)
    print(json.dumps(dict(receipt=output,**proposal["geometry"]),sort_keys=True))
