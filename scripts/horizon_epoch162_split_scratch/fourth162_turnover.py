"""Price the fourth 162 interval against the closed 170 tree and every still-active runway."""
import argparse
import json
import os
from pathlib import Path
import stat
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent/"horizon_epoch170_checkpoint_suffix"))
import compact_fourth162 as compact
import next_hourly170 as hourly
from fourth_interval import BASE, bind, need, reference

GIB = compact.GIB
INTERFACE = dict(path=str(compact.INTERFACE), sha256="d0aeddbde2ebef0a6a015dfd06e8917c0842cd7701f1b559fdb3887acd88d396")
CUSTODY = dict(path=str(hourly.PREVIOUS/"HOURLY_TERMINAL_AND_CUSTODY.json"),
               sha256="ffd8fc3648ccfd504ab178105e23acf199df498dcbfaec1cb19629e6c1cc54cb")
DRAIN = dict(path=str(hourly.PREVIOUS/"HOURLY_GUARD_DRAIN.json"),
             sha256="187575fd8bdb6ede879bac02e0739e659c6fcbc341a917ca24c83713d435186c")
DRAW = 20_011_974_656


def retained_tree(scope, archive):
    root = Path(scope["run"])
    archived = Path(archive["path"])
    need(root.resolve(strict=True) == root and archived.parent == root/"ledger", "different closed tree")
    def census():
        rows = []
        for path in [root, *sorted(root.rglob("*"))]:
            s = path.lstat()
            need(s.st_dev == root.stat().st_dev and (stat.S_ISDIR(s.st_mode) or stat.S_ISREG(s.st_mode) and s.st_nlink == 1),
                 "foreign retained inode " + str(path))
            rows.append((str(path.relative_to(root)), s.st_dev, s.st_ino, s.st_size, s.st_blocks*512, s.st_mtime_ns, s.st_ctime_ns))
        return rows
    before = census()
    need(before == census(), "closed 170 tree changed during allocation census")
    physical = sum(row[4] for row in before)
    need(0 < archive["identity"][2] <= physical <= scope["profile"]["new_home_total_bytes"], "unexpected closed tree size")
    return dict(rows=before, physical_bytes=physical, archive=archive)


def closure(whole, next_scope):
    custody, drain = bind(CUSTODY), bind(DRAIN)
    row = whole["after_floor170_accounting"]
    owner = row["actor"]
    release = bind(custody["bindings"]["release"])
    need(row["replacement_selected"] and not row["prospective"] and row["additional_inputs"] == 0
         and owner["phase"] == "terminal" and owner["invocation"] == custody["bindings"]["invocation"] == hourly.OLD_IID
         and owner["actor"] == custody["bindings"]["actor"] and owner["interface"] == row["scope"] == hourly.OLD_SCOPE
         and owner["release"] == custody["bindings"]["release"] == drain["release"]
         and drain["custody"] == CUSTODY and drain["bindings"] == custody["bindings"] and drain["intent"]
         and drain["guard_plan"] == owner["guard_plan"] == release["guard_plan"]
         and drain["timer_id"] == release["guard_timer_invocation_id"] and drain["producer_drained"] and drain["guard_drained"]
         and drain["scratch_released"] and drain["scratch"]["host_directory_empty"] and not drain["scratch"]["original_mount_present"]
         and not any(a["epoch"] == 170 for a in whole["base_169"]["observed_actors"])
         and not custody["archive_publication_authorized"] and not drain["resource_credit_bytes"],
         "different closed 170 owner, retained archive or guard drain")
    comparison = bind(custody["comparison"])
    point = hourly.predecessor(custody["comparison"], next_scope["endpoints"][0])
    need(point["slot"] == 73_773_645 and comparison["checkpoints"][-1] == custody["actual_terminal"]
         and comparison["evidence"]["closed_segment"] == custody["archive"] and owner["native_terminal"] == custody["native_producer"]["producer"],
         "archive or signed terminal changed")
    return retained_tree(bind(hourly.OLD_SCOPE), custody["archive"])


def scenario(whole, price, available, retained, next_output, next_ingress, next_control):
    old_cap = whole["after_floor170_accounting"]["home_growth"]
    need(old_cap == 8*GIB and 0 < retained <= old_cap and next_output in (0, old_cap)
         and min(next_ingress, next_control) >= 0, "unrecognized turnover geometry")
    # Keep the *entire* closed tree charged against shared capacity. No physical
    # free-space credit is taken for its archive, its scratch, or its guard.
    shared = whole["required_home"] - (old_cap-retained) + next_output + next_control + next_ingress
    installed = max(whole["epoch143_installed_guard_floor"], *whole["observed_sibling_guard_floors"])
    runway143, runway169, fourth = (price[k] for k in ("protected_143_runway","protected_169_runway","remaining"))
    need(price["minimum_fair_floor"] == installed == whole["adjacent_169_accounting"]["observed_floor"]
         and whole["fourth_162_accounting"]["additional_home"] == fourth + (64 << 20)
         and whole["epoch167_private_assembly"]["phase"] in ("booked","assembly")
         and whole["fourth_162_accounting"]["charged"] and whole["adjacent_169_accounting"]["charged"]
         and runway143 == whole["epoch143_remaining_replay_home"] and runway169 == whole["adjacent_169_accounting"]["remaining_output"],
         "different active siblings or shared 162 and 167 allocations")
    growth = runway143 + runway169 + fourth + next_output
    # Separate staging/controls, when unfunded, can be written concurrently too.
    concurrent = growth + next_control + next_ingress
    protected143 = max(shared, installed + runway143)
    required = max(shared, protected143, installed + concurrent)
    margin = available - required - DRAW
    return dict(shared_commitment=shared, protected_143_commitment=protected143, installed_floor=installed,
                protected_143_runway=runway143, protected_169_runway=runway169, fourth_output=fourth,
                closed_170_physical_retained=retained, closed_170_future_growth=0, successor_output=next_output,
                successor_ingress=next_ingress, successor_controls=next_control, required_home=required,
                joint_home_margin_upper_bound=margin, additional_home_required_at_least=max(0,-margin))


def project(proposal, version):
    source = Path(hourly.__file__).resolve()
    compact.published(version, [Path(__file__).resolve(), source, source.parent/"following_prepare.py",
                               HERE/"compact_fourth162.py", HERE/"fourth162_writer.py", HERE/"fourth_interval.py"])
    record = bind(proposal)
    full, price = record["whole_roster"], record["geometry"]
    info = bind(INTERFACE)
    scope = bind(info["scope"])
    old = bind(compact.REFUSAL)
    need(record["interface"] == info["full_size_interface"] and record["terminal"] == info["terminal"]
         and record["bootstrap"] == info["bootstrap"] and scope["kernel_qualification"] == info["kernel_qualification"]
         and full["package"] == old["whole_roster"]["package"] and full["writer"] == old["writer"]
         and full["fourth_162_predecessor"] == info["previous"] and not record["enrollment_issued"]
         and not record["production_started"] and not full["resource_credit_bytes"] and price["startup_drawdown_bytes"] == DRAW,
         "foreign proposal, rollout, custody or startup allowance")
    latest = hourly.source()
    retained = closure(full, latest)
    available = min(record["available_home"],full["available_home"])
    required = price["required_home"]
    need(available - required - DRAW == price["home_margin"] and required == full["adjacent169_joint_guard_requirement"]
         and price["protected_170_runway"] == latest["home_tree_cap"] == 8*GIB and not price["prestart_armed_cushion"],
         "different limiting guard or an existing fourth owner")
    block = Path(BASE).stat().st_dev
    need(Path(retained["archive"]["path"]).stat().st_dev == block and Path("/home/sol").stat().st_dev == block,
         "snapshots and retained archive do not share the priced HOME filesystem")
    frag = os.statvfs(BASE).f_frsize
    length = latest["endpoints"][0]["length"]
    ingress = (length+frag-1)//frag*frag
    variants = {}
    for name, output, staging, controls in (
        ("old_closed_new_170_unbooked", 0, 0, 0),
        ("successor_output_only_existing_input_and_controls", latest["home_tree_cap"], 0, 0),
        ("successor_with_unfunded_input_and_controls", latest["home_tree_cap"], ingress, latest["control_home"]),
    ):
        variants[name] = scenario(full,price,available,retained["physical_bytes"],output,staging,controls)
    return dict(schema="horizon-162-fourth-closed-170-turnover-proposal-v1", source_commit=version,
                native_proposal=proposal, original_refusal=compact.REFUSAL, qualified_fourth=INTERFACE,
                native_fleet=full["fleet"], writer=full["writer"], provider=full["package"], terminal_170=CUSTODY,
                drained_170=DRAIN, retained_170=retained, assembly_167=full["epoch167_private_assembly"],
                future_170_source=latest, available_home=available, actual_v35=price, startup_drawdown=DRAW,
                actual_donor_ram_margin=price["ram_margin"], potential_scoped_donor_partition=8*GIB,
                ram_margin_if_partitioned=price["ram_margin"]+8*GIB, scenarios=variants,
                applies_resource_credit=False, qualifies_positive_admission=False, production_started=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_commit")
    parser.add_argument("proposal_path")
    parser.add_argument("proposal_sha256")
    args = parser.parse_args()
    ref = dict(path=args.proposal_path, sha256=args.proposal_sha256)
    result = project(ref, args.source_commit)
    old = compact.original()[2]
    receipt = old["save"](BASE/("FOURTH_54_DRAINED_170_PROJECTION_"+args.proposal_sha256[:12]+".json"),result,0o400)
    print(json.dumps(dict(receipt=receipt, margins={k:v["joint_home_margin_upper_bound"] for k,v in result["scenarios"].items()})))
