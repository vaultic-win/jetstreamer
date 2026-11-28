"""Derive the next epoch 143 operator from its immutable V52 predecessor."""

import ast
import hashlib
import json
from pathlib import Path
import sys

from derive143_bootstrap_retry import ROOT, change, read_package
from reconcile_failed143_v52 import IID, BOOKING_SHA, ACTIVE_SHA

PREVIOUS = ROOT / "booking-price-v52"
TARGET = ROOT / "booking-price-v53"
PREVIOUS_SEAL = "fa9e315142bf57e2aca0bd456444caae5921655b47d12c71095cf20919b704d3"
PREVIOUS_ACTIVE = "7353e093feb5763907b9e76ac58fa35d8cf869af686dae85a0b91e58c8857c62"
V6_SEAL = "834e0502085a31dd0cc7a035eb96c7b00144d05d172fa4b1649633343dd34fa0"
V52_READY = "b900559f1d141ccbc4daa32e4625cedf7ff3e7e011c4f73496ba1898ae641d88"


def booker(data):
    data = data.replace("v52", "v53").replace("V52", "V53").replace("version = 52", "version = 53")
    data = change(data, "FAILED166_CADENCE_V51_ACTIVE.json", "FAILED166_CADENCE_V52_ACTIVE.json")
    data = change(data, PREVIOUS_ACTIVE, ACTIVE_SHA)
    return change(data, 'and ready["retained_143_phase"] == prior_ready["retained_143_phase"]',
                  'and prior["ready"]["sha256"] == "' + V52_READY + '"\n'
                  '                 and ready["retained_143_phase"] == prior_ready["retained_143_phase"]')


def preparer(data):
    data = data.replace("v52", "v53").replace("V52", "V53").replace("version = 52", "version = 53")
    marker = "    version = 53 if v53 is not None"
    return change(data, marker, f'''    if v53 is not None:
        failed, _ = core.read(funding.roll.ROOT / "failed-{IID}/RECONCILED.json")
        core.need(failed["failed_invocation"] == "{IID}" and failed["release_absent"]
                  and failed["expired_booking"]["sha256"] == "{BOOKING_SHA}"
                  and failed["resource_credit_bytes"] == 0,
                  "unreleased 143 attempt still needs reconciliation")
''' + marker)


def price(data, provider_seal):
    data = change(data, "import rollover143 as roll", "import rollover143 as roll\nfrom floor143 import quote_guard_floor")
    data = change(data, "issued-price-v6", "issued-price-v7")
    data = change(data, V6_SEAL, provider_seal)
    data = change(data, '    native162 = whole["existing_162"]', """    native162 = whole["existing_162"]
    gap = base["native"]["independent_gap170"]
    expected = {146, 162, 167, 172}
    if held:
        expected.add(143)
    if gap:
        expected.add(170)
        booking = core.bound(gap["release"])
        core.need(gap["unit"] == "horizon-qualify-170-from-73760367-20261128-v1.service"
                  and gap["phase"] in ("bootstrap", "worker")
                  and gap["invocation"] == actors[170]["invocation_id"]
                  and booking["interface"]["sha256"] == "3f375caf9273b81cb84c5908695c27c0e4dbc6406f5ab53ebc1e1611ddf2a69f"
                  and booking["actor"] == gap["actor"] and booking["guard_plan"] == gap["guard_plan"],
                  "epoch 170 differs from the independent guarded gap")
    core.need(base["native"]["independent_gap_funding"]["new_guard_cpu_micros"] == 1_000_000,
              "epoch 170 independent guard lost its reserved CPU")""")
    data = change(data, 'set(actors) == ({143, 146, 162, 167, 172} if held else {146, 162, 167, 172})',
                  'set(actors) == expected')
    data = change(data, "return raw, joint, replacement", "return raw, joint, replacement, gap")
    data = change(data, "raw, joint, own = criteria", "raw, joint, own, gap = criteria")
    data = change(data, 'phase170="stopped",', 'phase170=gap["phase"] if gap else "stopped",')
    start = data.index("    retained_home =")
    end = data.index("    return dict(schema=", start)
    data = data[:start] + '''    terms = quote_guard_floor(raw, joint,
                             [core.bound(ref)["minimum_free_bytes"] for ref in joint["guard_samples"].values()],
                             home, own)
    if core.current_fleet()[1] != fleet_ref:
        raise ValueError("accepted fleet changed while pricing epoch 143")
    home -= terms["additional_home_charge_bytes"]
    retained_home = whole["available_home"] - home - TREE - EVIDENCE
    retained_ram = whole["available_ram"] - ram - RAM
''' + data[end:]
    return change(data, "home_margin_bytes=home, ram_margin_bytes=ram, guard_floor_bytes=floor,\n"
                  "                disk_fits=not projection and home >= 0, memory_fits=not projection and ram >= 0,",
                  "home_margin_bytes=home, ram_margin_bytes=ram, **terms,\n"
                  "                disk_fits=not projection and home >= 0 and terms[\"guard_floor_fits\"],\n"
                  "                memory_fits=not projection and ram >= 0,")


def launcher(data):
    data = change(data, 'and (.held_invocation // "")==$iid',
                  'and .guard_floor_fits and (.guard_floor_bytes >= .required_guard_floor_bytes)\n'
                  '            and (.held_invocation // "")==$iid')
    data = change(data, "retained_required_home_bytes,available_home_bytes,retained_required_ram_bytes,",
                  "guard_floor_bytes,required_guard_floor_bytes,guard_floor_fits,\n"
                  "                retained_required_home_bytes,available_home_bytes,retained_required_ram_bytes,")
    return change(data, '''jq -e --argjson floor "$floor" '
    .guard_floor_bytes<=$floor
    and .available_home_bytes>=(([$floor,.retained_required_home_bytes]|max)+.candidate_home_bytes)' "$a/POST_GUARD_SCREEN.json" >/dev/null''',
                  '''if [[ $epoch == 143 ]]; then
    jq -e --argjson floor "$floor" --slurpfile pre "$a/PRESTART_SCREEN.json" '
        def gap: .whole_roster.base_169.native.independent_gap170 | {unit,invocation,actor,guard_plan,release};
        (. | gap)==($pre[0] | gap)
        and .guard_floor_bytes==$floor and .guard_floor_fits
        and .available_home_bytes>=(([$floor,.retained_required_home_bytes]|max)+.candidate_home_bytes)' "$a/POST_GUARD_SCREEN.json" >/dev/null
else
    jq -e --argjson floor "$floor" '
        .guard_floor_bytes<=$floor
        and .available_home_bytes>=(([$floor,.retained_required_home_bytes]|max)+.candidate_home_bytes)' "$a/POST_GUARD_SCREEN.json" >/dev/null
fi''')


def member_plan(files, work, destination):
    work.mkdir(mode=0o700)
    members = []
    for name, (data, mode) in files.items():
        if name.endswith(".py"):
            ast.parse(data, filename=name)
        path = work / name
        path.write_bytes(data)
        path.chmod(mode)
        members.append(dict(name=name, source=str(path), sha256=hashlib.sha256(data).hexdigest(), mode=mode))
    return dict(schema="jetstreamer-sealed-deployment-plan-v1", destination=str(destination), members=members)


def derive(work, revision, provider_seal):
    provider = ROOT.parent / "epoch162-first-hourly-completion-20261127-v2/issued-price-v7"
    read_package(provider, provider_seal)
    files = read_package(PREVIOUS, PREVIOUS_SEAL)
    for name, transform in (("book141.py", booker), ("prepare143.py", preparer), ("price_hourly143.py", lambda data: price(data, provider_seal)),
                            ("launch-first-hourly143.sh", launcher)):
        data, mode = files[name]
        files[name] = (transform(data.decode()).encode(), mode)
    source = Path(__file__).resolve().parent
    files["floor143.py"] = ((source / "floor143.py").read_bytes(), 0o444)
    files["DERIVATION.json"] = ((json.dumps(dict(
        branch="account-updates", revision=revision,
        predecessor=dict(path=str(PREVIOUS / "deployment-seal-receipt.json"), sha256=PREVIOUS_SEAL),
        stopped_roster_provider_sha256=provider_seal, failed_booking_sha256=BOOKING_SHA), indent=2) + "\n").encode(), 0o444)
    return member_plan(files, work, TARGET)


if __name__ == "__main__":
    print(json.dumps(derive(Path(sys.argv[1]), sys.argv[2], sys.argv[3]), indent=2))
