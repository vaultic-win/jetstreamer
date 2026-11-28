"""Apply the complete roster and the qualified epoch 169 startup policy to one adjacent span."""
import os
from pathlib import Path
import re
import runpy
import stat
import time

G = 1 << 30
CONTROL = 64 << 20
OUTPUT = 4*G
RT = Path("/var/lib/jetstreamer/horizon_runtime_data")
ROOT = RT/"epoch169-from-73245218-20261128-v1"
PROVIDERS = RT/"epoch162-first-hourly-completion-20261127-v2"
STARTUP = dict(path=str(RT/"epoch169-hourly-retry-20261128-v4/STARTUP_FLOOR_FIXTURE.json"),
               sha256="0a84fa894a382dc6a67c2544462b9fbeda237a52e0531b144e21891d049e1d32")


def need(ok, why):
    if not ok:
        raise ValueError(why)


def latest():
    return max((int(p.name.removeprefix("issued-price-v")),p) for p in PROVIDERS.glob("issued-price-v*")
               if re.fullmatch(r"issued-price-v[1-9][0-9]*",p.name) and (p/"deployment-seal-receipt.json").is_file())[1]


def provider(layout,spec):
    path=Path(__file__).resolve()
    directory=path.parent
    need(directory == latest() and spec["whole_roster"]["path"] == str(directory/"deployment-seal-receipt.json")
         and spec["capacity"] == dict(path=str(path),sha256=layout["digest"](path)),"foreign or superseded 169 price provider")
    record=layout["bound"](spec["whole_roster"])
    names={r["name"] for r in record["members"]}
    need(record["destination"] == str(directory) and len(names)==len(record["members"]) and
         {"capacity.py","adjacent169_peer.py","adjacent169_price.py","third162_peer.py","reclamation_price.py","after_floor170_price.py"}
         <= names, "incomplete shared price")
    for m in record["members"]:
        file=directory/m["name"]
        s=file.lstat()
        need(file.parent == directory and file.resolve(strict=True) == file and stat.S_ISREG(s.st_mode)
             and s.st_uid==0 and s.st_nlink==1 and not s.st_mode & 0o222 and s.st_size == m["bytes"]
             and layout["digest"](file)==m["sha256"], "changed shared member "+m["name"])
    return runpy.run_path(str(directory/"capacity.py"))


def startup(checked):
    # Both pairs were recorded across a held-gate transition on this epoch.
    cases=checked(STARTUP)
    need(set(cases)=={"available_home_fell","protected_floor_rose"},"unexpected 169 qualification samples")
    for case in cases.values():
        before=checked(case["prestart"])
        after=checked(case["postguard"])
        armed=before["guard_floor"]+max(0,before["home_margin"])//3
        need(armed==case["armed_floor"]>=after["guard_floor"]==case["measured_protected"] and
             case["remaining_after_full_output"]==after["whole_roster"]["available_home"]-armed-OUTPUT>=0,
             "changed 169 prestart or held floor qualification")


def geometry(whole,phase,iid,free,available_ram):
    need(phase in ("prestart","postguard"),"unknown 169 startup phase")
    lane=whole["adjacent_169_accounting"]
    remaining=lane["remaining_output"]
    installed=lane["observed_floor"]
    need(lane["charged"] and lane["writer_enrolled"] and lane["additional_home"]==remaining+CONTROL
         and not lane["additional_ram"] and not lane["additional_cpu"] and not lane["resident_bytes"]
         and not whole["resource_credit_bytes"] and 0 <= remaining <= OUTPUT,"wrong image or borrowed compute")
    if phase=="prestart":
        need(iid is None and lane["owner"] is None and lane["phase"]=="precharged" and installed==0 and remaining==OUTPUT,
             "169 already occupied")
    else:
        held=lane["owner"]
        need(lane["enrollment"] and held and held["phase"]==lane["phase"]=="held" and held["invocation_id"]==iid
             and installed>0 and not held["release"],"different 169 held gate")
    native=whole["base_169"]["native"]
    raw=native["raw"]
    third=whole["third_162_accounting"]
    run162=third["remaining_output"] if third["charged"] and third["phase"]!="terminal" else 0
    after=whole["after_floor170_accounting"]
    run170=after["home_growth"] if after["replacement_selected"] else whole["after_ram170_accounting"]["home_growth_bytes"]
    run143=whole["epoch143_remaining_replay_home"]
    dormant=whole.get("epoch143_dormant_tree")
    need(0<=run162<=3*G and 0<=run143<=64*G and run170 in (8*G,36*G)
         and (run143==raw["guarded_hourly_remaining"] or dormant and not raw["replacement143"]
              and run143+dormant["physical_bytes"]==raw["guarded_hourly_remaining"])
         and whole["epoch143_protected_runway_required_home"] == max(whole["required_home"],whole["epoch143_protected_sibling_floor"]+run143),
         "different 143/162/170 protected runway")
    growth=run143+run162+run170+remaining
    shared=whole["required_home"]
    fair=max(9_605_558_988_436,raw["guard_floor"],whole["guard_floor"]-run143-run162-run170,
             shared-growth,whole["epoch143_protected_sibling_floor"]-run162-run170-remaining,
             whole.get("epoch143_installed_guard_floor") or 0,*whole["observed_sibling_guard_floors"])
    free=min(free,whole["available_home"])
    mandatory=max(shared,whole["epoch143_protected_runway_required_home"],whole.get("third162_joint_guard_requirement",0),
                  whole.get("adjacent169_joint_guard_requirement",0),fair+growth)
    # Arm the historical one-third cushion only out of currently uncommitted
    # runway. The held gate must cover the new price with that same armed floor.
    slack=min(whole["home_margin"],free-mandatory)
    cushion=max(0,slack)//3 if phase=="prestart" else 0
    floor=max(installed,fair+cushion)
    required=max(mandatory,floor+growth)
    home=min(whole["home_margin"],free-required)
    ram=min(available_ram,whole["available_ram"])-whole["required_ram"]
    return dict(guard_floor=floor,required_home=required,required_ram=whole["required_ram"],home_margin=home,ram_margin=ram,
                protected_143_remaining=run143,protected_162_remaining=run162,protected_170_remaining=run170,
                charged_169_remaining=remaining,minimum_fair_floor=fair,startup_floor_fixture=STARTUP,unarmed_home_margin=slack,
                prestart_guard_cushion=cushion,fits=bool(whole["fits"] and min(home,ram)>=0 and (iid is None or floor==installed)))


def quote(phase, held_invocation, profile, enrollment):
    layout=runpy.run_path(str(ROOT/"operator-v1/layout.py"))
    spec=layout["bound"](enrollment)
    engine=provider(layout,spec)
    model=layout["scope"]()
    info=layout["bound"](spec["interface"])
    donor=dict(path=str(layout["DONOR"]),sha256=layout["DONOR_SHA"])
    need(os.geteuid()==0 and __debug__ and spec["operator"]==info["provider"] and spec["donor"]==donor
         and model["previous"]==info["previous"]==spec["previous"] and profile==layout["profile"](44),
         "unexpected 169 source, scope or compute")
    whole=engine["complete_roster"](False,adjacent169=phase=="prestart")
    lane=whole["adjacent_169_accounting"]
    need(whole["package"]==spec["whole_roster"] and whole["writer"]==spec["writer_active"] and
         lane["predecessor"]==model["previous"] and layout["bound"](whole["fleet"])["owner"]=="/root"
         and not whole["preparation_only"],"different full-roster owner")
    if phase=="postguard":
        held,ref=layout["pinned"](layout["DATA"]/"HELD_OWNER.json")
        need(lane["owner"]["actor"]==ref and held["producer_invocation_id"]==held_invocation and
             layout["manager"](layout["UNIT"])["InvocationID"]==held_invocation and
             held["mounts"]["image"]==layout["identity"](layout["IMAGE"])[:3],"unregistered held image")
    else:
        need(not os.path.lexists(layout["IMAGE"]),"occupied 169 output")
    startup(layout["bound"])
    disk=os.statvfs(ROOT)
    free=disk.f_bavail*disk.f_frsize
    ram=next(int(line.split()[1])*1024 for line in Path("/proc/meminfo").read_text().splitlines() if line.startswith("MemAvailable:"))
    geom=geometry(whole,phase,held_invocation,free,ram)
    return dict(schema="horizon-169-adjacent-fleet-price-v1",phase=phase,unit=layout["UNIT"],scratch_gib=44,
                profile=profile,held_invocation=held_invocation,donor=donor,enrollment=enrollment,
                exclusive_169_lease=True,boot_id=layout["BOOT"].read_text().strip(),fleet=whole["fleet"],writer=whole["writer"],
                adjacent_169_predecessor=model["previous"],whole_roster=whole,available_ram=ram,current_free_home=free,
                recorded_unix=time.time(),resource_credit_bytes=0,**geom)
