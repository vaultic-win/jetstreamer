"""Price the next 162 image with both successors booked and its first image in custody."""
import json
import os
from pathlib import Path
import runpy
import time

HERE=Path(__file__).resolve().parent
RT=Path("/var/lib/jetstreamer/horizon_runtime_data")
BASE=RT/"epoch162-second-replay-20261128-v1"
FIRST=RT/"epoch162-first-hourly-completion-20261127-v2"
ROOT169=RT/"epoch169-hourly-retry-20261128-v2"
ROOT170=RT/"epoch170-from-73760367-ram-20261128-v1"
G=1<<30
M=1<<20
EXPECTED="445b05009592b381506701162673494fe3d6deb3851a33adade0f4e44d6a64ad"


def geometry(native, retained, observed_home, available_ram, floor170, held_floor, remaining, control):
    # The sealed provider keeps the first segment's *whole* 8 GiB future disk
    # allowance on terminal. Keep it intact and debit this image independently.
    # In RAM a second producer replaces the drained first in its existing booking.
    required_ram=max(native["required_ram"],retained["whole_roster"]["required_ram"])
    floor=max(native["required_home"]+control,retained["whole_roster"]["required_home"]+control,
              retained["armed_floor"],floor170,held_floor)
    free=min(native["available_home"],observed_home)
    return dict(guard_floor=floor,required_home=floor+remaining,remaining=remaining,
                home_margin=free-floor-remaining,required_ram=required_ram,
                ram_margin=min(native["available_ram"],available_ram)-required_ram)


def quote(phase,held_invocation,profile,enrollment):
    l=runpy.run_path(str(HERE/"layout.py"))
    need=l["need"]
    need(HERE==BASE/"issued-split-v1" and os.geteuid()==0 and __debug__, "use the sealed second price")
    scope=l["scope"]()
    first=l["bound"](scope["previous"])
    need(scope["previous"]["sha256"]==EXPECTED and first["manager_drain"]["MainPID"]=="0" and first["source_files_preserved"]
         and scope["first_slot"]==69991077 and scope["last_slot"]==69998119, "changed predecessor")
    l["bound"](first["typed_manifest"])
    spec=l["bound"](enrollment)
    joint=l["bound"](spec["whole_roster"])
    owner=Path(joint["destination"])
    need(owner.parent==FIRST and owner.name.startswith("issued-price-v") and owner/"deployment-seal-receipt.json"==Path(spec["whole_roster"]["path"]), "foreign roster")
    for m in joint["members"]:
        need(l["digest"](owner/m["name"])==m["sha256"], "changed provider module")
    native=runpy.run_path(str(owner/"capacity.py"))["whole_roster"]()
    need(native["package"]==spec["whole_roster"] and not native["resource_credit_bytes"] and native["writer"]==spec["writer_active"],
         "writer or joint price changed")
    old=native["existing_162"]
    need(old["phase"]=="terminal" and old["invocation_id"]=="e08ac6700a714ea0bf2d08a40516fc7e"
         and old["realized_ram"]==0 and old["profile"]["combined_ram"]==profile["combined_ram"]==63*G
         and old["profile"]["home_image"]==8*G and profile==l["profile"](36) and profile["home_image"]==3*G,
         "missing first/second booking")
    registered=l["bound"](native["fleet"])
    need(registered["owner"]=="/root" and not registered["resource_credit_bytes"], "wrong host controller")
    proof=l["pinned"](ROOT169/"POST_GUARD_PRICE.json","3da3dd28855bfb5123fc5e319a3cca900c3619591fa067a42397da8f4d247e71")[0]
    prior=l["pinned"](ROOT169/"WORKER_ALIAS_STOP.json","c09b0bf82efe4c970a0810219bdccb03a1869333a30cd1fef39e9034dfc40e02")[0]
    l["bound"](prior["terminal"])
    release=l["pinned"](ROOT170/"SUCCESSOR_AUTHORIZED_RELEASE.json","053709a78f1be1b5d8e5f985e7822e7a0a7971eabd2ae0c5ceaae4f8a6e46c3d")[0]
    floor170=l["bound"](release["guard_plan"])["minimum_free_bytes"]
    # V10 and later carry a priced, possibly changed successor rather than
    # relying on the old snapshot's resident RAM credits.
    base=native["base_169"];n=base["native"]
    need(base["accounting"]["old_six_owner_lineage"]["static_169_memory"]==69*G
         and n["planned_169_retry"]["additional_ram"]>=8*G and n["planned_169_retry"]["original_169_guard_retained"]
         and n["ram_retry_cost"]["producer_memory_max"]>=56*G and n["ram_retry_cost"]["original_guard_still_budgeted"]
         and base["accounting"]["verification168_listener"]["scanner_ram_from_serial"]==2*G,
         "169, 170 or private scan reservoir missing")
    l["bound"](scope["preparation"])
    peer=n.get("independent_retry169")
    peer_phase="precharged" if peer is None else peer["phase"]
    need(peer_phase in ("precharged","held","bootstrap","worker","terminal"),"different 169 phase")
    remain=profile["home_image"]
    held_floor=0
    if phase=="postguard":
        actor,_=l["pinned"](l["DATA"]/"HELD_OWNER.json")
        need(actor["producer_invocation_id"]==held_invocation and l["manager"](l["UNIT"])["InvocationID"]==held_invocation, "different held second invocation")
        held_floor=l["bound"](actor["guard_plan"])["minimum_free_bytes"]
        need(actor["mounts"]["image"]==l["identity"](l["IMAGE"])[:3], "different charged output")
    else:
        need(phase=="prestart" and held_invocation is None and not l["IMAGE"].exists(), "second prestart occupied")
    available=next(int(v.split()[1])*1024 for v in Path("/proc/meminfo").read_text().splitlines() if v.startswith("MemAvailable:"))
    disk=os.statvfs(BASE)
    amounts=geometry(native,proof,disk.f_frsize*disk.f_bavail,available,floor170,held_floor,remain,profile["control"])
    return dict(schema="horizon-162-split-fleet-price-v1",phase=phase,unit=l["UNIT"],scratch_gib=36,profile=profile,
                held_invocation=held_invocation,donor=native["donor"],enrollment=enrollment,exclusive_166_lease=True,
                peers={"169":{"phase":peer_phase}},boot_id=l["BOOT"].read_text().strip(),fleet=native["fleet"],writer=native["writer"],
                second_162_predecessor=scope["previous"],whole_roster=native,second_169_prior=prior["terminal"],guard170=release["guard_plan"],
                available_ram=available,current_free_home=disk.f_bavail*disk.f_frsize,resource_credit_bytes=0,
                recorded_unix=time.time(),fits=amounts["home_margin"]>=0 and amounts["ram_margin"]>=0,**amounts)
