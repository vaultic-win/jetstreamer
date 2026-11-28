"""Price the third private 162 interval on the complete roster and both adjacent Bank checkpoints."""
import hashlib
import os
from pathlib import Path
import re
import runpy
import stat
import time

G = 1 << 30
CONTROL = 64 << 20
OUTPUT = 3*G
RT = Path("/var/lib/jetstreamer/horizon_runtime_data")
PROVIDERS = RT/"epoch162-first-hourly-completion-20261127-v2"
ROOT = RT/"epoch162-third-replay-20261128-v1"
HISTORY = dict(path=str(RT/"epoch166-closed-compact-indexes-20261128-v1/SHARED_HOME_DRAWDOWN_0400_053730.json"),
               sha256="cb92e5a9b96960d0e2a98a7f2d9ce75d5ad221b84c4549955eea4ce05a0b87ab")
MEASURED = 20_011_974_656


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def latest_provider():
    choices = [(int(p.name.removeprefix("issued-price-v")),p) for p in PROVIDERS.glob("issued-price-v*")
               if re.fullmatch(r"issued-price-v[1-9][0-9]*",p.name) and (p/"deployment-seal-receipt.json").is_file()]
    return max(choices)[1]


def provider(layout, spec):
    directory = Path(__file__).resolve().parent
    seal = spec["whole_roster"]
    need(directory == latest_provider() and seal["path"] == str(directory/"deployment-seal-receipt.json")
         and spec["capacity"]["path"] == str(directory/"third162_price.py"), "superseded or unregistered shared price")
    receipt = layout["bound"](seal)
    manifest = {m["name"]:m for m in receipt["members"]}
    need(receipt["destination"] == str(directory) and len(manifest) == len(receipt["members"])
         and {"third162_price.py","third162_peer.py","capacity.py","after_floor170_price.py","reclamation_price.py"} <= manifest.keys(),
         "incomplete shared price package")
    for name, member in manifest.items():
        path = directory/name
        s = path.lstat()
        need(path.parent == directory and path.resolve(strict=True) == path and stat.S_ISREG(s.st_mode)
             and s.st_uid == 0 and not s.st_mode & 0o222 and s.st_nlink == 1 and s.st_size == member["bytes"]
             and hashlib.sha256(path.read_bytes()).hexdigest() == member["sha256"], "changed common price member " + name)
    need(spec["capacity"]["sha256"] == manifest["third162_price.py"]["sha256"], "changed lane price")
    return runpy.run_path(str(directory/"capacity.py"))


def geometry(whole, phase, held, free, available_ram, drawdown):
    need(drawdown == MEASURED and phase in ("prestart","postguard"), "different startup drawdown or phase")
    accounting = whole["third_162_accounting"]
    remaining = accounting["remaining_output"]
    installed = accounting["observed_floor"]
    need(0 <= remaining <= OUTPUT and accounting["additional_home"] == remaining+CONTROL
         and accounting["charged"] and accounting["writer_enrolled"] and not accounting["additional_ram"]
         and not accounting["resident_credit"] and not whole["resource_credit_bytes"], "third image or loan not charged exactly once")
    if phase == "prestart":
        need(held is None and accounting["phase"] == "precharged" and not accounting["owner"] and installed == 0
             and remaining == OUTPUT, "third prestart already has an owner")
    else:
        owner = accounting["owner"]
        need(accounting["enrollment"] and accounting["phase"] == "held" and owner["invocation_id"] == held
             and owner["phase"] == "held" and installed > 0 and not owner["release"], "different held third producer")
    runway143 = whole["epoch143_remaining_replay_home"]
    raw = whole["base_169"]["native"]["raw"]
    after170 = whole["after_floor170_accounting"]
    paid170 = whole["after_ram170_accounting"]
    selected = after170["replacement_selected"]
    runway170 = after170["home_growth"] if selected else paid170["home_growth_bytes"]
    need(0 <= runway143 <= 64*G and runway143 == raw["guarded_hourly_remaining"]
         and paid170["phase"] == "booked" and runway170 == (8*G if selected else 36*G)
         and (not selected or after170["intent"] and paid170["superseded_by"] == after170["scope"])
         and whole["epoch143_protected_runway_required_home"] == max(whole["required_home"],
             whole["epoch143_protected_sibling_floor"]+runway143), "different 143 or 170 replacement booking")
    # The shared required_home pays all three working sets. Let each peer spend
    # its booked bytes while this producer is held or replaying. Its guard
    # must also respect the actual armed floor of every live sibling.
    growth = runway143+runway170+remaining
    shared = whole["required_home"]
    fair = max(raw["guard_floor"],whole["guard_floor"]-runway143-runway170,
               shared-growth,whole["epoch143_protected_sibling_floor"]-runway170-remaining,
               whole.get("epoch143_installed_guard_floor") or 0,*whole["observed_sibling_guard_floors"])
    free = min(free,whole["available_home"])
    # Bound the prestart tolerance by spare capacity after funding the full
    # simultaneous growth and retaining the measured startup drawdown.
    cushion = min(drawdown,max(0,free-growth-drawdown-fair)) if held is None else 0
    floor = max(installed,fair+cushion)
    required = max(shared,whole["epoch143_protected_runway_required_home"],floor+growth)
    margin = min(whole["home_margin"],free-required)-drawdown
    ram = min(available_ram,whole["available_ram"])-whole["required_ram"]
    return dict(guard_floor=floor,minimum_fair_floor=fair,required_home=required,remaining=remaining,
                home_margin=margin,ram_margin=ram,required_ram=whole["required_ram"],protected_143_runway=runway143,
                protected_170_runway=runway170,prestart_armed_cushion=cushion,startup_drawdown_bytes=drawdown,
                drawdown_evidence=HISTORY,fits=bool(whole["fits"] and min(margin,ram)>=0
                                                   and (held is None or floor == installed)))


def quote(phase, held_invocation, profile, enrollment):
    layout = runpy.run_path(str(ROOT/"operator-v1/layout.py"))
    spec = layout["bound"](enrollment)
    module = provider(layout,spec)
    scope = layout["scope"]()
    info = layout["bound"](spec["interface"])
    need(os.geteuid() == 0 and __debug__ and info["provider"] == spec["operator"]
         and spec["second_terminal"] == info["previous"] == scope["previous"]
         and spec["donor"] == dict(path=str(layout["DONOR"]),sha256=layout["DONOR_SHA"])
         and profile == layout["profile"](36), "foreign scope, donor or profile")
    whole = module["complete_roster"](False,third162=phase=="prestart")
    need(whole["package"] == spec["whole_roster"] and whole["writer"] == spec["writer_active"]
         and whole["donor"] == spec["donor"] and whole["third_162_predecessor"] == scope["previous"]
         and layout["bound"](whole["fleet"])["owner"] == "/root" and not whole["preparation_only"],
         "different whole fleet, writer, predecessor or loan")
    if phase == "postguard":
        actor,ref = layout["pinned"](layout["DATA"]/"HELD_OWNER.json")
        need(whole["third_162_accounting"]["owner"]["actor"] == ref and actor["producer_invocation_id"] == held_invocation
             and layout["manager"](layout["UNIT"])["InvocationID"] == held_invocation
             and actor["mounts"]["image"] == layout["identity"](layout["IMAGE"])[:3], "unbound third held image or owner")
    else:
        need(not os.path.lexists(layout["IMAGE"]), "third prestart found an existing image")
    former = module["report169"](whole["base_169"]["actor"])
    need(former == dict(phase="terminal",invocation_id="b01da82c3091478f920ddcc71f4d9191"), "unregistered original 169 terminal")
    history = layout["bound"](HISTORY)
    need(history["worst_stop_unix"]-history["worst_start_unix"] == 83, "changed startup history")
    disk = os.statvfs(ROOT)
    free = disk.f_bavail*disk.f_frsize
    ram = next(int(s.split()[1])*1024 for s in Path("/proc/meminfo").read_text().splitlines() if s.startswith("MemAvailable:"))
    result = geometry(whole,phase,held_invocation,free,ram,history["worst_observed_90s_free_byte_decrease"])
    return dict(schema="horizon-162-split-fleet-price-v1",phase=phase,unit=layout["UNIT"],scratch_gib=36,
                profile=profile,held_invocation=held_invocation,donor=whole["donor"],enrollment=enrollment,
                exclusive_166_lease=True,peers={"169":former},boot_id=layout["BOOT"].read_text().strip(),
                fleet=whole["fleet"],writer=whole["writer"],third_162_predecessor=scope["previous"],whole_roster=whole,
                available_ram=ram,current_free_home=free,resource_credit_bytes=0,recorded_unix=time.time(),**result)
