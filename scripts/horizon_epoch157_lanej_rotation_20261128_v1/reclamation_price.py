"""Price only epoch 157 reclamation against the closed, unassigned epoch 167 slot."""
import hashlib
import json
import os
from pathlib import Path
import stat

RT = Path("/var/lib/jetstreamer/horizon_runtime_data")
SOURCE = RT / "epoch167-assembly-20261127-v1/assembly-turnover-v1/SOURCE_TERMINAL.json"
SOURCE_HASH = "71141c7de11f90d96733a7dcdfc948369dc20ed97f6962e5fe355bc91e3ff34b"
REPORT_HASH = "6fa7b5a802ac3bc501af9b1f0cd6bc772f5e877d24bb76a7344324e6f9cffe55"
DRAIN = "84f37a4cb4886968c932b624b47a7863fde5b115eff2bbd11a4255f4c5f4bee9"
OLD143 = "4f736b6ca61ab274c7c643cc237520c59ad62508dddbf6f640f71f8aa2584fcc"
STOP170 = "b39a216895e15c4568468646d9054d78c6fbda47d04ac5cc352eeba065faabc6"
META = 16 << 20
PROFILES = {"build":(768 << 20, 500_000), "census":(512 << 20, 500_000),
            "fixture":(256 << 20, 250_000), "custody":(256 << 20, 250_000),
            "retire":(1 << 30, 1_000_000)}


def need(ok, message):
    if not ok:
        raise ValueError(message)


def verified(ref, pin=None):
    p = Path(ref["path"])
    m = p.lstat()
    need(p.resolve(strict=True) == p and stat.S_ISREG(m.st_mode) and m.st_nlink == 1
         and m.st_uid == m.st_gid == 0 and not m.st_mode & 0o022 and m.st_size < 32 << 20,
         "invalid scoped source " + str(p))
    data = p.read_bytes()
    need(ref["sha256"] == hashlib.sha256(data).hexdigest() and (pin is None or ref["sha256"] == pin)
         and m.st_ctime_ns == p.stat().st_ctime_ns, "scoped source changed " + str(p))
    return json.loads(data)


def project(whole, phase):
    need(phase in PROFILES and whole["preparation_only"] is False and whole["resource_credit_bytes"] == 0,
         "outside the 157 reclamation scope")
    ram, cpu = PROFILES[phase]
    shares = whole["closed_167_suballocations"]
    source = shares["phases"]["source_qualification"]
    witness = dict(path=str(SOURCE), sha256=SOURCE_HASH)
    record = verified(witness)
    report = verified(record["qualification"], REPORT_HASH)
    event = record["terminal"]
    need(record["private_only"] and report["source_epoch_last"] == 72_575_999 and not report["publication_authorized"]
         and source["phase"] == "terminal" and source["invocation"] == event["INVOCATION_ID"] == "ab8147b379d144a696b1d210127ea866"
         and source["unit"] == event["UNIT"] and source["manager_message"] == event["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448"
         and source["cursor"] == event["__CURSOR"] and shares["native_drain"]["sha256"] == DRAIN
         and shares["additional_ram"] == shares["additional_home"] == 0 and shares["retained_producer_ram"] == 42 << 30,
         "157 sublease lacks the exact drained 167 tail and source qualification")
    verified(shares["native_drain"], DRAIN)
    closed143 = whole["closed_143"]["second_retry_floor_terminal"]
    stop170 = whole["after_ram170_accounting"]["terminal_stop"]
    verified(closed143, OLD143)
    verified(stop170["stop_completion"], STOP170)
    need(stop170["reason"] == "filesystem-floor" and stop170["resource_credit_bytes"] == 0
         and whole["closed_143"]["resource_credit_bytes"] == 0
         and whole["epoch167_private_assembly"]["phase"] == "unbooked",
         "different incumbent or 167 assembly already booked")
    verified(whole["fleet"])
    verified(whole["writer"])
    unassigned = shares["unassigned"]
    need(unassigned["ram_bytes"] >= ram and unassigned["cpu_micros_per_second"] >= cpu
         and unassigned["home_bytes"] >= META, "the closed 167 slot cannot fund this 157 phase")
    available = whole["available_home"]
    previous = max(whole["required_home"], available - whole["home_margin"])
    installed = [whole["guard_floor"], *(v for k, v in whole.items() if k.endswith("_installed_guard_floor"))]
    floor = max(*installed, previous - unassigned["home_bytes"])
    live = os.statvfs("/home/sol")
    free = min(available, live.f_bavail * live.f_frsize)
    balance = free - floor - META
    return dict(schema="horizon-157-reclamation-scope-v1", phase=phase, home_bytes=META, ram_bytes=ram,
                cpu_micros=cpu, swap=0, fits=balance >= 0 and whole["ram_margin"] >= 0, floor=floor,
                home_margin=balance, ram_margin=whole["ram_margin"], available_home=free,
                ordinary_home_margin=whole["home_margin"], protected_installed_floors=installed,
                previously_unassigned=unassigned, closed_tail=shares["native_drain"], source_terminal=witness,
                closed143=closed143, stop170=stop170["stop_completion"], provider=whole["package"],
                fleet=whole["fleet"], writer=whole["writer"], resource_credit_bytes=0,
                planned_retirement_credit_bytes=0, general_admission=False, publication_authorized=False)
