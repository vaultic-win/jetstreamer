"""Fund one private closed reader from the drained hourly 170 producer's booking."""
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from following_prepare import need, read

GIB = 1 << 30
READER_RAM = 512 << 20
READER_CPU = 1_000_000
CONTROL = 2 << 20
UNIT = "horizon-qualify-170-from-73766969-ram-20261128-v1.service"
TIMER = UNIT.replace("-qualify-", "-guard-").replace(".service", ".timer")
IID = "732e022b564c49e5890c4cd3a86b8169"


def systemd(unit, *names):
    raw = subprocess.check_output(["/usr/bin/systemctl", "show", "--all", unit, "-p",
                                   ",".join(names)], text=True, timeout=15)
    result = dict(row.split("=", 1) for row in raw.splitlines())
    need(set(result) == set(names), "missing systemd evidence")
    return result


def project(whole, provider, terminal):
    base = whole["base_169"]
    native = base["native"]
    joint = native["raw"]["joint"]
    binding = terminal["bindings"]
    budget = whole["after_floor170_accounting"]
    prior = whole["after_ram170_accounting"]
    owner = budget["actor"]
    intent = read(budget["intent"])
    original = read(intent["price"])
    guard = read(owner["guard_plan"])
    release = read(binding["release"])
    need(whole["package"] == provider and whole["resource_credit_bytes"] == 0
         and whole["preparation_only"] is False and base["fleet"] == whole["fleet"]
         and base["writer"] == whole["writer"] and "closed_hourly170_reader" not in whole,
         "unsealed, preparatory or already adjusted shared quote")
    need(budget["replacement_selected"] and not budget["prospective"]
         and budget["scope"] == binding["scope"] == intent["interface"] == owner["interface"]
         and owner == native["after_floor170"]
         and owner["phase"] == "terminal" and owner["unit"] == intent["producer_unit"] == UNIT
         and owner["invocation"] == binding["invocation"] == guard["invocation_id"] == IID
         and owner["release"] == binding["release"] and owner["actor"] == binding["actor"]
         and owner["native_terminal"] == terminal["producer"]
         and not any(actor["epoch"] == 170 for actor in base["observed_actors"]),
         "different predecessor, live 170 actor or mismatched terminal")
    cost = native["ram_retry_cost"]
    need(prior["phase"] == "booked" and prior["superseded_by"] == budget["scope"]
         and prior["ram_delta"] == 0 and prior["producer_memory_max"] == joint["producer_allowance"] == 48 * GIB
         and original["phase"] == "start" and original["fits"]
         and original["producer_memory_max"] == cost["producer_memory_max"] == budget["producer_memory"] == 56 * GIB
         and cost["extra_ram"] == 8 * GIB and cost["original_guard_still_budgeted"]
         and cost["resident_ram_credit"] == budget["resident_credit"]
         == native["after_floor170_residency"]["realized_bytes"] == 0
         and cost["unrealized_producer_ram"] == 56 * GIB
         and original["guard_memory_max"] == prior["guard_memory_max"] == budget["guard_memory"]
         == joint["guard_sibling_allowance"] == GIB
         and joint["producer_quota_micros"] == 6_000_000
         and release["guard_plan"] == owner["guard_plan"] and guard["unit"] == UNIT
         and owner["floor"] == guard["minimum_free_bytes"],
         "expected one nonresident producer booking and its intact guard")
    # The raw ancestor budget still carries 48 GiB. The current native and
    # full budgets carry the superseding 56 GiB. They are different views of
    # one booking, so compare all margins without summing their differences.
    nominal = whole["fits"] and min(whole["home_margin"], whole["ram_margin"]) >= 0
    raw_debit = 0 if nominal else joint["producer_allowance"] - READER_RAM
    debit = 0 if nominal else budget["producer_memory"] - READER_RAM
    differences = {"joint": raw_debit, "native": debit, "full": debit}
    rows = {"joint": joint, "native": native, "full": whole}
    checks = {}
    for name, row in rows.items():
        available, required = row["available_ram"], row["required_ram"]
        need(available - required == row["ram_margin"] and required >= differences[name],
             "inconsistent prior RAM arithmetic")
        checks[name] = dict(required_before=required, required_after=required - differences[name],
                            ram_margin=row["ram_margin"] + differences[name],
                            home_margin=row["home_margin"])
    checks["peer"] = dict(ram_margin=base["ram_margin"] + debit, home_margin=base["home_margin"])
    # Retain the complete HOME booking, all peer floors and the exact old
    # guard. The reader writes receipts within the prior 64 MiB control space.
    floors = [whole["guard_floor"], *whole["observed_sibling_guard_floors"],
              guard["minimum_free_bytes"], whole["epoch143_installed_guard_floor"]]
    home = min(*(row["home_margin"] for row in checks.values()),
               whole["available_home"] - whole["required_home"],
               *(whole["available_home"] - floor for floor in floors if floor is not None))
    ram = min(row["ram_margin"] for row in checks.values())
    fits = nominal or home >= CONTROL and ram >= 0
    return dict(schema="horizon-170-private-closed-reader-funded-exchange-v1", fits=fits, nominal=nominal,
                provider=provider, writer=whole["writer"], fleet=whole["fleet"], actor=binding["actor"],
                terminal=terminal["pid1"], original_intent=budget["intent"], original_price=intent["price"],
                guard_plan=owner["guard_plan"], guard_timer_invocation_id=release["guard_timer_invocation_id"],
                existing_guard_memory=GIB, original_producer_memory=budget["producer_memory"],
                reader_memory=READER_RAM, reader_cpu_quota_micros=READER_CPU,
                sublease_debit=debit, home_margin=home, ram_margin=ram, floors=floors, budgets=checks,
                resource_credit_bytes=0, authority="private closed reader")


def quote(whole, provider, terminal):
    result = project(whole, provider, terminal)
    producer = systemd(UNIT, "Id", "ActiveState", "MainPID", "ControlPID", "ControlGroup", "Job", "InvocationID")
    timer = systemd(TIMER, "Id", "ActiveState", "Job", "InvocationID")
    invocation = producer["InvocationID"]
    state = {key: value for key, value in producer.items() if key != "InvocationID"}
    need(invocation in ("", IID)
         and state == dict(Id=UNIT, ActiveState="inactive", MainPID="0", ControlPID="0",
                              ControlGroup="", Job="")
         and not Path("/sys/fs/cgroup/system.slice", UNIT).exists(),
         "the retained producer cgroup is not drained")
    need(timer == dict(Id=TIMER, ActiveState="active", Job="",
                       InvocationID=result["guard_timer_invocation_id"]),
         "the original hourly guard timer changed")
    active = subprocess.check_output(["/usr/bin/systemctl", "list-units", "--plain", "--no-legend",
                                     "--type=service", "--state=running,activating,deactivating",
                                     "horizon-170-hourly-closed-read-*"], text=True, timeout=15)
    need(not active.strip(), "a closed reader already occupies the producer sublease")
    return dict(result, drained_cgroup=producer, retained_guard=timer)
