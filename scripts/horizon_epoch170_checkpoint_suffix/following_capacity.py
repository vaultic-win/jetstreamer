"""Include the local assembly, compiler, private intake and serial holding commitments at the fourth 170 handoff."""
from datetime import datetime
from hashlib import file_digest
from pathlib import Path
import re
import sys

GIB = 1 << 30
MIB = 1 << 20
RT = Path("/var/lib/jetstreamer/horizon_runtime_data")
DIRECTORY = RT / "epoch170-from-73766969-20261127-v1"
N_TOOLS = RT / "epoch186-closed-partial-rotation-20261127-v1/n-tools-v4"
N_SEAL = "d3a6bb1bd9e038af3118e765e40f81e9fb9ee03654ac9244e230f6247e624002"
INPUT_BYTES = 2_149_673_902


def load_holding(core):
    seal, seal_ref = core.read(N_TOOLS / "deployment-seal-receipt.json", N_SEAL)
    core.need(seal["destination"] == str(N_TOOLS), "different holding provider")
    for member in seal["members"]:
        path = N_TOOLS / member["name"]
        with path.open("rb") as source:
            digest = file_digest(source, "sha256").hexdigest()
        core.need(path.resolve() == path and not path.stat().st_mode & 0o222
                  and digest == member["sha256"], "changed holding provider")
    sys.path.insert(0, str(N_TOOLS))
    try:
        import n_admission
        core.need(Path(n_admission.__file__).resolve() == N_TOOLS / "n_admission.py",
                  "unexpected holding module")
    finally:
        sys.path.pop(0)
    return n_admission, seal_ref


def holding_owner(core, provider):
    units = provider.active_units("horizon-*park*", "horizon-*holding*", "horizon-*retire*",
                                  "horizon-*restore*", "horizon-closed186-*")
    if not units:
        return None
    core.need(len(units) == 1, "multiple serial holding owners")
    name, = units
    match = re.fullmatch(r"horizon-closed186-(park|retire|restore)-n-([0-9]+)\.service", name)
    core.need(match, "new serial holding owner requires a reconciled booking")
    receipt, ref = core.read(provider.op.OUT / "n" / f"ADMISSION_{match[1]}_{match[2]}.json")
    current = core.state(name)
    core.need(current["ActiveState"] == "active" and not current["Job"]
              and current["InvocationID"] == receipt["invocation"] and receipt["unit"] == name
              and int(current["MemoryMax"]) == receipt["ram"] <= 2 * GIB
              and current["MemorySwapMax"] == str(receipt["swap"]) == "0"
              and current["CPUQuotaPerSecUSec"] in ("1s", "2s"),
              "holding unit differs from its admission")
    cgroup = Path("/sys/fs/cgroup" + current["ControlGroup"])
    core.need((cgroup / "memory.max").read_text().strip() == current["MemoryMax"]
              and (cgroup / "memory.swap.max").read_text().strip() == "0",
              "serial holding cgroup exceeds its reservation")
    return dict(admission=ref, native=current)


def incoming(core, provider, fleet, interface):
    intake_dir = RT / "epoch170-following-bootstrap-20261127-v1"
    pending = provider.active_units("horizon-input-170-73766969-*")
    if interface is None:
        # A predecessor's closed archive can be attested before the next input
        # exists. Only actually issued transfers contribute growth and memory.
        starts = sorted(intake_dir.glob("START_*.json"))
        custody = intake_dir / "INPUT_CUSTODY.json"
        core.need(pending <= {"horizon-input-170-73766969-gcs-v1.service"}
                  and (not pending or starts), "unbound next-input transfer")
        if not starts:
            core.need(not custody.exists(), "input custody has no issued transfer")
            return None, 0, 0, 0
        ref = core.read(starts[-1])[1]
        if custody.is_file():
            core.need(not pending, "input copier still active after custody")
            _, concluded = core.read(custody)
            after_census = custody.stat().st_mtime > datetime.fromisoformat(fleet["sampled_at_utc"]).timestamp()
            return concluded, INPUT_BYTES if after_census else 0, 0, 0
        if pending:
            unit, = pending
            native = core.state(unit)
            core.need(native["MemoryMax"] == str(GIB) and native["MemorySwapMax"] == "0"
                      and native["CPUQuotaPerSecUSec"] == "500ms", "unexpected input copier")
        return ref, INPUT_BYTES, INPUT_BYTES, GIB
    intake, intake_ref = core.read(DIRECTORY / "package/following-input.json")
    st = Path(intake["destination"]).lstat()
    core.need(intake_ref == core.bound(interface["handoff"])["following_input"]
              and st.st_dev == Path("/home/sol").stat().st_dev
              and [st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns] == intake["file_identity"]
              and st.st_size == INPUT_BYTES and intake["single_copy"]
              and not pending,
              "single-copy following input is not in custody")
    input_after_fleet = datetime.fromisoformat(intake["completed_utc"]) > datetime.fromisoformat(fleet["sampled_at_utc"])
    return intake_ref, st.st_blocks * 512 if input_after_fleet else 0, 0, 0


def charge(core, base, assembly, interface):
    provider, seal = load_holding(core)
    fleet = provider.accepted_fleet(base["fleet"])
    funds = fleet["retry9_auxiliary_commitments"]
    repeated = provider.repeated_serial_slot(base, funds)
    compiler = provider.compiler_reservation()
    recovery = provider.recovery_reservation(compiler)
    owner = holding_owner(core, provider)
    # Account the existing bootstrap as occupied bytes. The fresh filesystem
    # reading already excludes its allocation. An older cadence may precede it.
    intake_ref, historical_input, pending_home, pending_ram = incoming(core, provider, fleet, interface)
    if assembly["state"] != "queued-or-drained":
        admitted = assembly["replay"]
        peer = base["replacement143"]
        core.need(not admitted["invocation143"] or (peer and peer["iid"] == admitted["invocation143"]),
                  "unreconciled 143 reservation")
        core.need(not admitted["invocation170"] or admitted["invocation170"] in
                  (base["priced_170_invocation"], "c3ab30cfeb05428bb8f5c48a5a44822c"),
                  "unreconciled 170 reservation")
    growth = base["required_home"] - base["guard_floor"]
    # The previous interval's 143 scheduling exclusion ends at its recorded
    # handoff. Preserve the full concurrent 143 growth on an active 168 floor.
    floor = max(base["guard_floor"], assembly["floor"] + base["guarded_hourly_remaining"] if assembly["floor"] else 0)
    archive_growth = assembly["incremental_home"]
    floor += pending_home
    candidate_home = floor + archive_growth + growth
    history = base["historical_home_margin"] - archive_growth - historical_input
    read_turnover = 0
    if base["phase"] == "read":
        # The native close and producer census are required before this quote.
        # The next producer cannot start until this reader exits and its complete
        # segment hash is accepted. Keep the independent guard and dispatcher.
        core.inactive("horizon-qualify-170-from-73746882-20261127-v1.service")
        core.inactive("horizon-qualify-170-from-73766969-20261127-v1.service")
        core.need(base["joint"]["producer_allowance"] == 48 * GIB and base["dispatch_memory_bytes"] == 512 * MIB,
                  "different readback turnover")
        read_turnover = 48 * GIB - 512 * MIB
    candidate_ram = base["required_ram"] + assembly["incremental_ram"] + pending_ram - read_turnover
    before_home, before_ram = core.availability()
    available_home = min(base["available_home"], before_home)
    available_ram = min(base["available_ram"], before_ram)
    budget = dict(available_home=available_home, required_home=candidate_home,
                  available_ram=available_ram, required_ram=candidate_ram,
                  historical_home_margin=history, home_margin=min(available_home-candidate_home, history),
                  ram_margin=available_ram-candidate_ram)
    rooms = provider.margins(budget, funds, compiler["image_physically_funded_bytes"], repeated["repeated_serial_bytes"])
    extra_reader = recovery["maximum_memory"] - funds["build_memory_bytes"]
    # The builder's independent evidence allowance is in margins(). The N
    # holding metadata and this interval's small records are independent.
    evidence_bytes = 32 * MIB
    home = rooms["remaining_home"] - evidence_bytes
    ram = rooms["post_reservation_ram_margin"] - extra_reader
    new_ram = available_ram - ram
    new_floor = floor + (rooms["build_home"] - compiler["image_physically_funded_bytes"]) + evidence_bytes
    new_required = new_floor + archive_growth + growth
    historical = history - rooms["build_home"] - evidence_bytes
    core.need(home == min(available_home-new_required, historical)
              and holding_owner(core, provider) == owner
              and core.current_fleet()[1] == base["fleet"],
              "complete commitments changed during the fourth-window quote")
    tree_fits = base["phase"] == "read" or base["terminal_tree_bounds"][1]+growth <= 384*GIB
    return dict(base, fits=home >= 0 and ram >= 0 and tree_fits,
                assembly168=assembly, guard_floor=new_floor, ordinary_170_guard_floor=base["guard_floor"],
                required_home=new_required, available_home=available_home, historical_home_margin=historical,
                home_margin=home, required_ram=new_ram, available_ram=available_ram, ram_margin=ram,
                assembly168_remaining_bytes=archive_growth, candidate_170_growth_bytes=growth,
                retained_143_growth=base["guarded_hourly_remaining"], following_custody=intake_ref,
                input_allocation_after_fleet=historical_input, sequential_read_RAM_difference=read_turnover, holding=owner, compiler=compiler, compiler_recovery=recovery,
                holding_provider=seal, shared_slot=repeated, charged_control_evidence=evidence_bytes,
                archive_publication_authorized=False)
