"""Use the shared post-assembly fleet quote for the already funded private scan."""

from hashlib import file_digest, sha256
import json
import os
from pathlib import Path
import runpy
import stat
import time

RT = Path("/var/lib/jetstreamer/horizon_runtime_data")
ROOT = RT / "epoch168-exact-private-verification-20261127-v1"
ORIGINAL = ROOT / "tools-v1"
SOURCE = ROOT / "split-price-v3"
ISSUER = RT / "epoch162-first-hourly-completion-20261127-v2"
DONOR = {"path":str(ISSUER/"SPLIT_AND_166_WATCHERS_1795819276953592886.json"),
         "sha256":"64aa76de4fb179a650488d3d53c05050aff7b4fa97ef60c61d3726e42545133c"}
OPERATION = Path("/run/horizon-epoch171-to136-g1.operation.lock")
SERIAL = Path("/run/lock/horizon-epoch140-suffix-compiler.lock")
G = 1 << 30
M = 1 << 20
ENTRY_RAM = 128*M


def need(condition, message):
    if not condition:
        raise ValueError(message)


def checked(path, sha256):
    st = path.lstat()
    need(path.resolve(strict=True) == path and stat.S_ISREG(st.st_mode) and st.st_uid == 0
         and st.st_nlink == 1 and not st.st_mode & 0o222, "unsealed price dependency " + str(path))
    with path.open("rb") as source:
        need(file_digest(source,"sha256").hexdigest() == sha256, "changed price dependency " + str(path))


def enrolled_provider(binding):
    seal = binding["package"]
    path = Path(seal["path"])
    need(path.is_relative_to(RT) and path.name == "deployment-seal-receipt.json", "unknown shared package")
    checked(path,seal["sha256"])
    record = json.loads(path.read_bytes())
    entry = Path(binding["entry"]["path"])
    need(record["destination"] == str(path.parent) and entry.parent == path.parent
         and entry.suffix == ".py", "shared entry does not belong to the sealed package")
    members = {}
    for member in record["members"]:
        name = member["name"]
        file = path.parent/name
        need(file.parent == path.parent and name not in members and file.stat().st_size == member["bytes"],
             "invalid shared price package member")
        checked(file,member["sha256"])
        members[name] = member["sha256"]
    need(members.get(entry.name) == binding["entry"]["sha256"], "shared roster entry changed")
    return runpy.run_path(str(entry))["whole_roster"]


def decision(q, slice_before, slice_after):
    for name in ("home_margin", "ram_margin", "guard_floor"):
        need(type(q[name]) is int, "incomplete shared fleet price")
    need(type(q["fits"]) is bool and (not q["fits"] or min(q["home_margin"],q["ram_margin"]) >= 0)
         and q["guard_floor"] > 0, "unfunded post-assembly roster")
    need(slice_before["child_quotas"] == slice_after["child_quotas"] and
         slice_before.get("pending",[]) == slice_after.get("pending",[]) and
         slice_before["additional_audit_ram"] == slice_after["additional_audit_ram"],
         "audit slice ownership changed during shared pricing")
    return q["fits"] and q["ram_margin"] >= ENTRY_RAM and slice_before["fits"] and slice_after["fits"]


def own_locks():
    rows = [line.split()[1:8] for line in Path("/proc/locks").read_text().splitlines()]
    for path in (OPERATION, SERIAL):
        st = path.lstat()
        inode = f"{os.major(st.st_dev):02x}:{os.minor(st.st_dev):02x}:{st.st_ino}"
        need(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1 and not st.st_mode & 0o022
             and ["FLOCK","ADVISORY","WRITE",str(os.getpid()),inode,"0","EOF"] in rows,
             "private admission does not own the registered lock " + str(path))


def historical_receipt(ref):
    # Older native receipts have root-only write access. Verify their bytes
    # against the digest inherited from the original sealed six-owner ledger.
    path = Path(ref["path"])
    st = path.lstat()
    need(path.is_relative_to(RT) and path.resolve(strict=True) == path and stat.S_ISREG(st.st_mode)
         and st.st_uid == 0 and st.st_nlink == 1 and not st.st_mode & 0o022, "foreign historical receipt")
    data = path.read_bytes()
    need(sha256(data).hexdigest() == ref["sha256"], "changed historical 166 receipt")
    return json.loads(data)


def historical_166(base):
    accounting = base["accounting"]
    serial = accounting["serial"]
    lineage = accounting["old_six_owner_lineage"]
    inherited = serial["inherited_ledger"]
    need(inherited["sha256"] == "e94d1b2cb8eed6c1df6ffa4e5958a24e660ef25fbd7e9a80e99a1cf914afc9eb"
         and inherited in lineage["references"] and serial["basis167"] in lineage["references"]
         and serial["inherited_pre_residency_ram"] == lineage["bounded_167_base"]
         and base["native"]["raw"]["joint"]["required_ram"] + base["native"]["raw"]["joint"]["resident_lower_bytes"]
         >= lineage["bounded_167_base"], "166 allocation is missing from the current ledger")
    old = historical_receipt(inherited)
    fleet = historical_receipt(old["fleet"])
    actors = [row for row in fleet["actual_executing_replays"] if row["epoch"] == 166]
    need(len(actors) == 1 and not old["resource_promise_ending_bytes"] and not old["resource_credit_bytes"],
         "different historical 166 booking")
    actor = actors[0]
    admission = historical_receipt(actor["admission"])
    need(admission["epoch"] == 166 and admission["producer_unit"] == actor["unit"]["Id"] == old["owners"]["166"]["unit"]
         and admission["producer_invocation_id"] == actor["unit"]["InvocationID"] == old["owners"]["166"]["iid"]
         and admission["candidate_hard_memory_bytes"] == 68*G
         and admission["independent_physical_cap_bytes"] == old["native_inputs"]["independent166_whole_cap_bytes"] == 288*G
         and admission["all_prior_promises_retained"] and not admission["resource_credit_bytes"],
         "historical 166 actor differs from the leased capacity")
    return dict(ledger=inherited, original_fleet=old["fleet"], original_166_admission=actor["admission"],
                bounded_167=serial["basis167"])


def protected_166(q, proof):
    d = q["donor_compute"]
    need(q["donor"] == DONOR and proof["donor"] == d and proof["retained_166_disk_bytes"] == 288*G
         and d["original_actor_bytes"] == 68*G and d["both_handlers_and_receivers_ram"] == 4608*M
         and d["passive_199_control_ram"] == 512*M and d["usable_166_ram"] == 63*G
         and d["original_cpu_micros"] == 9_000_000 and d["both_handlers_and_receivers_cpu"] == 3_000_000
         and d["passive_199_control_cpu"] == 250_000 and d["usable_166_cpu_micros"] == 5_750_000,
         "unrecognized temporary 166 booking")
    native = q["native_donor"]
    registered = set(proof["native"]) - {"horizon-qualify-162-first-hourly-completion-20261127-v2.service",
                                        "horizon-168-private-verification-listener.service"}
    need(set(native) == registered | {"horizon-199200-joint-cached-controller-20261121-v1.service",
                                      "horizon-qualify-199200-reservation-20261121-v1.service"},
         "incomplete temporary 166 donor census")
    for name, state in native.items():
        need(state["Id"] == name and not state["Job"], "166 donor has a pending operation")
        if name.endswith(".path"):
            original = proof["native"][name]
            need(state["ActiveState"] == "active" and state["SubState"] == "waiting"
                 and all(state[k] == original[k] for k in ("Paths","InvocationID","Triggers")),
                 "166 publication path changed")
        else:
            need(state["ActiveState"] in ("inactive","failed") and not state.get("ControlGroup")
                 and state.get("MainPID","0") == state.get("ControlPID","0") == "0", "166 donor has an active receiver")


def choose_phase(q, proof):
    shared = dict(mode="simultaneous", fits=q["fits"], home_margin=q["home_margin"], ram_margin=q["ram_margin"],
                  guard_floor=q["guard_floor"], required_home=q["required_home"], temporary_166_ram=0,
                  prospective_162_home_deferred=0)
    if q["existing_162"] is not None or (q["fits"] and q["ram_margin"] >= ENTRY_RAM):
        return shared
    protected_166(q,proof)
    base = q["base_169"]
    native = base["native"]
    need(q["prospective_162"] and q["remaining_162_home"] == 8*G and q["realized_162_ram"] == 0
         and q["required_home"] >= base["required_home"]+8*G and q["ram_margin"] == base["ram_margin"]
         and q["available_home"] == base["available_home"] and base["home_margin"] == q["available_home"]-base["required_home"]
         and base["required_home"] == base["guard_floor"] + base["remaining_output"]
         and base["guard_floor"] >= base["protected_home"]+64*M
         and not {162,166,173,199,200}.intersection(row["epoch"] for row in base["observed_actors"]),
         "five-owner price omitted an issued booking")
    if base["actor"]["phase"] != "terminal":
        disk = base["actor"]["disk"]
        need(base["guard_floor"] >= disk["floor"] and base["remaining_output"] >= disk["remaining"],
             "five-owner price omitted the epoch 169 guard or output")
    # The qualified provider prices current and following 170, including the
    # 143 turnover, before deriving base. Keep both of its historical limits.
    home = min(base["home_margin"], native["home_margin"], native["historical_home_margin"])
    requested = max(0, ENTRY_RAM - base["ram_margin"])
    borrowed = min(requested, q["donor_compute"]["usable_166_ram"])
    ram = base["ram_margin"] + borrowed
    return dict(mode="168-before-unissued-162", fits=home >= 0 and ram >= ENTRY_RAM,
                home_margin=home,ram_margin=ram,guard_floor=base["guard_floor"],required_home=base["required_home"],
                temporary_166_ram=borrowed, requested_temporary_166_ram=requested,
                prospective_162_home_deferred=q["required_home"]-base["required_home"],
                retained_166_disk_bytes=proof["retained_166_disk_bytes"],
                retained_166_handlers_and_199_ram=proof["donor"]["both_handlers_and_receivers_ram"]
                                                  + proof["donor"]["passive_199_control_ram"],
                historical_home_margin=native["historical_home_margin"])


def controller():
    group = Path("/sys/fs/cgroup")/Path("/proc/self/cgroup").read_text().strip().removeprefix("0::/")
    need(group.parent == Path("/sys/fs/cgroup/system.slice") and
         group.name.startswith("horizon-168-postassembly-dispatch-") and group.name.endswith(".service") and
         (group/"memory.max").read_text().strip() == str(ENTRY_RAM) and
         (group/"memory.swap.max").read_text().strip() == "0" and
         (group/"cpu.max").read_text().split() == ["25000","100000"] and
         (group/"pids.max").read_text().strip() == "64", "private dispatch controller is outside its bounded unit")
    return group.name


def price(fixture=False):
    need(not fixture and os.geteuid() == 0 and __debug__ and Path(__file__).resolve().parent == SOURCE,
         "use the issued private post-assembly price")
    entry = runpy.run_path(str(SOURCE/"dispatch.py"))
    registration = entry["load_published_pricing"]()
    release = entry["checked"](registration["original_deployment"])
    original = release["source"]["capacity.py"]
    need(original["path"] == str(ORIGINAL/"capacity.py") and
         registration["original_deployment"]["sha256"] == "55a9eecbcd29346d344f4aa9501d35890c5276392e1c84e5437957210a3b537d",
         "different original verifier")
    checked(ORIGINAL/"capacity.py",original["sha256"])
    old = runpy.run_path(str(ORIGINAL/"capacity.py"))
    _, api = old["load_helpers"]()
    contract = entry["checked"](registration["contract"])
    need(registration["contract"]["sha256"] == "689937a6805ab14a1d59c430c818ba98f463596dcdca483fca0a433980a1c53f"
         and contract["memory_max"] == 2*G and contract["cpu_quota_micros"] == 1_000_000
         and contract["evidence_limit"] == 16*M and contract["archive_disk_growth"] == contract["working_tree_bytes"] == 0
         and contract["shared_lock"] == str(OPERATION) and contract["compiler_serial_lock"] == str(SERIAL),
         "different native scanner reservation")
    quote = enrolled_provider(registration["shared_price"])
    unit = controller()
    own_locks()
    enrolled = entry["checked"](registration["issuer_enrollment"])
    need(enrolled["capacity"] == registration["shared_price"]["entry"] and enrolled["donor"] == DONOR,
         "162 is not enrolled on the unborrowed shared price")
    before = old["slice_admission"](api)
    start = time.monotonic()
    result = quote()
    after = old["slice_admission"](api)
    booking = result["base_169"]["accounting"]["verification168_listener"]
    need(result["schema"] == "horizon-168-post-assembly-six-owner-price-v1"
         and result["package"] == registration["shared_price"]["package"] and not result["resource_credit_bytes"]
         and result["prospective_162"] == (result["existing_162"] is None)
         and result["available_home"] - result["required_home"] == result["home_margin"]
         and result["available_ram"] - result["required_ram"] == result["ram_margin"]
         and result["donor_compute"]["usable_166_cpu_micros"] >= 3_000_000 + 250_000
         and booking["contract"] == registration["contract"] and booking["deployment"] == registration["original_deployment"]
         and booking["scanner_ram_from_serial"] == 2*G and booking["listener_ram"] == 128*M
         and booking["listener"]["ActiveState"] == "active" and booking["audits"]["scanner"] is None,
         "complete shared price does not fund the private verifier")
    need(entry["checked"](registration["issuer_enrollment"]) == enrolled and result["writer"] == enrolled["writer_active"],
         "162 enrollment changed during pricing")
    proof = entry["checked"](DONOR)
    phase = choose_phase(result,proof)
    ancestry = historical_166(result["base_169"]) if phase["mode"] == "168-before-unissued-162" else None
    own_locks()
    fits = decision(phase,before,after)
    need(time.monotonic()-start < 120, "expired shared fleet price")
    return dict(schema="horizon-168-private-post-assembly-admission-price-v1",fits=fits,whole_roster=result,
                shared_price=registration["shared_price"],contract=registration["contract"],
                price_registration=entry["ref"](entry["pricing_registration"]()),
                before=before,after=after,original_deployment=registration["original_deployment"],
                phase=phase,donor_lineage=ancestry,issuer_enrollment=registration["issuer_enrollment"],
                resource_credit_bytes=0,home_margin=phase["home_margin"],ram_margin=phase["ram_margin"]-ENTRY_RAM,
                guard_floor=phase["guard_floor"],
                entry_controller=unit,entry_controller_ram=ENTRY_RAM,entry_controller_cpu_micros=250_000,
                existing_scanner_ram=2*G,existing_listener_ram=128*M,existing_output_bound=16*M,
                incremental_archive_storage=0,canonical_writes=False)
