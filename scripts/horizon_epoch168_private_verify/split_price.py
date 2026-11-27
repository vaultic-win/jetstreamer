"""Use the shared post-assembly fleet quote for the already funded private scan."""

from hashlib import file_digest
import json
import os
from pathlib import Path
import runpy
import stat
import time

RT = Path("/var/lib/jetstreamer/horizon_runtime_data")
ROOT = RT / "epoch168-exact-private-verification-20261127-v1"
ORIGINAL = ROOT / "tools-v1"
SOURCE = ROOT / "split-price-v1"
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
    fits = decision(result,before,after)
    need(time.monotonic()-start < 120, "expired shared fleet price")
    return dict(schema="horizon-168-private-post-assembly-admission-price-v1",fits=fits,whole_roster=result,
                shared_price=registration["shared_price"],contract=registration["contract"],
                before=before,after=after,original_deployment=registration["original_deployment"],
                home_margin=result["home_margin"],ram_margin=result["ram_margin"]-ENTRY_RAM,guard_floor=result["guard_floor"],
                entry_controller=unit,entry_controller_ram=ENTRY_RAM,entry_controller_cpu_micros=250_000,
                existing_scanner_ram=2*G,existing_listener_ram=128*M,existing_output_bound=16*M,
                incremental_archive_storage=0,canonical_writes=False)
