"""Use the current shared roster to issue the staged disk-backed 170 from a closed RAM segment."""
from hashlib import sha256
import json
from pathlib import Path
import runpy
import stat
import time

RT = Path("/var/lib/jetstreamer/horizon_runtime_data")
DEP = ATTEMPT = RT / "epoch170-from-73766969-gap-20261128-v1"
OPERATOR = DEP / "operator-v1"
BASE_PROVIDER = RT / "epoch162-first-hourly-completion-20261127-v2/issued-price-v22"
BASE_SEAL = dict(path=str(BASE_PROVIDER / "deployment-seal-receipt.json"),
                 sha256="e8d13381e4089ab239c9dd1b2bf5025fc297ab1f9ba654e3fc8f1aeaf2c202ee")
WRITER_ROOT = RT / "survivor172-cadence-20261122-v1"
V64 = dict(path=str(WRITER_ROOT / "FAILED166_CADENCE_V64_ACTIVE.json"),
           sha256="986f2778ca9f025b778c5a188d88ecdeaa1c18ae042924429e8d201aece77d29")
UNIT = "horizon-qualify-170-from-73766969-20261127-v1.service"
BRIDGE = "horizon-qualify-170-from-73760367-ram-20261128-v3.service"
ALIAS = "/run/horizon-170-from-73766969-v1"
ENROLL_OPTION = "--enroll-after-ram-170"
RETRY = FOLLOWING = False
HOURLY_ROOT = RT / "epoch170-from-73766969-ram-20261128-v1"
HOURLY = Path(__file__).resolve().parent == HOURLY_ROOT / "operator-v1"
if HOURLY:
    DEP = ATTEMPT = HOURLY_ROOT
    OPERATOR = DEP / "operator-v1"
    BRIDGE = UNIT
    UNIT = "horizon-qualify-170-from-73766969-ram-20261128-v1.service"
    ENROLL_OPTION = "--enroll-after-floor-170"
    PRODUCER_MEMORY = 56 << 30


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def member(path, digest):
    st = path.lstat()
    need(path.resolve(strict=True) == path and stat.S_ISREG(st.st_mode) and st.st_uid == 0
         and st.st_nlink == 1 and not st.st_mode & 0o222, "unsealed source " + str(path))
    value = path.read_bytes()
    need(sha256(value).hexdigest() == digest, "changed source " + str(path))
    return value


def package(directory, ref):
    path = directory / "deployment-seal-receipt.json"
    need(ref["path"] == str(path), "different deployment directory")
    sealed = json.loads(member(path, ref["sha256"]))
    rows = {item["name"]: item for item in sealed["members"]}
    need(sealed["destination"] == str(directory) and len(rows) == len(sealed["members"]), "foreign package")
    for name, item in rows.items():
        target = directory / name
        need(target.parent == directory, "indirect package member")
        member(target, item["sha256"])
    return rows


def binding():
    own = OPERATOR / "deployment-seal-receipt.json"
    source = json.loads(own.read_bytes())
    need(own.resolve(strict=True) == own and own.stat().st_uid == 0 and not own.stat().st_mode & 0o222
         and source["destination"] == str(OPERATOR), "uninstalled after-RAM issuer")
    item, = [item for item in source["members"] if item["name"] == "binding.json"]
    result = json.loads(member(OPERATOR / "binding.json", item["sha256"]))
    name = "AFTER_FLOOR_WRITER_INTERFACE.json" if HOURLY else "AFTER_RAM_WRITER_INTERFACE.json"
    need(result["current_writer"] == V64 and result["scope"]["path"] == str(DEP / name)
         and not result["publication_authorized"], "unexpected installed scope or writer")
    return result


BINDING = binding()
PROVIDER = Path(BINDING["provider"]["path"]).parent


def shared_chain(directory, ref):
    expected = directory.name.removeprefix("issued-price-v")
    need(directory.parent == BASE_PROVIDER.parent and expected.isdigit()
         and directory.name == f"issued-price-v{int(expected)}" and int(expected) >= 22,
         "unrecognized shared provider")
    for version in range(int(expected),21,-1):
        package(directory,ref)
        if version == 22:
            need(ref == BASE_SEAL, "shared issuer lost its accepted V22 anchor")
            return
        ref = json.loads((directory / "SOURCE.json").read_bytes())["prior_shared_price"]
        directory = directory.with_name(f"issued-price-v{version-1}")


shared_chain(PROVIDER, BINDING["provider"])
prior = runpy.run_path(str(PROVIDER / "continuation_price.py"))["prior"]
read, bound, state, inactive, cmd, TREE = prior.read, prior.bound, prior.state, prior.inactive, prior.cmd, prior.TREE
shared = runpy.run_path(str(PROVIDER / ("after_floor170_price.py" if HOURLY else "after_ram170_admission.py")))
callback = shared["receiver"](prior, PROVIDER)
need(shared["SCOPE"] == callback.INTERFACE == BINDING["scope"] and callback.UNIT == UNIT,
     "unregistered issuer receiver")


def scope():
    return callback.contract.interface(), callback.INTERFACE


def compare_predecessor():
    if HOURLY:
        return callback.contract.checkpoint(scope()[0])
    return callback.contract.closed_comparison(scope()[0])


def predecessor_drained():
    comparison = compare_predecessor()
    for name in (BRIDGE, BRIDGE.replace("-qualify-", "-guard-")):
        need(not inactive(name)["ControlGroup"] and not (Path("/sys/fs/cgroup/system.slice") / name).exists(),
             "predecessor still owns a cgroup")
    guard = BRIDGE.replace("-qualify-", "-guard-").replace(".service", ".timer")
    timer = state(guard, "Id,ActiveState,Job")
    need(timer["ActiveState"] == "inactive" and not timer["Job"], "preceding guard has not drained")
    return comparison


def latest_hourly_provider():
    """Follow only sealed descendants of the admitted hourly provider that keep this issuer registered."""
    trusted = BINDING["provider"]
    member_digest = package(PROVIDER,trusted)["after_floor170_price.py"]["sha256"]
    version = int(PROVIDER.name.removeprefix("issued-price-v"))
    observed = sorted(int(p.name.removeprefix("issued-price-v")) for p in PROVIDER.parent.glob("issued-price-v*")
                      if p.name.removeprefix("issued-price-v").isdigit() and int(p.name.removeprefix("issued-price-v"))>version)
    directory = PROVIDER
    for expected, found in enumerate(observed,version+1):
        need(found==expected,"missing hourly provider predecessor")
        directory = PROVIDER.with_name(f"issued-price-v{expected}")
        receipt = directory/"deployment-seal-receipt.json"
        ref = dict(path=str(receipt),sha256=sha256(receipt.read_bytes()).hexdigest())
        members = package(directory,ref)
        history = json.loads(member(directory/"SOURCE.json",members["SOURCE.json"]["sha256"]))
        need(history["prior_shared_price"] == trusted and history["after_floor170_interface"] == callback.INTERFACE
             and members["after_floor170_price.py"]["sha256"] == member_digest, "different hourly receiver or provider lineage")
        trusted = ref
    return directory, trusted


def writer(require_registration=True):
    need(bound(V64)["new"]["program"] == str(WRITER_ROOT / "tools-cold168-retry5-failed166-v64-entry146/status_cycle.py"),
         "unrecognized V64 owner")
    peers = runpy.run_path(str(PROVIDER / "following_peers.py"))
    original = dict(path=str(peers["ISSUED"] / "deployment-seal-receipt.json"), sha256=peers["SEAL169"])
    active = peers["current_writer"](prior, original)
    actor = bound(active)
    ready = bound(actor["ready"])
    program = Path(actor["new"]["program"])
    if HOURLY:
        need(ready["after_ram170_interface"] == scope()[0]["preceding_disk_interface"], "writer lost the floor-stopped owner")
        if not require_registration and "after_floor170_interface" not in ready:
            return active, None
        key, digest = "after_floor170_interface", shared["RECEIVER_DIGEST"]
    else:
        need(ready["third_ram_gap170_interface"] == scope()[0]["prior_ram_interface"], "writer lost the RAM predecessor")
        key, digest = "after_ram170_interface", shared["SEAL"]
    receiver = package(shared["RECEIVER"],dict(path=str(shared["RECEIVER"] / "deployment-seal-receipt.json"),sha256=digest))
    installed = bound(ready["package"])
    rows = {item["name"]: item["sha256"] for item in installed["members"]}
    need(ready.get(key) == callback.INTERFACE
         and installed["destination"] == str(program.parent)
         and all(rows.get(name) == item["sha256"] for name, item in receiver.items())
         and ENROLL_OPTION.encode() in member(program, rows[program.name]), "writer has not installed the successor")
    return active, program


def price(phase, *, preliminary=False):
    need(Path(__file__).resolve().parent == OPERATOR and phase in ("start","held"),
         "different staged issuer or phase")
    old = predecessor_drained()
    active, program = writer(require_registration=not preliminary)
    if HOURLY:
        latest, provider_ref = latest_hourly_provider()
        capacity = runpy.run_path(str(latest / "capacity.py"))
        result = capacity["after_floor170_roster"](phase)
        need(result["whole_roster"]["package"] == provider_ref and result["writer"] == active
             and result["closed_comparison"] == old and not result["resource_credit_bytes"], "different hourly admission")
        return dict(result, writer_ready=program is not None, preliminary=preliminary)
    whole = runpy.run_path(str(PROVIDER / "capacity.py"))["whole_roster"]()
    need(whole["package"] == BINDING["provider"] and whole["writer"] == active
         and not whole["resource_credit_bytes"] and not whole["preparation_only"], "inconsistent shared owner or authority")
    return shared["candidate"](whole, phase, scope=callback.INTERFACE, closed=old)


def recover_start(inspect, save, scope_ref, closed):
    intent, ref = read(DEP / "SUCCESSOR_START_INTENT.json")
    need(intent["interface"] == scope_ref and intent["closed_comparison"] == closed
         and intent["producer_unit"] == UNIT and not intent["archive_publication_authorized"]
         and bound(intent["price"])["fits"], "foreign pending producer intent")
    native = state(UNIT)
    need(native["ActiveState"] == "active" and not native["Job"],
         "a prior start intent exists without a live held gate; reconcile its native result")
    actual = inspect()
    token = b"HORIZON_170_START_INTENT_SHA256=" + ref["sha256"].encode()
    env = (Path("/proc") / str(actual["producer_pid"]) / "environ").read_bytes().split(b"\0")
    need(env.count(token) == 1 and not Path(scope()[0]["barrier"]).exists()
         and not (DEP / "SUCCESSOR_RELEASE.json").exists(), "held gate does not bind the pending start")
    return save("SUCCESSOR_ACTOR.json",actual)


def recover_guard(operator):
    timer = state(operator.TIMER, "Id,ActiveState,Job")
    need(not timer["Job"], "successor guard timer is in transition")
    if timer["ActiveState"] == "active":
        return
    actor, _ = operator.same_actor()
    layout, _ = scope()
    plan, ref = read(Path(layout["plan_path"]))
    directory = Path(plan["receipt_directory"])
    need(timer["ActiveState"] == "inactive" and not inactive(operator.GUARD)["ControlGroup"]
         and directory == Path(layout["guard_receipts"]) and not any(directory.iterdir())
         and plan["unit"] == UNIT and plan["invocation_id"] == actor["producer_invocation_id"]
         and plan["worker_root"] == str(TREE) and not (DEP / "SUCCESSOR_RELEASE.json").exists(),
         "partially armed guard needs native reconciliation")
    fit = operator.checked_price("held")
    need(operator.funded_guard(fit, plan["minimum_free_bytes"], plan["maximum_root_physical_bytes"]),
         "existing guard plan exceeds fresh shared fit")
    operator.start_guard(layout, ref)


def recover_release(operator, grant, grant_ref):
    layout, scope_ref = scope()
    closed = predecessor_drained()
    actor, actor_ref = operator.same_actor()
    enrollment, enrollment_ref = read(DEP / "WRITER_ENROLLMENT.json")
    active, _ = writer()
    sample, timer, plan, plan_ref = operator.guard()
    accepted = bound(grant["admission"])
    need(grant["actor"] == actor_ref and grant["guard_plan"] == plan_ref and grant["guard_timer_invocation_id"] == timer
         and grant["producer_invocation_id"] == actor["producer_invocation_id"] and grant["interface"] == scope_ref
         and grant["closed_comparison"] == closed and grant["writer_enrollment"] == enrollment_ref
         and grant["resource_credit_bytes"] == 0 and not grant["archive_publication_authorized"]
         and enrollment["writer_active"] == active and enrollment["actor"] == actor_ref and enrollment["enrolled"]
         and accepted["actor"] == actor_ref and accepted["first_guard_sample"] == grant["first_guard_sample"]
         and accepted["post_guard_capacity"] == grant["post_guard_capacity"]
         and bound(grant["post_guard_capacity"])["fits"], "incomplete release is not bound to the current held actor")
    fit = operator.checked_price("held")
    need(operator.funded_guard(fit, plan["minimum_free_bytes"], plan["maximum_root_physical_bytes"]),
         "joint postguard HOME coverage failed")
    recovery = operator.save("SUCCESSOR_PERMIT_RECOVERY_" + str(time.time_ns()) + ".json",
                             dict(release=grant_ref,scope=scope_ref,closed_comparison=closed,actor=actor_ref,
                                  writer_enrollment=enrollment_ref,guard_sample=sample,price=fit,publication_authorized=False))
    need(operator.guard()[1] == timer and writer()[0] == active
         and time.time() - fit["observed"] <= 90, "recovered release expired")
    operator.publish_permit(Path(layout["barrier"]), actor["producer_invocation_id"])
    return dict(released=grant_ref,recovery=recovery)
