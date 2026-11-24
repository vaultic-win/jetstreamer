"""Observe the dedicated frozen-145 verifier from the funded incident census."""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

BASE = Path("/var/lib/jetstreamer/horizon_runtime_data")
UNIT = "horizon-holding-export145-20261121-v1.service"
VERSION = Path(__file__).resolve().parent.name
ENCODED_PREFIX_RECOVERY = VERSION == "tools-v5r"
AUDIT_TURNOVER_RECOVERY = ENCODED_PREFIX_RECOVERY or VERSION == "tools-v5q"
STATUS_OWNER_RECOVERY = AUDIT_TURNOVER_RECOVERY or VERSION == "tools-v5p"
DONOR_PRESSURE = STATUS_OWNER_RECOVERY or VERSION == "tools-v5o"
GUARD_WALK = DONOR_PRESSURE or VERSION == "tools-v5n"
MISSED_CLOCK = GUARD_WALK or VERSION == "tools-v5m"
LEASE_START = MISSED_CLOCK or VERSION == "tools-v5k"
FIVE_LANE_REJOIN = LEASE_START or VERSION in ("tools-v5h", "tools-v5i", "tools-v5j")
HOMEFLOOR_REJOIN = VERSION == "tools-v5g" or FIVE_LANE_REJOIN
HOMEFLOOR_PROVIDER = {"tools-v5h": "tools-homefloor-145-rejoin-v2",
                      "tools-v5i": "tools-homefloor-145-rejoin-v3",
                      "tools-v5j": "tools-homefloor-145-rejoin-v4",
                      "tools-v5m": "tools-homefloor-145-missed-rejoin-v1",
                      "tools-v5n": "tools-homefloor-145-guard-walk-rejoin-v1",
                      "tools-v5p": "tools-homefloor-145-status-owner-rejoin-v1",
                      "tools-v5q": "tools-homefloor-145-audit-turnover-rejoin-v1",
                      "tools-v5r": "tools-homefloor-145-encoded-prefix-rejoin-v1",
                      "tools-v5o": "tools-homefloor-145-donor-pressure-rejoin-v1",
                      "tools-v5k": "tools-homefloor-145-lease-rejoin-v1"}.get(VERSION, "tools-homefloor-145-rejoin-v1")
FIXTURE_REJOIN = VERSION == "tools-v5f" or HOMEFLOOR_REJOIN
TIMER_REJOIN = VERSION in ("tools-v5e", "tools-v5f") or HOMEFLOOR_REJOIN
FOCUSED_REJOIN = VERSION in ("tools-v5d", "tools-v5e", "tools-v5f") or HOMEFLOOR_REJOIN
TIMEOUT_REJOIN = VERSION in ("tools-v5c", "tools-v5d", "tools-v5e", "tools-v5f") or HOMEFLOOR_REJOIN
REJOIN = VERSION in ("tools-v5b", "tools-v5c", "tools-v5d", "tools-v5e", "tools-v5f") or HOMEFLOOR_REJOIN
PKG = BASE / "epoch145-semantic-continuity-20261121-v1" / (VERSION if REJOIN else "tools-v5")
IMAGE = PKG / "export145"
STATE = BASE / "epoch145-guarded-export-20261121-v1/state"
OLD = "add576f115cc4d3b897f47d024af72fd"
OLD_FAILURE = "33e011228a58df3c2a82ca49013a7d524eeca1e849fc59993effe5d2faf18e74"
OLD_RECOVERY = "9cdcfdb688ee018b9cddd43c9c5ba129712195e11d6c8172104a7f4a9a160a28"
if REJOIN:
    OLD = "5e0e20bc974149f096ea4bab10b15e1b"
    OLD_FAILURE = "00de799e968fa8c6e31a76284f0610bcc84bbe617193361ef457629b7294d38f"
    OLD_RECOVERY = "03cf2deacc6d38f5107bb894c59ced4ba2381aac425a1e3d9c401260053ca04f"
if TIMEOUT_REJOIN:
    OLD = "dc043eb78c4a4349b0098760dc764a1f"
    OLD_FAILURE = "baa00ca8b52aca80b105bf5582f955af8a3f9e22ce662908ce7a75afccfb1943"
    OLD_RECOVERY = "e992566275e63b28a020c847c02637626b245161a2e39f843ac1da4d64793b2f"
if FOCUSED_REJOIN:
    OLD = "d37f36f898a44932a19fd50d7014a6fe"
    OLD_FAILURE = "6533e594be11534e7fb58ac0f1fd752ead37cfd114e36899a956970b8318bb29"
    OLD_RECOVERY = "a3d623b47ea9612824d102714703b0d095db18e07bf8ce3570ec08331ad84e81"
if TIMER_REJOIN:
    OLD = "e6551a0bb8a14b989902e15c9ecc0751"
    OLD_FAILURE = "9ef9c938290ea2b43d3b2ce4aa617f08b33f4c893961e63f53ba3f48768e215f"
    OLD_RECOVERY = "55d2a0504271e8a1eea2ca8c105a288be9497f1a2b80177279481692d06e041f"
if FIXTURE_REJOIN:
    OLD = "a99ed8b51e8a482b805b8a36a11b2700"
    OLD_FAILURE = "da29d82a4349444ccc15e0be020aa12918ae5bbb4634f9b62e13cc83a93c5f43"
    OLD_RECOVERY = "6e06652ea695717b18fc29b955e463da8dc2dde16f8173da552df707c478e624"
if HOMEFLOOR_REJOIN:
    OLD = "afcf6cdd1ec0400ea2757f81472987b3"
    OLD_FAILURE = "5e001f59750a67f2cdce6aa43fb11b7d55e648a40d52e3fbee26ed3ead66a366"
    OLD_RECOVERY = "82532ce3f39356a26d78b2eb07ef32d6a90d604f7537d024ba5e696c42573ceb"
HOME = Path("/home/sol/.jetstreamer-private")
OUTPUT = HOME / "epoch145-prefix-extract-funded-20261121-v1/.tmp36MvkN"
SOURCE = HOME / "epoch145-cached-b2a09f57de39c384/work/diagnostic/epoch-145-through-63072070.jet"
MANIFEST = SOURCE.with_suffix(".jet.segment.json")
LOCK = HOME / "r2-holding-state-dev-samjohnson-v1/transition.lock"


def argv(pid):
    return [os.fsdecode(x) for x in Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0") if x]


def own_probe(s, parent, members, epoch, provider):
    # The check itself runs synchronously as the controller's direct child. A
    # different process checking the peer cannot claim this exception.
    me = os.getpid()
    if me not in members:
        return members
    actual = argv(me)
    s.need(epoch == 145 and os.getppid() == parent and __debug__ and sys.flags.isolated
           and len(actual) == 6 and actual[2:4] == [str(provider), "145"]
           and Path(actual[0]).resolve() == Path("/usr/bin/python3").resolve()
           and s.same_file(Path(f"/proc/{me}/exe"), Path("/usr/bin/python3"))
           and s.process(me)[2] == "0::/system.slice/" + UNIT, "foreign 145 admission probe")
    return tuple(p for p in members if p != me)


def encoded_prefix_stop(s, build, successor):
    original = "cbacb5a17e6347509640846eccb95cb0"
    proof = PKG.parent / "v5r-name-handoff" / "PREDECESSOR_STOP.json"
    stopped, reference = s.read(proof)
    s.need(stopped["schema"] == "horizon-manager-explicit-stop-witness-v1"
           and stopped["unit"] == UNIT and stopped["invocation_id"] == original
           and stopped["worker_launch_authorized"] is False
           and set(stopped["records"]) == {"stop_started", "deactivated", "stop_finished"},
           "different encoded-prefix predecessor stop")
    package = BASE / "epoch145-explicit-stop-inspector-20261124-v2" / "tools"
    seal, _ = s.read(package / "deployment-seal-receipt.json", build["stop_inspector_seal_sha256"])
    member, = (m for m in seal["members"] if m["name"] == "follow145" and m["mode"] == "0555")
    s.need(seal["destination"] == str(package) and seal["remote_mutations"] is False,
           "foreign encoded-prefix stop inspector")
    inspector = package / member["name"]
    image = inspector.lstat()
    s.need(stat.S_ISREG(image.st_mode) and image.st_uid == 0
           and image.st_nlink == 1 and stat.S_IMODE(image.st_mode) == 0o555,
           "unsealed encoded-prefix stop inspector")
    with inspector.open("rb") as stream:
        s.need(hashlib.file_digest(stream, "sha256").hexdigest() == member["sha256"],
               "changed encoded-prefix stop inspector")
    witness = json.loads(subprocess.check_output([
        str(inspector), "inspect-native-stop", original, str(stopped["not_before_monotonic_usec"]),
        successor], timeout=15))
    s.need(witness["schema"] == "horizon-manager-explicit-successor-witness-v1"
           and witness["boot_id"] == stopped["boot_id"] and witness["unit"] == UNIT
           and witness["invocation_id"] == original and witness["successor_invocation_id"] == successor
           and all(witness["records"][key] == row for key, row in stopped["records"].items()),
           "encoded-prefix successor does not follow the recorded native stop")
    return reference


def inspect(s, leased, m, members, epoch, provider, profile):
    """Return None for another image. Caller supplies its hash-pinned sealed profile."""
    pid = int(m["MainPID"])
    if pid < 2 or not IMAGE.exists() or not s.same_file(Path(f"/proc/{pid}/exe"), IMAGE):
        return None
    group = "0::/system.slice/" + UNIT
    generation = m["InvocationID"]
    s.need(s.iid(generation) and generation != OLD and m["Id"] == UNIT
           and m["ControlGroup"] == group[3:] and m["ActiveState"] == "active"
           and m["SubState"] == "running" and not m["Job"] and m["NRestarts"] == "0"
           and m["ControlPID"] == "0" and m["CPUQuotaPerSecUSec"] == "1s"
           and m["MemoryMax"] == str(2 << 30) and m["MemorySwapMax"] == "0", "foreign incident 145 controller")
    seal, seal_ref = s.read(PKG / "deployment-seal-receipt.json", profile["seal_sha256"])
    build, build_ref = s.read(PKG / "build-proof.json", profile["build_sha256"])
    image_sha = profile["image_sha256"]
    rows = {r["name"]: r["sha256"] for r in seal["members"]}
    s.need(seal["destination"] == str(PKG) and rows["export145"] == image_sha
           and rows["build-proof.json"] == build_ref["sha256"] and build["verifier_sha256"] == image_sha,
           "foreign sealed 145 image")
    with IMAGE.open("rb") as stream:
        s.need(hashlib.file_digest(stream, "sha256").hexdigest() == image_sha, "145 image bytes changed")
    f, failed = s.read(STATE / OLD / "failed.json", OLD_FAILURE)
    _, previous = s.read(STATE / OLD / "recovery-started.json", OLD_RECOVERY)
    expected_failure = f["error"] == "stopped worker fresh-census deadline" if REJOIN else "exit status: 124" in f["error"]
    if TIMEOUT_REJOIN:
        expected_failure = f["error"].rstrip().endswith("'horizon-qualify-168-full-metered-20261121-v1.service']' timed out after 10 seconds")
    if FOCUSED_REJOIN:
        expected_failure = f["error"].rstrip().endswith("ValueError: cadence publisher absent")
    if TIMER_REJOIN:
        expected_failure = f["error"].rstrip().endswith("tools-v14/retire-original-timers.py'), 'inspect']' timed out after 20 seconds")
    if FIXTURE_REJOIN:
        expected_failure = f["error"].rstrip().endswith("ValueError: unregistered replay process 227497")
    if HOMEFLOOR_REJOIN:
        expected_failure = f["error"].rstrip().endswith("ValueError: unregistered replay process 429808")
    s.need(f["iid"] == OLD and expected_failure, "foreign original failure")
    state = STATE / generation
    parent = Path(f"/proc/{pid}")
    registered = argv(pid)
    s.need(len(registered) == 5 and registered[:2] == [str(IMAGE), "recover-full-output"]
           and registered[-1] == image_sha and Path(registered[2]).name == "ROOT_COMPLETE_OPERATIONAL_FLEET.json"
           and Path(registered[2]).parent.parent == BASE and s.process(pid)[2] == group
           and ("INVOCATION_ID=" + generation).encode() in (parent / "environ").read_bytes().split(b"\0"),
           "foreign recovery command")
    s.read(Path(registered[2]), registered[3])
    ticks = s.process(pid)[1]
    fixed = (64512, 95818311)
    lm = LOCK.stat()
    s.need((lm.st_dev, lm.st_ino) == fixed and any(
        os.path.samestat(fd.stat(), lm) and any(" FLOCK " in line and " WRITE " in line
        for line in (parent / "fdinfo" / fd.name).read_text().splitlines())
        for fd in (parent / "fd").iterdir()), "145 serial owner changed")
    observed = own_probe(s, pid, members, epoch, provider)
    window = {"mode": "recover-full-output", "native_parent": {"pid": pid, "start_ticks": ticks},
              "continuity_seal": seal_ref, "continuity_build": build_ref,
              "failed_predecessor": failed, "prior_started": previous}
    if LEASE_START:
        need_failure = STATE / "f2afc696a63a4e6aa6812451cf3559e5" / "failed.json"
        _, actual = s.read(need_failure, "eff2c5c0da6cb103890f6ced5cb11920959f637234567d7fd2382a2fca2fbcc7")
        s.need(build["startup_failure"] == actual and build["child_lease_readiness_protocol"] == "self-stop-after-three-leases"
               and generation != need_failure.parent.name, "unqualified retry of the child lease failure")
        window["startup_failure"] = actual
    if MISSED_CLOCK:
        missed = STATE / "ff597d64ad37400ea5c6836336fb6706"
        _, failure = s.read(missed / "failed.json", "04eeb879aa90c3f3170e738c781f10eaf17ef44b2d8835d6f9f8f7ee29ee5fb6")
        _, recovery = s.read(missed / "recovery-started.json", "706b0986b8a3979caa083d08ac007d93905919819b50126486e738cee6977e48")
        s.need(build["missed_clock_failure"] == failure and build["previous_missed_recovery" if GUARD_WALK else "previous_recovery"] == recovery
               and generation != missed.name, "unqualified retry of the missed fleet census")
        window["missed_clock_failure"] = failure
    if GUARD_WALK:
        prior = STATE / "dba04d40f1b046b4875d7e27e0ff224a"
        _, failure = s.read(prior / "failed.json", "8a8ef5d04d44a1bb97771cef2a7e15958d721e0defc35f1e2aee0b3f55b85010")
        _, recovery = s.read(prior / "recovery-started.json", "06d2a4fa77bebe110f4d1c218bc91ec3066dc2e86f07575332d8725c1cf4e9b7")
        s.need(build["guard_walk_failure"] == failure and build["previous_recovery"] == recovery
               and build["rejected_guard"]["sha256"] == "6800d34a8bb71f468d2f06daf6a29cf9016d972f4cc1ef60d915600e8085ad1f"
               and build["registered_guard_clock"]["sha256"] == "119fdd9c0246b71fa188007daad510adc377bc002a110dda3e1074bb06d0819d"
               and generation != prior.name, "unqualified retry of the registered guard walk")
        window.update(guard_walk_failure=failure, rejected_guard=build["rejected_guard"],
                      registered_guard_clock=build["registered_guard_clock"])
    if DONOR_PRESSURE:
        prior = STATE / "f86e7e61f4b34dc7aedc4e08a128e713"
        terminal, failure = s.read(prior / "failed.json", "553c2d9be55bf4688dd1c8b42bc497ba2f6ea985305e42b7fb7db951f400bd36")
        _, recovery = s.read(prior / "recovery-started.json", "dad6a11f67b7717668c0189c607142ac89a64fc7fde8971b28b4e3c8622619ed")
        s.need(build["donor_pressure_failure"] == failure and build["donor_pressure_recovery"] == recovery
               and terminal["iid"] == prior.name and generation != prior.name
               and terminal["error"].rstrip().endswith("ValueError: insufficient HOME or general-slot memory")
               and {path.name for path in prior.iterdir()} == {"failed.json", "recovery-started.json"},
               "unqualified retry of the V5n donor pressure failure")
        window.update(donor_pressure_failure=failure, donor_pressure_recovery=recovery)
    if STATUS_OWNER_RECOVERY:
        prior = STATE / "f3474dfad55f4a05a64431421881db29"
        failed_owner, failure = s.read(prior / "failed.json", "8b5c1b7024fec2fadbfedc14b59bd80bad97d3f3e98ee30f405f78d8c1798d27")
        _, recovery = s.read(prior / "recovery-started.json", "e4b9e72a6481ea4f38b8fe7b49986463e2f93d37bc1dcb7f2156049930fd744b")
        stop, terminal = s.read(BASE / "epoch145-semantic-continuity-20261121-v1"
            / "f3474dfa-stopped-status-owner-20261123" / "TERMINAL.json",
            "95fc24c89db925ca86fa1f918a6f61e665d3c124a7e4687ecf8ee44816b01f6f")
        s.need(build["status_owner_failure"] == failure and build["status_owner_recovery"] == recovery
               and build["status_owner_terminal"] == terminal
               and failed_owner["iid"] == stop["invocation_id"] == prior.name and generation != prior.name
               and stop["failure"] == failure and stop["startup"] == recovery
               and failed_owner["error"].rstrip().endswith("ValueError: different status writer invocation")
               and {path.name for path in prior.iterdir()} == {"failed.json", "recovery-started.json"},
               "unqualified retry of the V5o status-owner failure")
        window.update(status_owner_failure=failure, status_owner_recovery=recovery, status_owner_terminal=terminal)
    if AUDIT_TURNOVER_RECOVERY:
        prior = STATE / "c01dc3ba08b74e3aa0d4b531601e9fda"
        stop, terminal = s.read(BASE / "epoch145-semantic-continuity-20261121-v1"
            / "c01dc3ba-stopped-public-audit-turnover-20261124" / "TERMINAL.json",
            "abda107d59f55823a92d3609cbc142dec21e7e63337d9b495f6f070dfe04de24")
        _, failure = s.read(prior / "failed.json", stop["failure"]["sha256"])
        _, recovery = s.read(prior / "recovery-started.json", stop["startup"]["sha256"])
        s.need(build["public_audit_terminal"] == terminal and stop["failure"] == failure
               and stop["startup"] == recovery and stop["invocation_id"] == prior.name
               and stop["source_checkpoint_exists"] is False and generation != prior.name
               and {path.name for path in prior.iterdir()} == {"failed.json", "recovery-started.json"},
               "unqualified retry of the V5p audit turnover failure")
        window["public_audit_terminal"] = terminal
    if ENCODED_PREFIX_RECOVERY:
        window["encoded_prefix_predecessor_stop"] = encoded_prefix_stop(s, build, generation)
    if observed == (pid,):
        s.need(epoch == 145 and os.getpid() in members, "145 participant has no leased child")
        return {"invocation_id": generation, "stage": "controller", "window": window}
    s.need(len(observed) == 2 and pid in observed, "foreign 145 descendants")
    child = next(p for p in observed if p != pid)
    pp, ct, pg = s.process(child)
    cp = Path(f"/proc/{child}")
    s.need((pp, pg) == (pid, group) and s.same_file(cp / "exe", IMAGE)
           and argv(child) == [str(IMAGE), "recover-worker", str(pid), image_sha]
           and ("INVOCATION_ID=" + generation).encode() in (cp / "environ").read_bytes().split(b"\0"),
           "foreign recovery worker")
    started, started_ref = s.read(state / "recovery-started.json")
    if HOMEFLOOR_REJOIN:
        started_fit = started["fresh_fit"]
        s.need(started_fit["schema"] == "horizon-incident-replay-fit-v1"
               and started_fit["epoch"] == 145 and started_fit["fits"]
               and started_fit["phase145"]["invocation_id"] == generation
               and started_fit["phase145"]["stage"] == "controller"
               and started_fit["phase145"]["window"]["native_parent"] == window["native_parent"]
               and started_fit["phase145"]["window"]["failed_predecessor"] == failed
               and started_fit["provider_seal"]["path"] == str(BASE / "incident-replay-fit-20261121-v1"
                   / HOMEFLOOR_PROVIDER / "deployment-seal-receipt.json"), "foreign 145 pre-worker admission")
    if STATUS_OWNER_RECOVERY:
        s.need(started_fit["status_registration"] == build["resumed_status"]
               and all(started_fit["phase145"]["window"][key] == window[key] for key in
                       ("status_owner_failure", "status_owner_recovery", "status_owner_terminal")),
               "foreign status-owner pre-worker admission")
    if AUDIT_TURNOVER_RECOVERY:
        s.need(started_fit["phase145"]["window"]["public_audit_terminal"] == window["public_audit_terminal"],
               "foreign audit turnover pre-worker admission")
    if ENCODED_PREFIX_RECOVERY:
        s.need(started_fit["phase145"]["window"]["encoded_prefix_predecessor_stop"]
               == window["encoded_prefix_predecessor_stop"], "foreign encoded-prefix pre-worker admission")
    predecessor = ("failed_manager_query" if TIMEOUT_REJOIN else
                   "failed_fresh_census" if REJOIN else "failed_preincident_verifier")
    if FOCUSED_REJOIN:
        predecessor = "failed_status_owner"
    if TIMER_REJOIN:
        predecessor = "failed_timer_inspection"
    if FIXTURE_REJOIN:
        predecessor = "failed_qualification_census"
    if HOMEFLOOR_REJOIN:
        predecessor = "failed_retry1"
    s.need(started["iid"] == generation and started["image"] == image_sha
           and started["r2_mutations"] is False and started["file"] == str(OUTPUT)
           and started["prior_frozen_recovery"][predecessor]["current_boot_failure"]["failure"] == failed
           and not any((state / n).exists() for n in ("failed.json", "complete.json", "verified-frozen.json")),
           "145 left its native frozen read phase")
    objects = {}
    for path, ino, size in ((SOURCE, 100214450, 105633748687), (MANIFEST, 100214429, 1809),
                            (OUTPUT, 103237059, 105610995833)):
        m = path.lstat()
        s.need(path.resolve(strict=True) == path and stat.S_ISREG(m.st_mode)
               and (m.st_dev, m.st_ino, m.st_size, m.st_nlink, m.st_uid, m.st_gid, stat.S_IMODE(m.st_mode))
               == (64512, ino, size, 1, 0, 0, 0o400), "different leased 145 file")
        objects[(64512, ino)] = str(path)
    window.update(native_child={"pid": child, "start_ticks": ct}, recovery=started_ref,
                  leases_parent=leased(pid, objects), leases_worker=leased(child, objects))
    s.need(s.process(pid)[1:] == (ticks, group) and s.process(child) == (pid, ct, group),
           "145 phase changed during capture")
    return {"invocation_id": generation, "stage": "leased-worker", "window": window}
