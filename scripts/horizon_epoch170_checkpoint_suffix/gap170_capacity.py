"""Authenticate the independent gap in both complete native censuses; its original tree stays charged."""
import hashlib
from pathlib import Path
import stat
import sys

RT = Path("/var/lib/jetstreamer/horizon_runtime_data")
ROOT = RT / "epoch170-from-73760367-20261128-v1"
UNIT = "horizon-qualify-170-from-73760367-20261128-v1.service"
OBSERVER_SEAL = "65e86ab5373da6f4d177115898c096ed62fe1819df3945faf9022c975f56beb1"
EXTRA_HOME = 2_144_617_297 + (128 << 20)


def receiver(core):
    directory = ROOT / "observer-modules-v1"
    seal, _ = core.read(directory / "deployment-seal-receipt.json", OBSERVER_SEAL)
    core.need(seal["destination"] == str(directory), "different gap observer")
    support = RT / "prefix140-status-cadence-20261122-v1/cadence-tools"
    writer = RT / "survivor172-cadence-20261122-v1/tools-cold168-retry5-failed166-v52-entry146"
    sources = {directory / row["name"]: row["sha256"] for row in seal["members"]}
    core.need(set(sources) == {directory / name for name in ("gap170_status.py", "gap170_contract.py", "gap170_native.py")},
              "incomplete gap observer package")
    sources.update({
        writer / "bridge170_status.py": "555f65b5f255c123cc2d6be4a85211d5102297086f63c7287c87308ac57e18e0",
        writer / "bounded167_admission.py": "765935bd063d74b4aca3f3fe148dce72521b3749a787e77e10d8dbb680ddce9d",
        support / "evidence.py": "64cf122f5ef5651da18b66a2d6a262201f0ea60fba5bf1b1b80b657d3d528912",
    })
    for path, digest in sources.items():
        st = path.lstat()
        core.need(path.resolve(strict=True) == path
                  and stat.S_ISREG(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o222
                  and hashlib.sha256(path.read_bytes()).hexdigest() == digest,
                  "different sealed gap observer " + str(path))
    sys.path[:0] = [str(directory), str(writer), str(support)]
    try:
        import gap170_status as callback
    finally:
        del sys.path[:3]
    core.need(all(Path(sys.modules[path.stem].__file__) == path for path in sources),
              "foreign independently checked receiver")
    return callback


def owner(core, fleet):
    callback = receiver(core)
    callback.contract.stopped_owner(fleet)
    gap = callback.gap
    if not gap.ACTOR.exists():
        gap.native.idle(UNIT)
        core.need(not gap.RELEASE.exists() and not gap.ENROLLMENT.exists()
                  and not (ROOT / "ACTUAL_GUARD_PLAN.json").exists(), "gap authority without an actor")
        return None
    ref, actor = gap.read_actor()
    manager = gap.native.props(UNIT, gap.PROPS)
    if manager["ActiveState"] in ("inactive", "failed"):
        gap.terminal(actor)
        return None
    scope = callback.interface()
    grant_ref, grant = gap.release(scope, ref, actor, callback.contract.checkpoint(scope))
    processes, worker, phase = gap.live(scope, manager, actor, grant is not None)
    plan_file = Path(scope["plan_path"])
    if phase != "held":
        gap.guard(scope, actor, worker, grant)
    if grant:
        core.need(grant["independent_checkpoint"] == callback.contract.CHECKPOINT, "foreign gap permit")
    return dict(unit=UNIT, invocation=actor["producer_invocation_id"], actor=ref,
                pid=actor["producer_pid"], processes=processes, phase=phase,
                guard_plan=core.read(plan_file)[1] if plan_file.exists() else None,
                release=grant_ref)


def debit(core, native):
    # The third guard remains armed. The GCS copy and evidence live outside its
    # whole-tree cap. Charge them even if the historical sample already includes them.
    old = native["stopped_169_compute_handoff"]
    start = core.bound(old["start"])
    donor_file = RT / "epoch159-bounded-reference-20261123-v1/HEAD131757-132005-donor.json"
    donor, donor_ref = core.read(donor_file, "0341586ebc5fd04e0f354fc3081774fdc1d952558dc456542cb79599f4ff6b62")
    loan = start["actor_cpu_micros"] - donor["charged_reference"]["cpu_cores"] * 1_000_000
    core.need(loan == 1_000_000 and donor["producer_cores_retained"] == 1
              and start["guard_cpu_micros"] == 1_000_000 and old["available_producer_ram"] == 20 << 30,
              "no separate capacity for the original epoch 170 guard")
    native.update(required_home=native["required_home"] + EXTRA_HOME,
                  home_margin=native["home_margin"] - EXTRA_HOME,
                  historical_home_margin=native["historical_home_margin"] - EXTRA_HOME,
                  required_ram=native["required_ram"] + (1 << 30),
                  ram_margin=native["ram_margin"] - (1 << 30),
                  independent_gap_funding=dict(retained_old_guard_ram=1 << 30, new_guard_cpu_micros=loan,
                                               cpu_donor=donor_ref, additional_HOME=EXTRA_HOME))
