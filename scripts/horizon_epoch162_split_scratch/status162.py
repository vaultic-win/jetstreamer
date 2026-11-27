"""Join one private epoch 162 split-scratch producer to the established cadence and fleet price."""

import hashlib
import json
import re
import runpy
import stat
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace

PKG = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch162-first-hourly-completion-20261127-v2/issued-split-v1")
FIELD = "current_private162_split_completion"
SUCCESS = "7ad2d189f7e94e70a38c781354912448"
FAILURE = "98e322203f7a4ed290d09fe03c09fe15"


def api():
    """The writer copies this adapter and pins the operator seal alongside it."""
    seal = PKG / "deployment-seal-receipt.json"

    def frozen(p):
        st = p.lstat()
        if not (
            p.resolve() == p
            and stat.S_ISREG(st.st_mode)
            and st.st_uid == 0
            and not st.st_mode & 0o222
            and st.st_nlink == 1
        ):
            raise ValueError("unsealed 162 module " + str(p))
        return p.read_bytes()

    raw = frozen(seal)
    source = Path(__file__).resolve()
    if source.parent != PKG:
        spec = json.loads(frozen(source.parent / "split162_provider.json"))
        if spec != {"path": str(seal), "sha256": hashlib.sha256(raw).hexdigest()}:
            raise ValueError("changed split162 operator seal")
    record = json.loads(raw)
    if record["destination"] != str(PKG):
        raise ValueError("foreign 162 operator")
    members = {m["name"]: m for m in record["members"]}
    for f in (source, PKG / "layout.py"):
        if hashlib.sha256(frozen(f)).hexdigest() != members[f.name]["sha256"]:
            raise ValueError("unsealed 162 " + f.name)
    return SimpleNamespace(**runpy.run_path(str(PKG / "layout.py")))


def active(row):
    return bool(row and row["phase"] != "terminal")


def owner(plan, props, held, layout):
    iid, pid = held["producer_invocation_id"], held["producer_pid"]
    layout.need(
        re.fullmatch(r"[0-9a-f]{32}", iid)
        and int(iid, 16)
        and 1 < pid
        and props["Id"] == layout.UNIT
        and props["ActiveState"] == "active"
        and props["SubState"] == "running"
        and not props["Job"]
        and props["InvocationID"] == iid
        and props["MainPID"] == str(pid)
        and props["ControlGroup"] == layout.GROUP
        and props["MemoryMax"] == str(plan["producer_memory_max"])
        and props["MemorySwapMax"] == "0"
        and props["CPUQuotaPerSecUSec"] == "2s"
        and layout.ticks(pid) == held["start_ticks"]
        and held["boot_id"] == layout.BOOT.read_text().strip(),
        "foreign 162 producer or cgroup",
    )
    return iid, pid


def native_end(l, actor):
    iid = actor["producer_invocation_id"]
    rows = subprocess.check_output(
        [
            "/usr/bin/journalctl",
            "-q",
            "--no-pager",
            "-o",
            "json",
            "_UID=0",
            "_PID=1",
            "_BOOT_ID=" + actor["boot_id"].replace("-", ""),
            "UNIT=" + l.UNIT,
            "INVOCATION_ID=" + iid,
        ],
        text=True,
        timeout=15,
    )
    matches = [r for line in rows.splitlines() if (r := json.loads(line)).get("MESSAGE_ID") in (SUCCESS, FAILURE)]
    errors = [r for r in matches if r["MESSAGE_ID"] == FAILURE and r.get("COMMAND") == "ExecStart"]
    if errors:
        matches = errors
    l.need(matches and not l.CGROUP.exists(), "162 terminal lacks PID1 closure or a clean cgroup drain")
    return {
        k: matches[-1][k]
        for k in ("__CURSOR", "__REALTIME_TIMESTAMP", "MESSAGE_ID", "MESSAGE", "EXIT_CODE", "EXIT_STATUS")
        if k in matches[-1]
    }


def last_guard(l, actor, require_recent=True):
    intent = l.bound(actor["guard_plan"])
    files = sorted(l.GUARDS.glob("sample-*.json"), key=lambda p: p.stat().st_mtime_ns, reverse=True)
    for path in files[:6]:
        s, ref = l.pinned(path)
        if s["producer_invocation_id"] != actor["producer_invocation_id"]:
            continue
        physical = s["root_physical_observation"]
        l.need(
            s["guard_sha256"] == l.GUARD_SHA
            and s["producer_stop_enabled"]
            and s["trip_reason"] is None
            and s["plan_sha256"] == actor["guard_plan"]["sha256"]
            and s["producer"]["pid"] == actor["producer_pid"]
            and not s["root_physical_observation_error"]
            and not s["worker_observation_error"]
            and not physical["exceeds_budget"]
            and s["minimum_free_bytes"] == intent["minimum_free_bytes"] <= s["available_bytes"]
            and intent == l.guard_plan(actor["producer_invocation_id"], intent["minimum_free_bytes"])
            and (not require_recent or 0 <= time.time() - s["recorded_unix_seconds"] <= 90),
            "162 lost its guard",
        )
        l.need(
            l.manager(l.TIMER)["InvocationID"] == actor["guard_timer_invocation_id"]
            and l.manager(l.TIMER)["ActiveState"] == "active",
            "162 guard timer changed",
        )
        return s, ref, intent
    raise ValueError("162 lacks an invocation-bound guard sample")


def current(fleet):
    l = api()
    props = l.manager(l.UNIT)
    old = fleet.get(FIELD)
    historical = fleet.get("current_private162_first_hourly")
    l.need(
        historical
        and historical["phase"] == "terminal"
        and historical["actor"]["producer_invocation_id"]
        == historical["native_terminal"]["INVOCATION_ID"]
        == "91cf839d57a1464a9444f5f51c349c40"
        and historical["held_owner"]["sha256"] == "8b4dbb7c8db646bb07cfaea7db4d5c1f107150aa90ad920c7cd8e4657862e31a"
        and historical["release"]["sha256"] == "5ac3edb870f44508560cdf58255be2f91bddad84e2e651e6d2da011c38617679",
        "missing original epoch 162 terminal",
    )
    registered = [r for r in fleet["actual_active_private_diagnostics"] if r["epoch"] == 162]
    l.need(
        not any(r["epoch"] == 162 for r in fleet["actual_active_bootstraps"] + fleet["actual_executing_replays"])
        and (registered == [old] if active(old) else not registered),
        "multiple or inconsistent 162 assignments",
    )
    idle = props["ActiveState"] in ("inactive", "failed") and props["MainPID"] == "0" and not props["Job"]
    held_file = l.DATA / "HELD_OWNER.json"
    if not held_file.exists():
        l.need(
            idle
            and not l.CGROUP.exists()
            and not old
            and not (l.DATA / "GRANT.json").exists()
            and not l.ALLOW.exists(),
            "unidentified 162 actor before first guard",
        )
        return None
    held, held_ref = l.pinned(held_file)
    pre = l.bound(held["intent"])
    q = l.bound(pre["prestart"])
    slot = q["scratch_gib"]
    plan = l.profile(slot)
    l.need(
        held["producer_unit"] == l.UNIT
        and pre["profile"] == plan
        and q["profile"] == plan
        and q["donor"] == {"path": str(l.DONOR), "sha256": l.DONOR_SHA}
        and (not old or old["held_owner"] == held_ref),
        "different 162 admission or predecessor",
    )
    common = dict(
        epoch=162,
        unit=props,
        actor=held,
        held_owner=held_ref,
        producer_invocation_id=held["producer_invocation_id"],
        profile=plan,
        donor=q["donor"],
        terminal=None,
        native_diagnostic=None,
        observer_config=None,
        worker=None,
        resource_credit_bytes=0,
        archive_publication_authorized=False,
        canonical_replay_claimed=False,
        transaction_replay_claimed=False,
    )
    if idle:
        return dict(common, phase="terminal", terminal=native_end(l, held))
    iid, pid = owner(plan, props, held, l)
    node = Path(l.scope()["node"]["path"])
    held_gate = Path(f"/proc/{pid}/exe").samefile(l.GATE)
    grant = None
    if not held_gate:
        released, grant = l.pinned(l.DATA / "GRANT.json")
        l.need(
            Path(f"/proc/{pid}/exe").samefile(node)
            and released["held"] == held_ref
            and l.bound(released["postguard"])["held_invocation"] == iid
            and l.ALLOW.read_bytes() == iid.encode(),
            "different 162 release or executable",
        )
    guard, ref, guard_plan = last_guard(l, held)
    children = []
    for p in sorted(int(x) for x in (l.CGROUP / "cgroup.procs").read_text().split() if int(x) != pid):
        exe = Path(f"/proc/{p}/exe")
        name = exe.readlink()
        l.need(
            name.name == "historical-worker"
            and name.is_relative_to(l.RUN / "scratch")
            and l.digest(exe) == l.scope()["capped_worker"]["sha256"],
            "unsealed 162 worker",
        )
        children.append(dict(pid=p, start_ticks=l.ticks(p), path=str(name)))
    l.need(
        len(children) <= 1 and (not held_gate or not children) and len(guard["workers"]) <= 1,
        "unexpected worker census for 162",
    )
    worker = (
        children[0]
        if children and any(p == children[0]["pid"] and 0 < n <= 3500000 for p, n in guard["workers"])
        else None
    )
    if guard["workers"]:
        l.need(worker, "162 worker changed across its guard")
    mounts = l.verify_mounts(pid, slot, held["mounts"]["image"], l.scope()["profile"]["readonly_projections"])
    l.need(mounts == held["mounts"], "162 mount changed after hold")
    # Only the host image can grow. The single data file has a kernel-enforced
    # length. Keep the full control allowance across all phases and guard samples.
    alloc = l.IMAGE.stat().st_blocks * 512
    l.need(0 <= alloc <= l.HOME_IMAGE + l.CONTROL and l.identity(l.IMAGE)[:3] == mounts["image"], "162 image changed")
    disk = dict(
        floor=guard_plan["minimum_free_bytes"],
        maximum=l.HOME_IMAGE,
        remaining=max(0, l.HOME_IMAGE - alloc),
        fixed_control=l.CONTROL,
    )
    return dict(
        common,
        phase="held" if held_gate else "worker" if worker else "bootstrap",
        worker=worker,
        guard=ref,
        guard_plan=held["guard_plan"],
        release=grant,
        mounts=mounts,
        disk=disk,
    )


def recheck(fleet, row):
    now = current(fleet)
    if row is None or now is None:
        if row is not now:
            raise ValueError("162 crossed enrollment")
        return
    for key in ("phase", "unit", "held_owner", "worker", "profile", "mounts", "donor", "terminal"):
        if now.get(key) != row.get(key):
            raise ValueError("changed 162 identity " + key)


def assignment(l, row):
    return dict(
        range="162",
        producer_unit=l.UNIT,
        controller_unit=l.UNIT,
        expected_producer_invocation_id=row["producer_invocation_id"],
        expected_controller_invocation_id=row["producer_invocation_id"],
        scratch_path=str(l.RUN / "scratch"),
        worker_executable_basename="historical-worker",
    )


def observe(c, observed_lane):
    l, row = api(), current(c.fleet)
    cfg = [r for r in c.cfg["diagnostic_replays"] if r["range"] == "162"]
    result = [r for r in c.sample["diagnostic_replays"] if r["range"] == "162"]
    l.need(len(cfg) == len(result) <= 1 and (row or not cfg), "unbound or duplicate 162 sample")
    if row is None:
        return None
    row["observer"] = c.sample_ref
    if row["worker"]:
        row["observer_config"] = assignment(l, row)
    if cfg:
        prev = c.fleet[FIELD]
        req, sample = cfg[0], result[0]
        l.need(
            req == prev["observer_config"] == assignment(l, row)
            and sample["producer_unit"] == l.UNIT
            and sample["expected_producer_invocation_id"] == row["producer_invocation_id"]
            and sample["status"] in ("observed", "unavailable")
            and not sample["ordinary_replay_claim"]
            and not sample["publication_authorized"]
            and not sample["r2_mutations"],
            "wrong 162 sample",
        )
        row["native_diagnostic"] = sample
        if row["worker"] and sample["status"] == "observed":
            obs = sample["observation"]
            l.need(
                all(
                    obs[k]["pid"] == row["worker"]["pid"] and obs[k]["executable"] == row["worker"]["path"]
                    for k in ("worker_before", "worker_after")
                ),
                "162 sample changed workers",
            )
            row["transaction_replay_claimed"] = bool(
                observed_lane(obs, req, row["producer_invocation_id"], row["actor"]["producer_pid"])
            )
    return row


def project(c, row):
    cfg = [r for r in c.next_cfg["diagnostic_replays"] if r["range"] != "162"]
    if active(row) and row["observer_config"]:
        cfg.append(row["observer_config"])
    c.next_cfg["diagnostic_replays"] = cfg


def install(fleet, row):
    if row is None:
        return
    if active(row):
        if any(
            r["epoch"] == 162
            for r in fleet["actual_active_private_diagnostics"]
            + fleet["actual_executing_replays"]
            + fleet["actual_active_bootstraps"]
        ):
            raise ValueError("162 already counted")
        fleet["actual_active_private_diagnostics"].append(row)
        fleet["active_private_diagnostic_count"] += 1
        fleet["active_producer_count"] += 1
    fleet[FIELD] = row
    (entry,) = [r for r in fleet["epochs"] if r["epoch"] == 162]
    entry.update(
        current_private_diagnostic=row,
        current_status_scope="Private epoch 162 capped-worker interval " + row["phase"] + ".",
    )


def status_fields(row):
    return dict(
        private162_split_phase=row["phase"],
        private162_split_held=row["held_owner"],
        private162_split_guard=row.get("guard"),
        private162_split_terminal=row["terminal"],
        private_transaction_progress=row["transaction_replay_claimed"],
        private162_canonical_progress=False,
    )
