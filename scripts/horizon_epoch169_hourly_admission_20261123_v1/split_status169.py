"""Observe the private hourly 169 actor on the sole existing fleet clock."""
import hashlib
import json
import os
from pathlib import Path
import runpy

HERE = Path(__file__).resolve().parent
BASE = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch169-hourly-admission-20261123-v1")
PROVIDER = BASE / "issued-split-v1"
FIELD = "current_private169_hourly"
UNIT = "horizon-qualify-169-focused-hourly-20261123-v1.service"
LOG = Path("/home/sol/.jetstreamer-private/epoch169-hourly-source-20261123-v1/hourly-run/producer.log")


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def reader():
    spec = json.loads((HERE / "split169_provider.json").read_bytes())
    seal_file = PROVIDER / "deployment-seal-receipt.json"
    raw = seal_file.read_bytes()
    need(spec == {"path": str(seal_file), "sha256": hashlib.sha256(raw).hexdigest()}
         and seal_file.lstat().st_uid == 0 and not seal_file.lstat().st_mode & 0o222,
         "different 169 operator")
    seal = json.loads(raw)
    need(seal["destination"] == str(PROVIDER), "169 operator at foreign location")
    members = {m["name"]: m for m in seal["members"]}
    for name in ("split_actor.py", "actor.py", "scratch_mount.py", "watch.py"):
        file = PROVIDER / name
        st = file.lstat()
        need(file.resolve() == file and st.st_uid == 0 and not st.st_mode & 0o222 and st.st_nlink == 1
             and st.st_size == members[name]["bytes"] and hashlib.sha256(file.read_bytes()).hexdigest() == members[name]["sha256"],
             "unsealed private 169 receiver dependency")
    return runpy.run_path(str(PROVIDER / "split_actor.py"))


def active(row):
    return bool(row and row["phase"] != "terminal")


def accept_assignment(row):
    need(row["range"] == "169" and row["producer_unit"] == row["controller_unit"] == UNIT
         and row["expected_producer_invocation_id"] == row["expected_controller_invocation_id"]
         and row["scratch_path"] == str(LOG.parent.parent / "v158/scratch")
         and row["worker_executable_basename"] == "historical-worker"
         and row["append_log"]["path"] == str(LOG), "unregistered private 169 observer configuration")
    return row


def observe(c, observed_lane):
    native = reader()
    row = native["current"](c.fleet)
    prior = c.fleet.get(FIELD)
    assigned = [r for r in c.cfg["diagnostic_replays"] if r["range"] == "169"]
    seen = [r for r in c.sample["diagnostic_replays"] if r["range"] == "169"]
    need(len(assigned) == len(seen) <= 1, "duplicate or missing native 169 sample")
    if not row:
        need(not assigned and not prior, "169 enrollment or scheduled sample lost its native owner")
        return None
    if prior:
        need(prior["hourly169_start_intent"] == row["hourly169_start_intent"]
             and (prior["phase"] != "terminal" or row["phase"] == "terminal" and prior["terminal"] == row["terminal"]),
             "169 changed its registered predecessor")
    iid = row["unit"]["InvocationID"] if active(row) else row["invocation_id"]
    row.update(observer=c.sample_ref, observer_config=None, worker=None, native_diagnostic=None,
               transaction_replay_claimed=False, reservation_ending_bytes=0)
    if active(row):
        pid = row["processes"][0][0]
        row["actor"] = {"producer_pid": pid, "producer_invocation_id": iid}
        if row["phase"] != "held":
            grant, ref = native["receipt"](BASE / "GRANT.json")
            need(grant["invocation_id"] == iid and grant["pid"] == pid and
                 grant["private_scratch_mount"] == row["binding"]["private_scratch_mount"] and not grant["canonical_publication_authorized"],
                 "ungated or foreign 169 payload")
            row["release"] = ref
        if row["phase"] == "worker":
            child, ticks, device, inode = row["processes"][1]
            child_image = Path("/proc") / str(child) / "exe"
            need(os.path.samestat(LOG.stat(), (Path("/proc") / str(pid) / "fd/1").stat())
                 and (LOG.stat().st_dev, LOG.stat().st_ino) == (grant["log_device"], grant["log_inode"]), "169 append log detached")
            row["worker"] = dict(pid=child, start_ticks=ticks, path=str(child_image.readlink()), device=device, inode=inode)
            row["observer_config"] = accept_assignment(dict(range="169", producer_unit=UNIT, controller_unit=UNIT,
                expected_producer_invocation_id=iid, expected_controller_invocation_id=iid,
                scratch_path=row["binding"]["private_scratch_mount"]["path"], worker_executable_basename="historical-worker",
                append_log=dict(path=str(LOG), device=grant["log_device"], inode=grant["log_inode"])))
    if assigned:
        expected = accept_assignment(assigned[0])
        result = seen[0]
        need(prior and prior["observer_config"] == expected and result["producer_unit"] == UNIT
             and result["expected_producer_invocation_id"] == iid and result["status"] in ("observed", "unavailable")
             and result["scratch_path"] == expected["scratch_path"]
             and result["ordinary_replay_claim"] is result["publication_authorized"] is result["r2_mutations"] is False,
             "different 169 sampled owner")
        row["native_diagnostic"] = result
        if row["phase"] == "worker" and result["status"] == "observed":
            sample = result["observation"]
            need(row["observer_config"] == expected and all(sample[k]["pid"] == row["worker"]["pid"]
                 and sample[k]["executable"] == row["worker"]["path"] for k in ("worker_before", "worker_after")), "169 switched workers")
            row["transaction_replay_claimed"] = observed_lane(sample, expected, iid, row["actor"]["producer_pid"])
    return row


def project(c, row):
    configured = [r for r in c.next_cfg["diagnostic_replays"] if r["range"] != "169"]
    if row and row["observer_config"]:
        configured.append(accept_assignment(row["observer_config"]))
    c.next_cfg["diagnostic_replays"] = configured


def install(fleet, row):
    if not row:
        return
    need(not any(r["epoch"] == 169 for r in fleet["actual_active_private_diagnostics"] +
                 fleet["actual_executing_replays"] + fleet["actual_active_bootstraps"]), "169 is already counted")
    fleet[FIELD] = row
    if active(row):
        fleet["actual_active_private_diagnostics"].append(row)
        fleet["active_private_diagnostic_count"] += 1
        fleet["active_producer_count"] += 1
    entry, = (r for r in fleet["epochs"] if r["epoch"] == 169)
    entry.update(current_private_diagnostic=row, current_status_scope="Hourly private epoch 169 " + row["phase"] + ". Canonical repair remains open.")


def status_fields(row):
    return dict(private169_hourly_phase=row["phase"], hourly169_start_intent=row["hourly169_start_intent"],
                private169_guard=row.get("guard"), private169_terminal=row.get("terminal"),
                private_transaction_progress=row["transaction_replay_claimed"], hourly169_canonical_progress=False)


def verification(fleet):
    reader()
    spec = runpy.run_path(str(PROVIDER / "split_capacity.py"))
    return spec["verification168"](fleet["retry9_auxiliary_commitments"])
