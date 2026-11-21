"""Attach the native epoch 166 disposition to the existing fleet/status publisher."""
import json
import subprocess
from pathlib import Path

from evidence import BASE, bound, checked, need, sealed

PACKAGE = BASE / "epoch166-terminal-20261121-v1/cadence-tools-v2"
SHA = "6bc61b775d8c5ad46f52938405388bac84f7faf0e079b6be906eda6d5de6913c"
SEAL = "9c6e1cdf403ed5921f516b8ca9714ff54bd08b052b695fd253b1eafe31362025"
TERMINAL = PACKAGE.parent / "TERMINAL_SUCCESS.json"
FIELD = "terminal166_local_commit"


def native_config(c):
    """Read the registered/effective config that produced this particular native sample."""
    config_ref = c.fleet["sole_next_observer"]
    package_ref = bound(PACKAGE / "deployment-seal-receipt.json")
    need(package_ref["sha256"] == SEAL and bound(PACKAGE / "terminal166")["sha256"] == SHA,
         "epoch 166 sampler artifact changed")
    result = json.loads(subprocess.check_output(
        [PACKAGE / "terminal166", "inspect-cadence", config_ref["path"]], timeout=60))
    fields = [r["range"] for r in c.sample["replays"]]
    if result["mode"] == "original":
        need(result["config"] == config_ref and "166" in fields and FIELD not in c.fleet,
             "incumbent 166 missing from sample or previously closed")
        return None
    need(result["mode"] == "closed" and len(fields) == 3 and set(fields) == {"167", "170", "172"},
         "local completion needs a fresh three-replay sample")
    if "selection" in result:
        choice = result["selection"]
        stage = Path(config_ref["path"]).parent.parent / "after-166"
        need(checked(bound(stage / "selection.json")) == choice and
             choice["predecessor_fleet"] == c.fleet_ref and choice["original"] == config_ref and
             choice["previous_sample"] == c.fleet["observer"] and choice["output"] == c.sample_ref["path"],
             "native 166 selection belongs to a different sample")
        c.cfg = sealed(bound(stage / "sealed-next/observer.json"))
        need(c.cfg == result["projected_config"], "effective native selection changed")
        terminal = choice["terminal"]
    else:
        terminal = result["terminal"]
        need(terminal == c.fleet.get(FIELD) and result["config"] == config_ref["path"],
             "wrong terminal 166 successor lineage")
    need(terminal == bound(TERMINAL), "changed 166 local publication receipt")
    return terminal


def owner_view(fleet, disposition):
    if disposition is None:
        return fleet
    rows = [r for r in fleet["actual_executing_replays"] if r["epoch"] != 166]
    return dict(fleet, actual_executing_replays=rows, **{FIELD: disposition})


def status_after(c, old, age):
    terminal = checked(c.terminal166)
    archive = terminal["local_archive"]
    need(terminal["epoch"] == 166 and terminal["resource_credit_bytes"] == 0 and
         not terminal["canonical_r2_verified"] and archive["size"] > 0 and age >= 0,
         "incomplete local 166 publication")
    remain = old["estimated_remaining_millis"] - age
    if old["phase"] == "replay":
        # The existing replay forecast includes a 12-hour delivery allowance.
        finished = int(terminal["manager_terminal"]["__REALTIME_TIMESTAMP"]) // 1000
        measured = round(c.now.timestamp() * 1000)
        need(finished <= measured, "native 166 sample clock precedes the local commit")
        remain = max(remain, finished + 12 * 3600_000 - measured)
    need(remain > 0, "local 166 delivery forecast expired; reconcile current verification phase")
    return (dict(old, phase="verification", jet_size_bytes=archive["size"], sampled_at_utc=c.stamp,
                 elapsed_execution_millis=old["elapsed_execution_millis"] + age,
                 estimated_remaining_millis=remain), archive)


def attach(fleet, c):
    if c.terminal166 is None:
        return
    fleet[FIELD] = c.terminal166
    previous = next((r for r in c.fleet["actual_executing_replays"] if r["epoch"] == 166), None)
    if previous is not None:
        fleet["historical166_before_local_commit"] = previous
    row = next(r for r in fleet["epochs"] if r["epoch"] == 166)
    row.pop("current_replay", None)
    row.update(current_repair_owner="/root", no_live_producer_claimed=True, state="verification",
               repair_open=True, terminal166_local_commit=c.terminal166,
               current_status_scope="Original cohort committed the local archive. Full, plugin and R2 delivery checks are pending.")
