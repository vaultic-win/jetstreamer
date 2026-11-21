"""Consume the original 168 mismatch and keep its private reservation."""
from pathlib import Path
from evidence import BASE, bound, checked, need, pair

FIELD = "terminal168_trace_mismatch"
PREVIOUS = pair(BASE/"root074959-live166167170-20261121-v1/ROOT_COMPLETE_OPERATIONAL_FLEET.json",
                "c9ecc50696094fd64eee58bf447dcb9769d2ed5f6a46e82c0eee0f79d52b3e7d")
SAMPLE = pair(BASE/"sample-root081959-live166167170-20261121-v1.json",
              "b81eb3cdf50e37a0a95bd233f9d4b0b20c7e5de770d4bea8141dbe27e5a5d42d")
TERMINAL = pair(BASE/"epoch168-terminal-trace-20261121-v1/TERMINAL.json", "29672efbaff97d23a9a9d45a824840cb2d4cf43c6f5e8427ed3b532b41a38de2")


def prior(f):
    if FIELD not in f:
        return False
    need(f[FIELD] == TERMINAL and not any(r["epoch"] == 168 for r in f["actual_active_private_diagnostics"]),
         "foreign 168 closure or active private row")
    checked(TERMINAL)
    return True


def owner_view(c, owners):
    first = c.sample_ref == SAMPLE
    if not first and not prior(c.fleet):
        return owners
    from owners import DIAG_IID, DIAG_REF, DIAG_UNIT
    terminal = checked(TERMINAL)
    need(terminal["epoch"] == 168 and terminal["unit"] == DIAG_UNIT and terminal["invocation"] == DIAG_IID
         and terminal["admission"] == DIAG_REF and terminal["previous_fleet"] == PREVIOUS and terminal["sample"] == SAMPLE
         and terminal["terminal_before_routine_sample"] and terminal["resource_credit_bytes"] == 0
         and not any(terminal[k] for k in ("forecast_authority", "archive_verified", "archive_publication_authorized", "r2_mutations")),
         "foreign 168 terminal receipt")
    if first:
        need(c.fleet_ref == PREVIOUS and FIELD not in c.fleet, "168 closure belongs to another predecessor")
        rows = [r for r in owners["actual_active_private_diagnostics"] if r["epoch"] == 168]
        need(len(rows) == 1 and rows[0]["admission"] == DIAG_REF and
             rows[0]["unit"]["InvocationID"] == DIAG_IID and rows[0]["unit"]["Id"] == DIAG_UNIT,
             "168 closure belongs to another admission")
    return dict(owners, **{FIELD: TERMINAL}, actual_active_private_diagnostics=[
        r for r in owners["actual_active_private_diagnostics"] if r["epoch"] != 168])


def native():
    from owners import DIAG_IID, DIAG_UNIT, show
    unit = show(DIAG_UNIT, ("Id", "ActiveState", "SubState", "Result", "InvocationID", "MainPID", "NRestarts", "Job", "ControlGroup", "ExecMainCode", "ExecMainStatus"))
    need(unit == dict(Id=DIAG_UNIT, ActiveState="failed", SubState="failed", Result="exit-code",
                      InvocationID=DIAG_IID, MainPID="0", NRestarts="0", Job="", ControlGroup="",
                      ExecMainCode="1", ExecMainStatus="1"), "168 native terminal identity changed")
    cg = Path("/sys/fs/cgroup/system.slice") / DIAG_UNIT
    need(not cg.exists() or not (cg/"cgroup.procs").read_text().strip(), "168 retired cgroup has a process")
    timer = "horizon-guard-168-trace-local3-20261120-v1.timer"
    for name in (timer, timer.removesuffix(".timer") + ".service"):
        state = show(name, ("ActiveState", "Job"))
        need(state == {"ActiveState": "inactive", "Job": ""}, "168 guard still owns work")
    return unit


def observation(c):
    from owners import DIAG_IID, DIAG_UNIT, DIAG_REF
    configured = [r for r in c.cfg["diagnostic_replays"] if r["range"] == "168"]
    seen = [r for r in c.sample["diagnostic_replays"] if r["range"] == "168"]
    if c.sample_ref == SAMPLE:
        expected = next(r for r in c.fleet["actual_active_private_diagnostics"] if r["epoch"] == 168)
        need(configured == [expected["observer_config"]] and len(seen) == 1, "168 terminal observation registration")
        r = seen[0]
        need(r["producer_unit"] == DIAG_UNIT and r["expected_producer_invocation_id"] == DIAG_IID
             and r["scratch_path"] == configured[0]["scratch_path"] and r["observation"] is None
             and r["status"] == "unavailable" and not any(r[k] for k in
             ("ordinary_replay_claim", "publication_authorized", "r2_mutations", "replay_launch_authorized")),
             "foreign 168 terminal observation")
    else:
        need(prior(c.fleet) and not configured and not seen, "168 terminal remains in a later observer")
    return dict(epoch=168, terminal=TERMINAL, admission=DIAG_REF, original_sample=SAMPLE,
                phase="private-diagnostic-terminal-execution-mismatch", unit=c.private,
                current_coordinated_observer=c.sample_ref, observer_diagnostic_result=(seen or [None])[0],
                live_owner_claimed=False, resource_credit_bytes=0, canonical_replay_claimed=False,
                transaction_replay_claimed=False, archive_publication_authorized=False)


def install(c, fleet, row):
    need(c.diagnostic["terminal"] == TERMINAL and c.diagnostic["live_owner_claimed"] is False,
         "unbound terminal 168 diagnostic")
    fleet[FIELD] = TERMINAL
    if c.sample_ref == SAMPLE:
        fleet["historical168_before_trace_mismatch"] = next(r for r in c.fleet["actual_active_private_diagnostics"] if r["epoch"] == 168)
    row.pop("current_private_diagnostic", None)
    row.update(no_live_producer_claimed=True, current_repair_owner="/root", repair_open=True,
               state="verification", terminal168_trace_mismatch=TERMINAL,
               next_action="Resolve the historical execution mismatch at slot 72728191 before replaying the epoch.",
               current_status_scope="The private trace ended at the execution mismatch. Archive verification remains pending.")
