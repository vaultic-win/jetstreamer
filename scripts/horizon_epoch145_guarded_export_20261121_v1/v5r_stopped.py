"""Carry the original frozen epoch 145 candidate through the V5r guard exit."""

from pathlib import Path
import runpy

RUNTIME = Path("/var/lib/jetstreamer/horizon_runtime_data")
TERMINAL = RUNTIME / (
    "epoch145-semantic-continuity-20261121-v1/v5r-name-handoff/"
    "V5R_GUARD_TERMINAL_095224.json"
)
TERMINAL_SHA = "85e6514447293f66ebf4e20936e9bac0551575bb0f6fdab66651b7aa0e391d97"
PRIOR_ADAPTER = RUNTIME / (
    "incident-replay-fit-20261121-v1/tools-homefloor-145-v5p-stopped-v1/v5p_stopped.py"
)
PRIOR_ADAPTER_SHA = "d33bfb4bc87bc9d47e65a1d09b8f176760fbb89808da4884ab5587f255066de7"
IID = "8f2b9c06b62147babe83c9ade7271cd3"
UNIT = "horizon-holding-export145-20261121-v1.service"
STATE = RUNTIME / "epoch145-guarded-export-20261121-v1/state" / IID


def stopped_phase(status, fit):
    terminal, ref = status.read(TERMINAL, TERMINAL_SHA)
    fit.binary(PRIOR_ADAPTER, PRIOR_ADAPTER_SHA)
    prior_adapter = runpy.run_path(str(PRIOR_ADAPTER))
    api, prior = prior_adapter["historical"]()
    need = status.need
    manager = api["inspect_unit"]()
    api["check_empty"](manager)
    native = terminal["native_terminal"]
    fail, failure_ref = status.read(STATE / "failed.json", terminal["failure"]["sha256"])
    begin, start_ref = status.read(STATE / "recovery-started.json", terminal["startup"]["sha256"])
    retained = terminal["candidate"]
    candidate = Path(retained["path"])
    st = candidate.lstat()
    phase = prior["failed_phase"]
    old = phase["candidate"]
    need(terminal["schema"] == "horizon-epoch145-retained-guard-terminal-v1"
         and manager["InvocationID"] == fail["iid"] == begin["iid"] == native["INVOCATION_ID"] == IID
         and manager["ExecMainStatus"] == "1" and native["UNIT"] == UNIT
         and native["EXIT_CODE"] == "exited" and native["EXIT_STATUS"] == "1"
         and {key: manager[key] for key in terminal["manager"][UNIT]} == terminal["manager"][UNIT]
         and failure_ref == terminal["failure"] and start_ref == terminal["startup"]
         and fail["error"] == "stopped worker fresh-census deadline"
         and begin["file"] == str(candidate) and begin["r2_mutations"] is False
         and terminal["fully_verified"] is False and terminal["archive_publication_authorized"] is False
         and terminal["resource_credit_bytes"] == 0 and terminal["r2_mutations"] is False,
         "unbound V5r terminal or candidate custody")
    need((st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_blocks * 512) ==
         (retained["device"], retained["inode"], retained["bytes"], retained["mtime_ns"],
          retained["allocated_bytes"])
         and (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns) ==
         (old["device"], old["inode"], old["bytes"], old["mtime_ns"], old["ctime_ns"])
         and st.st_mode == old["mode"] and (st.st_uid, st.st_gid, st.st_nlink) == (0, 0, 1),
         "retained V5r candidate changed")
    api["retained"](api["bound"](prior["predecessor_review"]))
    need({path.name for path in STATE.iterdir()} == {"failed.json", "recovery-started.json"}
         and api["inspect_unit"]() == manager and not fit.members(UNIT),
         "V5r terminal changed during retained-input check")
    return dict(phase, InvocationID=IID, failure=failure_ref, recovery=start_ref,
                manager_exit={key: value for key, value in native.items() if key != "MESSAGE"},
                guard_terminal=ref)
