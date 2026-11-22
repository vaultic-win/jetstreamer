"""Binding for the cold epoch 167 successor using the original qualified actor reader."""
from pathlib import Path

DIRECTORY = "epoch167-source-index-rebook-20261122-v3"
NAME = "167-source-index-v3-20261122"
UNIT = "horizon-qualify-" + NAME + ".service"
TIMER = "horizon-guard-" + NAME + ".timer"
LANE = Path("/home/sol/.jetstreamer-private/epoch167-standard-lane-20261109-v1")
PREVIOUS_RUN = LANE / "replacement-source-index-v1-20261121"
RUN = PREVIOUS_RUN / "cold-source-index-v3-20261122"
PREVIOUS_UNIT = "horizon-qualify-167-source-index-v1-20261121.service"
GUARD_SHA = "0d02c342a3993dea74f5a452d91c8ed655e551f28794b0333093fb767d18251b"
GUARD_DIR = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch167-cold-guard-20261122-v3/tools")
GUARD_SEAL = "0fd5e8a3f7113e5c373222b6aa647b179617876a6855253461a6633f5f9c5cb3"
GUARD_QUAL = "42afc173c57edb71a7b6f0bd7a43542d96cb85f08ff25fcd260134e5fff90021"
FAILURE = {"path":"/var/lib/jetstreamer/horizon_runtime_data/epoch167-source-index-rebook-20261122-v1/START_FAILURE.json",
           "sha256":"bf7c9db02f21c189f4bbf479428522ef52a3c5d7f553dc1118dd0edac71533a9"}
PREVIOUS_IID = "0876e9944c784b41afeff1b666539ead"
STOP = {"path": "/var/lib/jetstreamer/horizon_runtime_data/epoch167-source-index-recovery-20261121-v1/guard-receipts/stop-completion.json",
        "sha256": "50c7f072d70a1e3112c67034e4fc324a8597093871483c7c3af411bb52ea1c64"}
RETURN = {"path": "/var/lib/jetstreamer/horizon_runtime_data/epoch167-ancestor-accounts-20261122-v2/RETURN.json",
          "sha256": "35c7b753caa4db4a4774fae5c716a12003422c84a106e35288b0278981df4ede"}

def observe(s, fit, native_actor, own):
    """Return the native actor row (or None before launch) for the actual successor."""
    stopped = s.bound(STOP, Path(STOP["path"]))
    returned = s.bound(RETURN, Path(RETURN["path"]))
    s.need(stopped["producer_invocation_id"] == PREVIOUS_IID and
           stopped["terminal"]["active"] == "inactive" and stopped["terminal"]["pid"] == 0 and
           returned["verified_release_bytes"] == 95559610368 and returned["lane_cap_bytes"] == 512 << 30 and
           s.show(PREVIOUS_UNIT)["ActiveState"] == "inactive" and not fit.members(PREVIOUS_UNIT),
           "foreign predecessor or ancestor disposal")
    failed = s.bound(FAILURE, Path(FAILURE["path"]))
    failed_unit = "horizon-qualify-167-source-index-v2-20261122.service"
    s.need(failed["cgroup"]==[] and failed["producer_invocation_id"]=="cdcb80c45de340278a07418190d7c3c7"
           and not fit.members(failed_unit) and s.show(failed_unit)["ActiveState"]=="inactive",
           "v2 launch was not drained")
    # The normal adapter retains original cgroup, worker, guard sample, PID1 and whole-tree checks.
    predecessor = {"original": {"producer_invocation_id": PREVIOUS_IID}, "stop_completion": STOP}
    row = native_actor(167, own, LANE, RUN, predecessor, generation=(DIRECTORY, NAME))
    if row is None:
        return None
    directory = Path(STOP["path"]).parents[2] / DIRECTORY
    prepared, prepared_ref = s.read(directory / "PREPARED.json")
    intent, _ = s.read(directory / "START_INTENT.json")
    root = RUN.stat()
    b = prepared["baseline"]
    s.need(intent["prepared"] == prepared_ref and b["retirement"] == RETURN and b["previous_cold_failure"]==FAILURE and
           b["predecessor_stop"] == STOP and intent["stable_root"] == b["root"] and
           b["root"] == {"path":str(RUN),"device":root.st_dev,"inode":root.st_ino} and
           RUN.resolve(strict=True) == RUN and (root.st_dev,root.st_uid,root.st_gid)==(64512,1001,1003) and
           row["producer_unit"] == UNIT and row["timer"] == TIMER and
           row["producer_invocation_id"] != PREVIOUS_IID, "unbound cold 167 generation")
    profile = prepared["profile"]
    args = profile["producer_argv"]
    node = "/usr/local/lib/jetstreamer/horizon-independent167-singleton-package-20261109-v1/jetstreamer-node"
    proc = Path("/proc") / str(row["producer_pid"])
    command = proc.joinpath("cmdline").read_bytes().split(b"\0")
    s.need(profile["producer_unit"]==UNIT and profile["guard_timer"]==TIMER and
           profile["fresh_attempt"]==str(RUN) and profile["guard_worker_root"]==str(LANE) and
           command == [a.encode() for a in args[args.index(node):]]+[b""], "foreign cold 167 argv")
    cache = PREVIOUS_RUN / "output/compact-indexes"
    snap_view = Path("/usr/local/lib/jetstreamer/horizon-standard-local-input167-20261110-v1") / Path(b["snapshot"]["path"]).name
    mounts = {Path(parts[4]): set(parts[5].split(",")) for parts in
              (line.split() for line in proc.joinpath("mountinfo").read_text().splitlines())}
    for host, view in [(cache,RUN/"output/compact-indexes"),(Path(b["snapshot"]["path"]),snap_view)]:
        mounted = proc / "root" / view.relative_to("/")
        s.need(s.same_file(host,mounted) and "ro" in mounts.get(view,()), "cold 167 input bind changed")
    return row
