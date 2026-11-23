"""Authenticate one missed RSS sample and its sole scheduled replacement."""
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

ROOT = Path("/var/lib/jetstreamer/horizon_runtime_data")
CADENCE = ROOT / "survivor172-cadence-20261122-v1"
NEXT_GRACE_SECONDS = 300


def need(ok, message):
    if not ok:
        raise ValueError(message)


def read(path, expected=None):
    p = Path(path)
    need(p.resolve(strict=True) == p and p.is_relative_to(ROOT), "foreign cadence path")
    with os.fdopen(os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as f:
        st = os.fstat(f.fileno())
        need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_uid == st.st_gid == 0 and
             st.st_mode & 0o022 == 0 and st.st_size <= 32 << 20, "unsafe cadence input")
        data = f.read(st.st_size + 1)
        def identity(s):
            return s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns
        need(len(data) == st.st_size and identity(st) == identity(os.fstat(f.fileno())) == identity(p.lstat()),
             "replaced cadence input")
    ref = {"path": str(p), "sha256": hashlib.sha256(data).hexdigest()}
    need(expected is None or ref == expected, "changed bound cadence input")
    return json.loads(data), ref


def utc(s):
    t = datetime.fromisoformat(s)
    need(t.utcoffset() == timedelta(0), "UTC cadence clock required")
    return t


def complete_rss(side):
    if side["status"] != "observed":
        return False
    rss = side["rss"]
    rows = rss["processes"]
    return (rss["census_stable"] is True and rss["error"] is None and
            len({r["pid"] for r in rows}) == len(rows) and rss["aggregate_rss_bytes"] > 0 and
            all(r["pid"] > 0 and r["start_ticks"] > 0 and r["rss_bytes"] >= 0 for r in rows) and
            rss["aggregate_rss_bytes"] == sum(r["rss_bytes"] for r in rows))


def clock(previous, fleet, now, get=read):
    original = fleet["sole_next_observer"]
    need(re.fullmatch("[0-9a-f]{64}", original["sha256"]), "bad config digest")
    failed_dir = CADENCE / ("recover-" + original["sha256"][:20])
    try:
        reg, _ = get(failed_dir / "REGISTERED.json")
    except FileNotFoundError:
        return {"state": "ordinary"}
    def bound(ref):
        return get(ref["path"], ref)[0]
    bad, bad_ref = get(failed_dir / "TERMINAL.json", reg["terminal"])
    need(bad["error"] == "native HOST RSS unavailable" and bad["fleet"] == previous and
         bad["prior_config"] == original, "unrelated rejected sample")
    old_config = bound(original)
    config, cfgref = get(failed_dir / "sealed-next/observer.json", reg["config"])
    seal, _ = get(failed_dir / "sealed-next/deployment-seal-receipt.json")
    need(seal["destination"] == str(failed_dir / "sealed-next") and seal["sealer_sha256"] ==
         "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3" and
         [(row["name"], row["sha256"]) for row in seal["members"]] == [("observer.json", cfgref["sha256"])],
         "unsealed replacement clock")
    sample = bound(bad["failed_sample"])
    c = sample["cadence"]
    anchor = fleet["observer"]
    need(old_config["output"] == bad["failed_sample"]["path"] and c["previous_sample"] == anchor["path"] and
         c["previous_sample_sha256"] == anchor["sha256"] and old_config["previous_sample"] == anchor["path"] and
         c["observation_reason"] == old_config["observation_reason"] == "routine" and c["routine_minimum_interval_enforced"]
         and c["minimum_interval_seconds"] == old_config["minimum_interval_seconds"] == 1800 and
         c["observed_interval_seconds"] >= 1800 and c["configured_not_before_utc"] == old_config["not_before_utc"] and
         utc(sample["recorded_at_utc"]) >= utc(c["configured_not_before_utc"]), "different failed original clock")
    rss = sample["host_resident_memory"]
    need(any(rss[k]["status"] == "unavailable" and rss[k]["error"] for k in ("before", "after")),
         "missing native RSS rejection")
    need({k for k in set(old_config) | set(config) if config.get(k) != old_config.get(k)} ==
         {"not_before_utc", "output"} and config["not_before_utc"] == c["next_routine_observation_not_before_utc"] and
         utc(config["not_before_utc"]) == utc(sample["recorded_at_utc"]) + timedelta(seconds=1800),
         "changed replacement clock or topology")
    q = Path(config["output"])
    mo = re.fullmatch(r"sample-(root[0-9]{6}[-a-zA-Z0-9]+)\.json", q.name)
    need(q.parent == ROOT and mo, "foreign successor output")
    deadline = int(utc(config["not_before_utc"]).timestamp()) + NEXT_GRACE_SECONDS
    try:
        successor, newref = get(ROOT / mo.group(1) / "ROOT_COMPLETE_OPERATIONAL_FLEET.json")
    except FileNotFoundError:
        need(now <= deadline, "registered single replacement did not complete in time")
        return {"state": "pending", "deadline": deadline, "config": cfgref, "terminal": bad_ref, "expected_fleet": str(ROOT / mo.group(1) / "ROOT_COMPLETE_OPERATIONAL_FLEET.json")}
    sr = successor["observer"]
    good = bound(sr)
    cc = good["cadence"]
    need(successor["owner"] == "/root" and successor["schema"] == fleet["schema"] and
         successor["previous_Root_operational_review"] == previous and sr["path"] == str(q) and
         good["recorded_at_utc"] == successor["sampled_at_utc"] and utc(config["not_before_utc"]) <= utc(good["recorded_at_utc"]) and
         utc(good["recorded_at_utc"]).timestamp() <= successor["recorded_unix_seconds"] <= min(now, deadline) and
         cc["configured_not_before_utc"] == config["not_before_utc"] and cc["previous_sample"] == anchor["path"] and
         cc["previous_sample_sha256"] == anchor["sha256"] and cc["minimum_interval_seconds"] == 1800 and cc["routine_minimum_interval_enforced"] and
         cc["observation_reason"] == "routine" and cc["observed_interval_seconds"] >= 1800 and
         all(complete_rss(good["host_resident_memory"][k]) for k in ("before", "after")),
         "unaccepted replacement or wrong predecessor")
    return {"state": "accepted", "fleet": newref, "config": cfgref, "terminal": bad_ref}


if __name__ == "__main__":
    path, sha = sys.argv[1:]
    previous = {"path": path, "sha256": sha}
    fleet = read(path, previous)[0]
    print(json.dumps(clock(previous, fleet, int(datetime.now(timezone.utc).timestamp()))))
