"""Re-review the published graph and prepare the exact retry10 check or execution plan.

The dry run emits no plan. Materialization writes only private immutable review data.
The invoked lifecycle binary independently rebuilds the full graph and checks its digests.
"""

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time

W = Path("/home/sol/.jetstreamer-private/epoch166-retry10-consumer-review-20261123")
D = Path("/var/lib/jetstreamer/horizon_runtime_data")
H = D / "epoch166-retry10-holding-20261122-v1"
BASE = Path("/home/sol/.jetstreamer-private")
ORIGINAL = H / "retirement-tools/jetstreamer-r2"
ORIGINAL_ALIAS = BASE / "horizon-root-runtime-data" / ORIGINAL.relative_to(D)
ORIGINAL_SEAL = {
    "path": str(ORIGINAL.with_name("deployment-seal-receipt.json")),
    "sha256": "ac04d6adffe8326365a45adde19ac0638c608583e28c8665b515efb4280b8ea7",
}
MATRIX = W / "SEMANTIC_BINDINGS_20261123T034106Z.json"
EXPECTED = "1283a13c654c69b7a228d0665062514eaeed8cd0b986f6f8d86eafba76e110a5"
FUTURE = "horizon-qualify-166-independent-retry11-20261122.service"
PARK = "horizon-closed166-retry10-park-20261122-v1.service"
MANAGER_COMMIT = "e0214452e559a67632512a1d539a9b6fd8b00290"
REPO = Path("/home/sol/workspace/jetstreamer")


def need(cond, msg):
    if not cond:
        raise ValueError(msg)


def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def raw(path, immutable=False):
    path = Path(path)
    s = path.lstat()
    need(
        path.resolve(strict=True) == path
        and stat.S_ISREG(s.st_mode)
        and s.st_nlink == 1
        and s.st_size < 129 * 1024**2
        and path.suffix != ".jet",
        "invalid regular evidence: " + str(path),
    )
    if immutable:
        need(
            s.st_uid == 0 and not s.st_mode & 0o222,
            "mutable or non-root evidence: " + str(path),
        )
    data = path.read_bytes()
    t = path.lstat()
    need(
        (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        == (t.st_dev, t.st_ino, t.st_size, t.st_mtime_ns, t.st_ctime_ns),
        "evidence raced: " + str(path),
    )
    return data


def ref(path, immutable=False):
    return {
        "path": str(path),
        "sha256": hashlib.sha256(raw(path, immutable)).hexdigest(),
    }


def checked(b, immutable=False):
    data = raw(b["path"], immutable)
    need(hashlib.sha256(data).hexdigest() == b["sha256"], "SHA changed: " + b["path"])
    return data


def load(p):
    return json.loads(raw(p))


def doc(b, immutable=False):
    return json.loads(checked(b, immutable))


def native(units):
    props = "Id,Names,LoadState,ActiveState,SubState,Job,MainPID,ControlPID,InvocationID,FragmentPath,DropInPaths,TriggeredBy,Triggers,UnitFileState,ExecStart,ExecMainStatus,ExecMainPID,ExecMainExitTimestampMonotonic,Result,NRestarts,Restart,ControlGroup,NeedDaemonReload"
    result = subprocess.run(
        ["systemctl", "show", "--all", "-p", props, *sorted(units)],
        capture_output=True,
        text=True,
        check=True,
    )
    need(not result.stderr, "manager stderr")
    rows = [
        dict(x.split("=", 1) for x in block.splitlines())
        for block in result.stdout.strip().split("\n\n")
    ]
    m = {x["Id"]: x for x in rows}
    need(set(m) == set(units), "manager identities incomplete")
    return m


def dead(r):
    return (
        r["ActiveState"] == "inactive"
        and r["SubState"] == "dead"
        and not r["Job"]
        and all(r.get(k) in ("0", None) for k in ["ControlPID", "MainPID"])
    )


def recorded_disposition(row):
    c = row["classification"]
    if c == "canonical-manager-definition":
        if row["formal_blocker"] and "/run/systemd/system/" in row["path"]:
            return "retired-observer-drop-in", [row["units"][0]]
        return "closed-consumer", row["units"]
    if c == "historical-observer-config":
        return "closed-consumer", row["output_named_historical_units"]
    if c in ("observer-fixture-config", "historical-evidence"):
        if c == "observer-fixture-config":
            need(
                row["suite_root"]
                and row["suite_evidence"]
                and row["borrowed_output_does_not_register_an_owner"],
                "fixture scope and proof",
            )
        else:
            need(
                row["exact_fields"] and all(i["meaning"] for i in row["exact_fields"]),
                "historical field evidence",
            )
        return "retained-nonexecuting-evidence", []
    need(
        c
        in [
            "staged-trigger-copy",
            "executable-holding-control",
            "compiled-closed-accounts-profile",
            "executable-prefix-inspector-input",
        ],
        "unexpected node classification",
    )
    return "closed-consumer", row["units"]


def cgroup_empty(unit):
    path = Path("/sys/fs/cgroup/system.slice") / unit
    try:
        path.lstat()
    except FileNotFoundError:
        return
    need(
        "populated 0" in (path / "cgroup.events").read_text().splitlines(),
        "populated " + unit,
    )


def namespace_proof(q):
    need(
        q["qualification_only"] and q["candidate"]["path"] != q["original"]["path"],
        "unexpected origin proof",
    )
    for key in (
        "candidate",
        "original",
        "original_alias",
        "original_seal",
        "native_qualification",
        "seal",
        "sealer",
        "original_eligibility",
        "plan",
    ):
        checked(q[key], True)
    need(
        q["original"]["path"] == str(ORIGINAL)
        and q["original_alias"]
        == {"path": str(ORIGINAL_ALIAS), "sha256": q["original"]["sha256"]}
        and q["original_seal"] == ORIGINAL_SEAL
        and ORIGINAL.samefile(ORIGINAL_ALIAS)
        and q["original_inode"]
        == [ORIGINAL_ALIAS.stat().st_dev, ORIGINAL_ALIAS.stat().st_ino]
        and any(
            case.get("mode") == "bound"
            and "ORIGINAL_AND_BOUND_CANDIDATE_VERIFIED" in case["evidence"]
            for case in q["cases"]
        ),
        "original installed image must remain readable through its physical alias with the successor bound",
    )
    nq = doc(q["native_qualification"], True)
    failure = {
        "path": str(W / "PARK_DISPATCH_FAILURE_9dcefb54_20261123.json"),
        "sha256": "3be28439aca0a20fa90ec895661fc5542f6e33b47b299e9383f3428c6c5256d5",
    }
    need(
        q.get("park_dispatch_failure") == failure
        and q.get("park_dispatch_test") is not None,
        "the real rejected park dispatch and the corrected native test are required",
    )
    checked(failure, True)
    need(
        q["park_dispatch_test"] == nq.get("actual_park_test"),
        "uncorrelated actual park qualification",
    )
    park_log = checked(q["park_dispatch_test"]).decode()
    need(
        "test holding::epoch166_retry10_retire::independent_tests::genuine_park_dispatch_after_reload ... ok"
        in park_log
        and "1 passed; 0 failed" in park_log,
        "corrected binary did not verify the complete genuine park",
    )
    need(
        q["candidate"]["sha256"] == nq["image"]["sha256"]
        and q["original"]["sha256"]
        == "57b05bbcfa72fd4d6a6be68673c219299daeade65359236085e7a06be9b2515c",
        "image provenance",
    )
    need(
        len(q["cases"]) == 2
        and all(c["rc"] != 0 for c in q["cases"])
        and q["production_bind_property"]
        == "BindReadOnlyPaths=" + q["candidate"]["path"] + ":" + q["original"]["path"],
        "missing actual origin cases",
    )
    unit_proof = doc(
        {
            "path": str(W / "manager-only-1795406682279710514/PASSED.json"),
            "sha256": "5e849d9e557090a43e776885c3f64f71ad1e0da0ea4661897934faeb404599f0",
        },
        True,
    )
    need(
        "actual_manager_test" in nq and "test_groups" in nq,
        "combined current-manager qualification required",
    )
    log = checked(nq["actual_manager_test"]).decode()
    kernel_case = "holding::epoch166_retry10_retire::consumers::reviewed_managers::tests::actual_retired_managers_and_activation_namespace"
    need(
        f"test {kernel_case} ... ok" in log and "1 passed; 0 failed" in log,
        "actual manager test in the final full native binary",
    )
    need(
        all(
            nq["test_groups"][name]["passed"] >= minimum
            for name, minimum in {
                "epoch166_retry6_retire": 26,
                "epoch166_retry7_retire": 27,
                "epoch166_retry8_retire": 27,
                "epoch166_retry10_retire": 27,
                "epoch168_metered_retire": 28,
            }.items()
        ),
        "all native suites",
    )
    need(
        unit_proof["passed"]
        and unit_proof["read_only"]
        and unit_proof["census_started"] is False
        and unit_proof["registry_sha256"]
        == "6f7e921b8e408dae35491c03004298bf887a357d6b6f24013e72bb817d3490a9",
        "actual full-manager fixture",
    )
    commit = nq["published_source_commit"]
    need(re.fullmatch("[a-f0-9]{40}", commit) is not None, "invalid source commit")
    for before, after in [(MANAGER_COMMIT, commit), (commit, "origin/account-updates")]:
        subprocess.run(
            [
                "runuser",
                "-u",
                "sol",
                "--",
                "git",
                "-C",
                str(REPO),
                "merge-base",
                "--is-ancestor",
                before,
                after,
            ],
            check=True,
        )
    return nq


def check_service_command(body, mount, version, fleet):
    # The finished original transfer is the funded networked holding profile.
    # No credential contents are opened by this planner.
    properties = [
        "EnvironmentFiles",
        "CPUQuotaPerSecUSec",
        "MemoryMax",
        "MemorySwapMax",
        "TasksMax",
    ]
    result = subprocess.check_output(
        ["systemctl", "show", "--all", "-p", ",".join(properties), PARK], text=True
    )
    profile = dict(line.split("=", 1) for line in result.splitlines())
    credential = Path(
        "/var/lib/jetstreamer/r2-chronological-plugin-audit-deployment-20261118-v1/credentials.env"
    )
    need(
        profile["EnvironmentFiles"] == str(credential) + " (ignore_errors=no)",
        "original holding credential provider changed",
    )
    reservation = fleet["retry9_auxiliary_commitments"]
    need(
        reservation["holding_serial"]
        and reservation["holding_and_build_may_overlap"]
        and reservation["holding_cpu_quota_micros"] == 2000000
        and reservation["holding_memory_bytes"] == 2 << 30,
        "holding reservation changed",
    )
    need(
        profile["CPUQuotaPerSecUSec"] == "2s"
        and profile["MemoryMax"] == str(2 << 30)
        and profile["MemorySwapMax"] == "0"
        and profile["TasksMax"] == "256",
        "recorded holding resource limits changed",
    )
    state = BASE / "r2-holding-state-dev-samjohnson-v1"
    capture = "horizon-closed166-retry10-park-terminal-20261122-v1.service"
    options = [
        "After=" + capture,
        "ExecStartPre=/usr/bin/systemctl --quiet is-active " + capture,
        "EnvironmentFile=" + str(credential),
        "CPUQuota=100%",
        "MemoryMax=" + profile["MemoryMax"],
        "MemorySwapMax=0",
        "TasksMax=256",
        "TimeoutStartSec=30min",
        "Restart=no",
        "UMask=0077",
        "NoNewPrivileges=yes",
        "ProtectSystem=strict",
        "ProtectHome=read-only",
        "ReadWritePaths=" + str(state),
        "RemainAfterExit=yes",
        mount,
    ]
    unit = "horizon-closed166-retry10-check-" + version.rsplit("-", 1)[1]
    return [
        "systemd-run",
        "--no-block",
        "--unit=" + unit,
        "--service-type=oneshot",
        *(part for option in options for part in ("-p", option)),
        *body,
    ]


def lock_version(path):
    path.mkdir(mode=0o700, parents=False, exist_ok=False)
    need(
        path.stat().st_uid == 0
        and path.stat().st_dev == BASE.stat().st_dev
        and stat.S_IMODE(path.stat().st_mode) == 0o700,
        "version dir",
    )


def write(path, obj):
    data = (json.dumps(obj, sort_keys=True, separators=(",", ":")) + "\n").encode()
    with path.open("xb") as f:
        os.fchmod(f.fileno(), 0o400)
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    return ref(path, True)


def local_transition(source, digest):
    state = BASE / "r2-holding-state-dev-samjohnson-v1" / "retirements"
    quarantine = state / ("epoch166-retry10-" + digest + ".jet")
    records = {}
    for name in ("intent", "moved", "unlink-intent", "completion"):
        path = state / ("epoch166-retry10-" + name + ".json")
        try:
            path.lstat()
        except FileNotFoundError:
            continue
        records[name] = ref(path)
    local = []
    for f in (source, quarantine):
        try:
            s = f.lstat()
        except FileNotFoundError:
            continue
        need(
            stat.S_ISREG(s.st_mode)
            and s.st_dev == 64512
            and s.st_ino == 93782070
            and s.st_size == 64922604512
            and s.st_nlink == 1,
            "changed original physical identity: " + str(f),
        )
        local.append(str(f))
    need(
        len(local) <= 1
        and ("moved" not in records or "intent" in records)
        and ("unlink-intent" not in records or "moved" in records)
        and ("completion" not in records or "unlink-intent" in records),
        "invalid native retirement receipt order",
    )
    need(
        (str(quarantine) not in local or "intent" in records)
        and (str(source) not in local or "moved" not in records)
        and (local or "unlink-intent" in records)
        and ("completion" not in records or not local),
        "original source disposition disagrees with native receipts",
    )
    if records:
        intent = doc(records["intent"])
        need(
            intent["source"] == str(source)
            and intent["sha256"] == digest
            and intent["inode"] == 93782070
            and intent["quarantine"] == str(quarantine),
            "wrong source in original intent",
        )
    return {
        "current_source_or_quarantine": local,
        "native_transition_receipts": records,
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument(
        "action", choices=["review-only", "prepare-check", "prepare-execute"]
    )
    p.add_argument("--fleet", type=Path, required=True)
    p.add_argument("--origin-proof", type=Path)
    p.add_argument("--origin-sha")
    p.add_argument("--prior-check", type=Path)
    p.add_argument("--prior-sha")
    a = p.parse_args()
    need(os.geteuid() == 0 and sys_isolated(), "root python3 -IB required")
    started = int(time.time())
    matrix_ref = {"path": str(MATRIX), "sha256": EXPECTED}
    m = doc(matrix_ref, True)
    g = doc(m["graph"], True)
    need(
        len(m["rows"]) == len(g["nodes"]) == 271
        and set(m["rows"]) == {n["file"]["path"] for n in g["nodes"]},
        "actual graph file set differs",
    )
    need(
        m["sealed_corpus"] == g["sealed_metadata_census_sha256"]
        and m["definition_corpus"] == g["definition_census_sha256"],
        "closure corpus",
    )
    ins = ref(H / "RETIREMENT_STATIC_INPUT_BINDINGS.json", True)
    bindings = doc(ins, True)["static_bindings"]
    for b in bindings.values():
        checked(b, False)
    source = g["source"]
    transition = local_transition(Path(source), g["sha256"])
    prepared = doc(m["future_retry11"]["prepared"], True)
    boot = prepared["baseline"]["snapshot"]
    bootstat = Path(boot["path"]).lstat()
    need(
        bootstat.st_ino == boot["inode"] == 93782058
        and bootstat.st_size == boot["length"] == 1968014870,
        "retained bootstrap changed",
    )
    for i in prepared["indexes"]:
        md = Path(i["path"]).lstat()
        need(
            [md.st_dev, md.st_ino, md.st_size, md.st_mtime_ns, md.st_ctime_ns]
            == i["identity"],
            "index changed " + i["path"],
        )
    need(
        a.fleet.name == "ROOT_COMPLETE_OPERATIONAL_FLEET.json"
        and a.fleet.parent.parent == D
        and re.fullmatch(
            "root[0-9]+-live166167170-[0-9]+-v[0-9]+", a.fleet.parent.name
        ),
        "current production fleet",
    )
    fleetref = ref(a.fleet)
    fleet = doc(fleetref)
    sample = doc(fleet["observer"])
    need(
        sample["schema"] == "jetstreamer-horizon-live-resource-sample-v2",
        "foreign fleet sample",
    )
    scheduled = ref(a.fleet.parent / "sealed-next/observer.json", True)
    scheduled_doc = doc(scheduled, True)
    nextbase = "horizon-observer-" + Path(scheduled_doc["output"]).stem.removeprefix(
        "sample-"
    )
    service = nextbase + ".service"
    timer = nextbase + ".timer"
    live = {
        v["unit"]["Id"]: (v["epoch"], v["unit"]["InvocationID"], v["scratch_path"])
        for v in fleet["actual_executing_replays"]
    }
    upcoming = {
        v["producer_unit"]: (
            int(v["range"]),
            v["expected_producer_invocation_id"],
            v["scratch_path"],
        )
        for v in scheduled_doc["replays"]
    }
    need(
        live == upcoming
        and all(
            u != "horizon-qualify-166-independent-recovery-20261121-v1.service"
            and not Path(v[2]).is_relative_to(Path(source).parents[1])
            for u, v in live.items()
        ),
        "old generation in current active or scheduled consumers, or scheduler/fleet differ",
    )
    # Recheck previous lifecycle commands, including the completed 05:02 V5
    # read of this partial and its authentic native receipt.
    lifecycle_ref = {
        "path": str(W / "PRIOR_LIFECYCLE_CHECKS_THROUGH_050210_20261123.json"),
        "sha256": "1d587dca2b685a024938da76ec7df7e6b331e2cdbcca8d1545b37f838089805f",
    }
    lifecycle = doc(lifecycle_ref, True)
    checked(lifecycle["previous_review"], True)
    for image in [lifecycle["image"], *lifecycle["additional_images"]]:
        checked(image, True)
    prior_attempts = {attempt["unit"]: attempt for attempt in lifecycle["attempts"]}
    units = set([service, timer, FUTURE, *live, *prior_attempts])
    classified = {}
    for n in g["nodes"]:
        k = n["file"]["path"]
        r = m["rows"][k]
        checked(n["file"])
        need(
            r["sha256"] == n["file"]["sha256"] and n["edges"] == r["edges"],
            "graph/current binding " + k,
        )
        kind, owners = recorded_disposition(r)
        units.update(owners)
        classified[k] = (kind, owners)
        if kind == "retired-observer-drop-in":
            units.add(owners[0][:-8] + ".timer")
    comps = []

    def add_comp(image, owners, proof):
        checked(image, True)
        units.update(owners)
        comps.append(
            dict(
                image=image,
                owner_units=list(owners),
                no_local_partial_required=True,
                reviewed_source=proof,
            )
        )

    for ci in m["compiled_originals"]:
        for b in ci["source_evidence"]:
            checked(b, True)
        add_comp(ci["image"], [ci["owner"]], ci["source_evidence"])
    accounts = m["newly_identified_compiled_accounts_consumer"]
    for hist in accounts["historical_completions"]:
        for b in hist["evidence"]:
            checked(b)
        need(
            hist["completion"]["scope_empty"]
            and not hist["completion"]["archive_or_snapshot_removed"],
            "incomplete accounts transition",
        )
    add_comp(
        accounts["image"],
        accounts["historical_managers"],
        [accounts["profiles"], accounts["production_qualification"]],
    )
    add_comp(
        m["future_retry11"]["qualified_executable"],
        [FUTURE],
        [m["future_retry11"]["qualification"], m["future_retry11"]["prepared"]],
    )
    for section, owners in [
        (
            "base",
            [
                "horizon-closed166-retry10-park-terminal-20261122-v1.service",
                "horizon-closed166-retry10-consumer-census-20261122-v1.service",
            ],
        ),
        (
            "successor",
            ["horizon-closed166-retry10-consumer-census-successor-20261123-v1.service"],
        ),
    ]:
        image = m["lifecycle_programs"][section]
        proof = [ins, m["lifecycle_programs"]["successor_origin_proof"], lifecycle_ref]
        if section == "base":
            # The successor occupies the original service pathname in the checker namespace.
            # Its HOME backing name still opens the original, sealed inode.
            need(
                image["path"] == str(ORIGINAL) and ORIGINAL.samefile(ORIGINAL_ALIAS),
                "original deployment mount aliases differ",
            )
            seal = doc(ORIGINAL_SEAL, True)
            member = next(x for x in seal["members"] if x["name"] == ORIGINAL.name)
            need(
                seal["destination"] == str(ORIGINAL.parent)
                and member["sha256"] == image["sha256"],
                "original deployment seal mismatch",
            )
            image = {"path": str(ORIGINAL_ALIAS), "sha256": image["sha256"]}
            proof.append(ORIGINAL_SEAL)
        add_comp(image, owners, proof)
    for path, im in m["observer_images_derived_from_start_wrappers"].items():
        owners = sorted(
            {
                r["output_named_historical_units"][0]
                for r in m["rows"].values()
                if r["classification"] == "historical-observer-config"
                and r["manager_journal_exact_config"]
                and any(x.get("observer") == im for x in r["wrapper_bindings"])
            }
        )
        need(owners, "no historical owner for " + path)
        # The resident observer image is serving current peers under new scheduling; these two
        # rows record genuine old image/command generations, independent of that use.
        add_comp(im, owners[:1], [matrix_ref])
    states = native(units)
    for u, (e, iid, sp) in live.items():
        need(
            states[u]["ActiveState"] == "active"
            and states[u]["SubState"] == "running"
            and states[u]["InvocationID"] == iid
            and int(states[u]["MainPID"]) > 0,
            "live peer generation changed: " + u,
        )
    need(
        states[timer]["ActiveState"] == "active"
        and states[timer]["SubState"] == "waiting"
        and states[timer]["Triggers"] == service
        and scheduled["path"] in states[service]["ExecStart"]
        and timer in states[service]["TriggeredBy"].split(),
        "fleet is no longer the live next schedule",
    )
    terminal = {
        b["unit"]
        for b in m["native_validation_blockers"]
        if b["path"].startswith("/run/systemd/transient/")
    }
    for u, r in states.items():
        if u in live or u in (timer, service):
            continue
        cgroup_empty(u)
        if u in prior_attempts:
            attempt = prior_attempts[u]
            checked(attempt["submit"], True)
            if attempt.get("successful_check"):
                receipt = doc(attempt["native_receipt"], True)
                measured = doc(attempt["terminal_timing"], True)
                need(
                    receipt["checked"]
                    and not receipt["data_removed"]
                    and receipt["local_proof"]["sha256"] == g["sha256"]
                    and receipt["local_proof"]["identity"]["inode"] == 93782070
                    and measured["iid"] == attempt["manager"]["InvocationID"],
                    "wrong prior completed native check",
                )
            if r["LoadState"] == "not-found" and dead(r):
                continue
            before = attempt["manager"]
            checked(attempt["fragment"])
            fields = (
                "Id",
                "Job",
                "MainPID",
                "ControlPID",
                "ActiveState",
                "SubState",
                "InvocationID",
                "ExecMainPID",
                "ExecMainStatus",
                "ExecMainExitTimestampMonotonic",
                "Restart",
                "NRestarts",
                "Result",
                "FragmentPath",
                "DropInPaths",
                "ControlGroup",
                "TriggeredBy",
                "Triggers",
            )
            need(
                all(r.get(k) == before.get(k) for k in fields)
                and r["ExecStart"].count("argv[]=") == 1
                and r["ExecStart"].partition(" ; start_time=")[0]
                == before["ExecStart"].partition(" ; start_time=")[0],
                "previous lifecycle attempt reacquired its input or changed command: "
                + u,
            )
        elif u == PARK or u in terminal:
            original = m["native_snapshot"][u]
            for field in [
                "Id",
                "InvocationID",
                "ActiveState",
                "SubState",
                "MainPID",
                "ControlPID",
                "NRestarts",
                "Job",
                "Restart",
                "Result",
                "ExecMainStatus",
                "FragmentPath",
                "DropInPaths",
                "TriggeredBy",
                "Triggers",
            ]:
                need(
                    r.get(field) == original.get(field),
                    "changed original manager " + u + " " + field,
                )
        else:
            need(dead(r), "open owner " + u)
    for c in comps:
        for b in c["reviewed_source"]:
            checked(b, True)
    now = int(time.time())
    need(
        0 <= now - started <= 1800,
        "fresh review did not finish within observation window",
    )
    current = {
        "began_utc": dt.datetime.fromtimestamp(started, dt.timezone.utc).isoformat(),
        "at_utc": utc(),
        "matrix": matrix_ref,
        "graph": m["graph"],
        "native": states,
        "current_fleet": fleetref,
        "current_sample": fleet["observer"],
        "sample_completed_utc": sample["completed_at_utc"],
        "next_config": scheduled,
        "active": live,
        "next_service": service,
        "next_timer": timer,
        "compiled": comps,
        "source_ino": 93782070,
        "source_size": 64922604512,
        "local_transition": transition,
        "previous_lifecycle_checks": lifecycle_ref,
        "bootstrap_inode": bootstat.st_ino,
        "static_inputs": ins,
        "classifications": dict(
            (c, sum(v[0] == c for v in classified.values()))
            for c in sorted({x[0] for x in classified.values()})
        ),
        "r2_operations": 0,
        "physical_operations": 0,
    }
    if a.action == "review-only":
        print(
            json.dumps(
                {
                    k: current[k]
                    for k in [
                        "at_utc",
                        "graph",
                        "current_fleet",
                        "next_timer",
                        "classifications",
                        "source_ino",
                        "r2_operations",
                        "physical_operations",
                    ]
                }
            )
        )
        return
    need(
        a.origin_proof and a.origin_sha,
        "qualified exact successor origin and digest required",
    )
    q = doc({"path": str(a.origin_proof), "sha256": a.origin_sha}, True)
    nq = namespace_proof(q)
    prior = None
    if a.action == "prepare-execute":
        need(a.prior_check and a.prior_sha, "native check required")
        prior = {"path": str(a.prior_check), "sha256": a.prior_sha}
        receipt = doc(prior)
        need(
            receipt["schema"] == "jetstreamer-holding-retire166-retry10-check-v1"
            and receipt["checked"]
            and receipt["descriptor"]["source"] == source
            and 0 <= now - receipt["recorded_unix_seconds"] < 900,
            "unusable native check receipt",
        )
    else:
        need(a.prior_check is None and a.prior_sha is None, "check has no predecessor")
    bundles = H / "retirement-evidence"
    if not bundles.exists():
        bundles.mkdir(mode=0o700)
    need(
        bundles.resolve(strict=True) == bundles
        and bundles.stat().st_uid == 0
        and bundles.stat().st_mode & 0o077 == 0
        and bundles.stat().st_dev == BASE.stat().st_dev,
        "unsafe evidence root",
    )
    v = bundles / (a.action + "-" + str(time.time_ns()))
    lock_version(v)
    cur = write(v / "owner-review.json", current)
    nodes = []
    for count, n in enumerate(g["nodes"]):
        k = n["file"]["path"]
        kind, owners = classified[k]
        row = write(
            v / (f"node-{count:03}.json"),
            dict(
                review=m["rows"][k],
                source_matrix=matrix_ref,
                current_review=cur,
                source_rechecked_at=started,
            ),
        )
        nodes.append(
            dict(
                file=n["file"],
                edges=n["edges"],
                disposition=kind,
                owner_units=owners,
                semantic_evidence=[row],
            )
        )
    reasons = {
        "producer-controller": "Original independent producer and worker closed; new replay uses distinct root and old archive absence. Active current peers and sole scheduled manager are identified in the fresh review.",
        "libraries-and-relative-inputs": "Historical scanner and accounts gate required exact old bytes/inode and have native terminal evidence. No outstanding execution of either. Scratch scanners inspect sibling scratch metadata.",
        "sealed-launch-plans": "The park has authentic custody and terminal receipts. The current lifecycle alone retains exclusive integrity access until retirement; the bound previous lifecycle images were invoked for metadata census and terminal capture.",
        "timer-path-cron": "Disabled batch watcher and real terminal service preserved. The twelve orphan drop-ins retain their real names and pinned digests. The four drained transient generations and their trigger/cgroup namespace are checked natively.",
        "future-builds": "The qualified retry11 image authenticates historical completion and demands both original file and quarantine absence. Bootstrap, all three indexes and sources are retained.",
        "recovery": "Original partial is held with authenticated historical custody; native retirement revalidates the remote and full local identity. Never reopen old scanner, accounts, replay or park during this operation.",
        "live-accounting-and-witness-roots": "Current peer roots, witnesses, distinct bootstrap, indexes, scratch allocations and fit inputs remain available. This plan grants no capacity or launch credit.",
    }
    classes = [
        dict(
            **{"class": k},
            no_local_archive_required=True,
            reason=v,
            inspected_inputs=[matrix_ref, cur],
        )
        for k, v in reasons.items()
    ]
    review = write(
        v / "closure.json",
        dict(
            schema="horizon-closed166-retry10-transitive-consumer-closure-v1",
            owner="/root",
            source=source,
            sha256=g["sha256"],
            length=g["length"],
            inspection=bindings["inspection"],
            park_plan=g["park_plan"],
            park_terminal=bindings["park_terminal"],
            recorded_unix_seconds=started,
            sealed_metadata_root=g["sealed_metadata_root"],
            definition_roots=g["definition_roots"],
            sealed_metadata_census_sha256=m["sealed_corpus"],
            definition_census_sha256=m["definition_corpus"],
            nodes=nodes,
            compiled_consumers=comps,
            classes=classes,
            unresolved_edges=[],
            complete_transitive_consumer_graph_qualified=True,
            dynamic_native_and_future_consumers_reviewed=True,
            no_reopening_until_retirement_complete=True,
            resource_promises_and_live_witness_ancestors_preserved=True,
        ),
    )
    plan = write(
        v / "plan.json",
        dict(
            schema="jetstreamer-horizon-holding-retire166-retry10-plan-v1",
            **bindings,
            consumer_closure=review,
            prior_check=prior,
        ),
    )
    command = (
        "holding-check-retire166-retry10"
        if prior is None
        else "holding-retire166-retry10"
    )
    body = [
        q["original"]["path"],
        command,
        plan["path"],
        "--spec-sha256",
        plan["sha256"],
        "--self-sha256",
        q["candidate"]["sha256"],
    ]
    receipt = write(
        v / "OWNER_HANDOFF.json",
        {
            "prepared_utc": utc(),
            "sole_physical_owner": "/root",
            "plan": plan,
            "consumer_closure": review,
            "native_source": nq["published_source_commit"],
            "namespace": q["production_bind_property"],
            "native_argv": body,
            "check_service_argv": check_service_command(
                body, q["production_bind_property"], v.name, fleet
            )
            if prior is None
            else None,
            "r2_operations": 0,
            "physical_operations": 0,
        },
    )
    os.chmod(v, 0o500)
    for folder in [v, bundles, H]:
        fd = os.open(folder, os.O_DIRECTORY)
        os.fsync(fd)
        os.close(fd)
    print(json.dumps(receipt))


def sys_isolated():
    import sys

    return sys.flags.isolated and __debug__


if __name__ == "__main__":
    main()
