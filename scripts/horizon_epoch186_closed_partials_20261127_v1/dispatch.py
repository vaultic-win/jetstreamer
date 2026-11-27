"""Price and run one epoch 186 phase using a fresh transient service."""

from pathlib import Path
import argparse, fcntl, json, os, re, subprocess, sys, time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rotation as op


def dispatch(phase, lane):
    op.need(os.getuid() == 0, "the native dispatch requires root")
    op.deployment(phase, lane)
    d = op.OUT / lane
    row = op.source(lane)
    runid = str(time.time_ns())
    unit = "horizon-closed186-" + phase + "-" + lane + "-" + runid + ".service"
    proof = {
        "fixture": op.OUT / "RESTORE_FIXTURE_ACCEPTED.json",
        "park": d / "PARK_ACCEPTED.json",
        "retire": d / "RETIRED.json",
        "restore": d / "RESTORED.json",
    }.get(phase)
    if proof and proof.exists():
        record = op.bound(op.ref(proof))
        op.need(record["success"], "incomplete previous phase")
        if phase == "restore":
            path = Path(row["source"])
            saved = op.bound(record["output"])["restored"]
            op.need(
                op.stamp(path) == saved["identity"]
                and saved["sha256"] == row["sha256"],
                "restored original changed",
            )
        if phase == "retire":
            op.need(
                not Path(row["source"]).exists(),
                "source again present after retirement",
            )
        return op.ref(proof)
    hard, quota, timeout = {
        "fixture": ("256M", "25%", "3min"),
        "precheck": ("256M", "25%", "3min"),
        "park": ("2G", "200%", "3h"),
        "retire": ("1G", "100%", "40min"),
        "restore": ("2G", "100%", "3h"),
    }[phase]
    evidence = d / ("OUTPUT_" + phase + "_" + runid + ".json")
    err = d / ("STDERR_" + phase + "_" + runid)
    arg = ["systemd-run", "--quiet", "--service-type=exec", "--unit=" + unit]
    props = [
        "CPUQuota=" + quota,
        "MemoryMax=" + hard,
        "MemorySwapMax=0",
        "RuntimeMaxSec=" + timeout,
        "Restart=no",
        "TasksMax=256",
        "UMask=0077",
        "Nice=12",
        "IOSchedulingClass=idle",
        "ProtectSystem=strict",
        "ProtectHome=read-only",
        "PrivateDevices=yes",
        "NoNewPrivileges=yes",
        "PrivateTmp=yes",
        "LimitCORE=0",
        "Environment=HORIZON186_RUN_ID=" + runid,
        "EnvironmentFile=/etc/jetstreamer/horizon-r2.env",
        "ReadWritePaths=" + str(d),
        "ReadOnlyPaths=" + str(op.TOOLS),
        "StandardOutput=file:" + str(evidence),
        "StandardError=file:" + str(err),
    ]
    if phase == "fixture":
        props.append("ReadWritePaths=" + str(op.OUT / "fixture"))
    if phase == "park":
        props.append("ReadWritePaths=" + str(op.HOLD))
    if phase in ("restore", "retire"):
        props.append("ReadWritePaths=" + str(Path(row["source"]).parent))
    for v in props:
        arg += ["-p", v]
    argv = arg + [
        "--",
        "/usr/bin/python3",
        "-IB",
        str(op.TOOLS / "rotation.py"),
        phase,
        lane,
    ]
    op.fixed(
        op.PROVIDER, "a8d2139c524f06d38329cb9c7ab00ab036f26f1adbba3b3b501b365511fed471"
    )
    ops = __import__("runpy").run_path(str(op.PROVIDER))
    rbytes = {
        "fixture": 256 * op.M,
        "precheck": 256 * op.M,
        "park": 2 * op.G,
        "retire": op.G,
        "restore": 2 * op.G,
    }[phase]
    reserve = 16 * op.M if phase in ("park", "restore", "retire") else 2 * op.M
    if phase == "restore" and not Path(row["source"]).exists():
        reserve = op.read(d / "expected.json")["single_copy_peak"]
    if phase in ("fixture", "precheck"):
        rbytes += 2 * op.G  # independent of the serial park
    with op.phase_quote(phase, reserve, rbytes) as q:
        if phase not in ("fixture", "precheck"):
            op.serial_handoff()
        op.need(
            q["remaining_ram"] >= rbytes and q["remaining_home"] >= reserve,
            "insufficient fit "
            + str((q["remaining_ram"] - rbytes, q["remaining_home"] - reserve)),
        )
        start = op.save(
            d / ("START_" + phase + "_" + runid + ".json"),
            dict(
                utc=time.time(),
                unit=unit,
                phase=phase,
                full_fleet=q,
                extra_memory=rbytes,
                extra_home=reserve,
                source=row["source"],
                command=argv,
            ),
        )
        subprocess.run(argv, check=True)
        state = ops["props"](unit)
        iid = state["InvocationID"]
        op.need(
            re.fullmatch("[0-9a-f]{32}", iid) is not None, "missing native invocation"
        )
    terminal = ops["terminal"](unit, iid, int(state["MainPID"]))
    op.save(d / ("TERMINAL_" + phase + "_" + runid + ".json"), terminal)
    op.need(terminal["success"], "failed phase, see " + str(err))
    for p in (evidence, err):
        os.chmod(p, 0o400)
    # The sealed R2 driver may also print a one-line custody record on stdout.
    result = json.loads(evidence.read_text().strip().splitlines()[-1])
    record = dict(
        success=True,
        unit=unit,
        invocation=iid,
        native_terminal=terminal,
        output=op.ref(evidence),
        stderr=op.ref(err),
        start=start,
    )
    if phase == "fixture":
        op.need(
            result["atomic_noclobber"]
            and result["changed_etag_status"] == 412
            and result["whole_disk_readback"]
            and result["one_inode"],
            "incomplete restore fixture",
        )
    if phase == "park":
        record["native_custody"] = result["native_custody"]
        op.bound(record["native_custody"])
    if phase == "retire":
        record.update(result)
    target = proof if proof else d / ("REMOTE_PRECHECK_" + runid + ".json")
    return op.save(target, record)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument(
        "phase", choices=["fixture", "precheck", "park", "retire", "restore"]
    )
    p.add_argument("lane", choices=["m", "n"])
    a = p.parse_args()
    print(json.dumps(dispatch(a.phase, a.lane)), flush=True)
