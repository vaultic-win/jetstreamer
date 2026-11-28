"""Native custody checks for the single 136 writer, before V11 submission."""
import os
from pathlib import Path
import re
import stat
import subprocess

RUNTIME = Path("/var/lib/jetstreamer/horizon_runtime_data")
LOCK = Path("/run/horizon-epoch171-to136-g1.operation.lock")
WRITER = "horizon-admit-136-actual-20261120-g1.service"
PAYLOAD = "horizon-qualify-136-actual-20261120-g1.service"
HOLDING = "horizon-holding-export145-20261121-v1.service"
BASE = Path("/home/sol/.jetstreamer-private/epoch136-actual-20261120-g1")
REGISTRY = Path("/run/horizon-epoch171-exclusive-to136-g1/standard169-cpu.json")
V5E = "a99ed8b51e8a482b805b8a36a11b2700"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def native(unit):
    fields = "Id,InvocationID,MainPID,ControlPID,Job,ActiveState,SubState,NRestarts,Result,ExecMainStatus,ControlGroup"
    call = subprocess.run(["/usr/bin/systemctl", "show", unit, "-p", fields],
                          capture_output=True, text=True, timeout=8)
    require(call.returncode in (0, 4), "cannot inspect " + unit)
    result = dict(line.split("=", 1) for line in call.stdout.splitlines())
    require(result["Id"] == unit, "wrong native unit")
    return result


def process_start(proc):
    return int((proc / "stat").read_text().rsplit(")", 1)[1].split()[19])


def same_writer_lock(pid, path, boot, device, inode):
    require(Path("/proc/sys/kernel/random/boot_id").read_text().strip() == boot, "writer lock boot changed")
    proc = Path("/proc") / str(pid)
    m = path.lstat()
    require(stat.S_ISREG(m.st_mode) and stat.S_IMODE(m.st_mode) == 0o600 and
            m.st_uid == m.st_gid == 0 and m.st_nlink == 1 and (m.st_dev, m.st_ino) == (device, inode),
            "changed original operation lock")
    for fd in (proc / "fd").iterdir():
        try:
            if not os.path.samestat(m, fd.stat()):
                continue
            locks = (proc / "fdinfo" / fd.name).read_text().splitlines()
        except FileNotFoundError:
            continue
        for row in locks:
            if row.startswith("lock:"):
                fields = row.split()
                if (fields[2:6] == ["FLOCK", "ADVISORY", "WRITE", str(pid)]
                        and fields[6] == f"{os.major(device):02x}:{os.minor(device):02x}:{inode}"
                        and fields[7:] == ["0", "EOF"]):
                    require(os.path.samestat(m, path.lstat()), "writer lock changed while reading")
                    return str(fd)
    raise ValueError("writer has no exclusive untruncated operation lock")


def writer_owner(ready, fleetref, planref):
    row = native(WRITER)
    pid = int(row["MainPID"])
    proc = Path("/proc") / str(pid)
    require(row["ActiveState"] == "active" and row["SubState"] == "running" and not row["Job"] and
            row["NRestarts"] == "0" and pid == os.getppid() and re.fullmatch("[0-9a-f]{32}", row["InvocationID"]),
            "price was not requested by the live original writer")
    group = "/system.slice/" + WRITER
    require(row["ControlGroup"] == group and (proc / "cgroup").read_text().strip() == "0::" + group,
            "writer outside native service")
    argv = [os.fsdecode(v) for v in (proc / "cmdline").read_bytes().split(b"\0") if v]
    require(argv == [str(BASE / "controller/admit136"), "session", planref["path"], planref["sha256"],
                     fleetref["path"], fleetref["sha256"]], "writer command or generation changed")
    locked = ready["operation_lock"]
    require(locked["path"] == str(LOCK), "foreign operation lock")
    same_writer_lock(pid, LOCK, ready["boot_id"], locked["device"], locked["inode"])
    return dict(pid=pid, start_ticks=process_start(proc), invocation_id=row["InvocationID"])


def pending_candidate(waiter, fence, expected_writer, checked, observation):
    if fence:
        loan = fence["standard169_cpu_lease"]
        require(loan["registry"]["path"] == str(REGISTRY) and checked(loan["registry"])["standard_routes"] ==
                loan["masked_standard_routes"] and loan["cpu_quota_micros"] == 4_250_000 and
                loan["unassigned_standard169_cpu_micros"] == 4_750_000, "foreign donor fence")
    else:
        require(not os.path.lexists(REGISTRY.parent), "unexpected donor fence")
    if waiter is None:
        require(not (BASE / "admission.json").exists() and not (BASE / "reproduction").exists(),
                "foreign or stale 136 admission")
        n = native(PAYLOAD)
        require(n["ActiveState"] == "inactive" and not n["Job"] and n["MainPID"] == n["ControlPID"] == "0"
                and not (Path("/sys/fs/cgroup/system.slice") / PAYLOAD).exists(), "136 payload already present")
        return dict(cap=72 << 30, remaining=72 << 30, occupied=False, identity=None,
                    loan_micros=4_250_000 if fence else 0)
    require(fence and waiter["writer_invocation_id"] == expected_writer["invocation_id"],
            "waiting 136 lacks its writer and exclusive loan")
    live = observation()
    require(live["active_at_capture"] is True and live["phase"] == "waiting-status-and-post-fit" and
            live["unit"]["Id"] == PAYLOAD and live["unit"]["InvocationID"] == waiter["iid"] and
            int(live["unit"]["MainPID"]) == waiter["producer_pid"] and
            live["native_start_ticks"] == waiter["start_ticks"] and
            live["guard"]["plan"] == waiter["guard_plan"] and not live["guard"]["workers"],
            "136 helper or prefire differs")
    g = checked(waiter["guard_plan"])
    require(g["maximum_root_physical_bytes"] == 64 << 30, "wrong 136 physical stop")
    pid = waiter["producer_pid"]
    binary = (Path("/proc") / str(pid) / "exe").stat()
    return dict(cap=72 << 30, remaining=72 << 30, occupied=True, guard_floor=g["minimum_free_bytes"],
                loan_micros=4_250_000,
                identity=dict(unit=PAYLOAD, iid=waiter["iid"],
                              processes=[[pid, waiter["start_ticks"], binary.st_dev, binary.st_ino]]))


def holding_complete(pinned, holding_module, build, observer, semantic_iid=V5E):
    manager = native(HOLDING)
    require(manager["ActiveState"] == "inactive" and manager["SubState"] == "dead"
            and not manager["Job"] and manager["MainPID"] == manager["ControlPID"] == "0"
            and manager["NRestarts"] == "0" and manager["Result"] == "success"
            and manager["ExecMainStatus"] == "0" and not (Path("/sys/fs/cgroup/system.slice") / HOLDING).exists(),
            "holding verifier has not completed and drained")
    done, extraction = holding_module["completion"](observer, build)
    expected = RUNTIME / "epoch145-guarded-export-20261121-v1/state" / semantic_iid / "complete.json"
    require(done["path"] == str(expected) and pinned == done and extraction["epoch"] == 145,
            "wrong original successful semantic recovery")
    return done


def boundary(proof, writer, fleetref, registered):
    require(proof["schema"] == "horizon-145-136-writer-boundary-v1" and
            proof["writer"] == writer and proof["fleet"] == fleetref and proof["selector"] == registered
            and proof["post_submission_held"] is True, "unprotected successor")
    return proof["semantic_complete"]


def capture_context(fleetref, fence, waiter, *, pin, checked, runpy, json, observation, fixture_provider=None,
                    retry=False, v5n=False, v5o=False, v5q=False, v5r=False,
                    check_package=None, read_immutable=None):
    # The systemd writer and its immutable plan, not a projection from the caller,
    # select the deployed price and cross-owner inspector.
    proc = Path("/proc") / str(os.getppid())
    args = [os.fsdecode(v) for v in (proc / "cmdline").read_bytes().split(b"\0") if v]
    require(len(args) == 6 and args[0] == str(BASE / "controller/admit136") and args[1] == "session",
            "not an original 136 session")
    planref = dict(path=args[2], sha256=args[3])
    plan = json.loads(pin(Path(args[2]), args[3]))
    owner_seal = plan["controller_deployment"]
    owner_pkg = Path(owner_seal["path"]).parent
    seal = json.loads(pin(Path(owner_seal["path"]), owner_seal["sha256"]))
    require(seal["destination"] == str(owner_pkg) and owner_pkg.parent.parent == RUNTIME and owner_pkg.name == "controller", "foreign writer package")
    require(seal["sealer_sha256"] == "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3",
            "foreign sealer")
    members = {row["name"]: row for row in seal["members"]}
    require(os.path.samestat((proc / "exe").stat(), (owner_pkg / "admit136").stat()) and
            plan["controller"]["sha256"] == members["admit136"]["sha256"], "foreign session executable")
    registered = plan["holding145_prestart_ready"]
    ready_path = Path(registered["path"])
    require(ready_path.parent.parent == RUNTIME and ready_path.name == "READY.json", "foreign selector registration")
    def read(ref):
        return json.loads(pin(Path(ref["path"]), ref["sha256"]))
    ready = read(registered)
    checker = ready["boundary_inspector"]
    executable = Path(checker["path"])
    require(executable.is_relative_to(RUNTIME) and executable.parent != Path("/"), "foreign boundary inspector")
    pinned = v5o or v5q or v5r
    if v5n or pinned:
        version, writer, dispatcher = (
            ("V5R_IID", "epoch136-joint-writer-20261124-v11", "epoch145-v5r-136-dispatch-20261124-v1") if v5r else
            ("V5Q_IID", "epoch136-joint-writer-20261124-v10", "epoch145-v5q-136-dispatch-20261124-v1") if v5q else
            ("V5O_IID", "epoch136-joint-writer-20261123-v9", "epoch145-v5o-136-dispatch-20261123-v1") if v5o else
            ("IID", "epoch136-joint-writer-20261123-v8", "epoch145-v5n-136-dispatch-20261123-v1"))
        require(owner_pkg == RUNTIME / writer / "controller" and
                Path(planref["path"]) == owner_pkg.parent / "registered-production-plan.json" and
                ready_path == RUNTIME / dispatcher / "READY.json", "foreign semantic writer or selector")
        module = owner_pkg / "v5n_boundary.py"
        pin(module, members[module.name]["sha256"])
        successor = runpy.run_path(str(module))
        require(ready["schema"] == "horizon-145-136-prestart-selector-ready-v1" and
                ready["original_semantic_invocation"] == successor[version] and
                ready["registered_provider"] == plan["joint_fit_145"], "foreign semantic boundary")
        if not pinned:
            require(plan["holding145_semantic_worker"] == successor["SEMANTIC_RESULT"] and
                    plan["holding145_completion"] == successor["COMPLETION_TOOLS"], "foreign V5n boundary")
        require(executable == ready_path.parent / "tools/boundary-inspector" and
                ready["deployment"]["path"] == str(executable.parent / "deployment-seal-receipt.json"),
                "foreign semantic boundary inspector")
        deployment = check_package(executable.parent, ready["deployment"]["sha256"])
        require(sum(row["name"] == executable.name and row["sha256"] == checker["sha256"] and row["mode"] == "0555"
                    for row in deployment["members"]) == 1, "unsealed semantic boundary inspector")
        directory = (successor["V5R_PROVIDER"] if v5r else successor["V5Q_PROVIDER"] if v5q else successor["V5O_PROVIDER"] if v5o else
                     RUNTIME / "incident-replay-fit-20261121-v1/tools-homefloor-145-post-v5n-136-v1")
        provider = fixture_provider(ready["registered_provider"], directory)
        price = runpy.run_path(str(provider))
    elif fixture_provider is not None:
        writer = "epoch136-joint-writer-20261122-v7c" if retry else "epoch136-joint-writer-20261122-v7b"
        require(owner_pkg == RUNTIME / writer / "controller", "foreign V7 controller")
        module = owner_pkg / "fixture_boundary.py"
        pin(module, members[module.name]["sha256"])
        fixture = runpy.run_path(str(module))
        iid, price, build, verifier = fixture["prepare"](planref, plan, registered, ready, read, checked, pin,
                                                         fixture_provider, runpy, retry=retry)
    else:
        for name in ("admit136", "post-stop-fit", "retire-original-timers.py", "closure.py", "idle_floor.py",
                     "idle_audit_cpu.py", "incident_extensions.py"):
            pin(owner_pkg / name, members[name]["sha256"])
        require(ready["schema"] == "horizon-145-136-prestart-selector-ready-v1" and
                ready["original_semantic_invocation"] == V5E, "unregistered holding selector")
        pin(executable, checker["sha256"])
        price = runpy.run_path(str(owner_pkg / "post-stop-fit"))
        v11 = RUNTIME / "epoch145-semantic-continuity-20261121-v1/tools-v11"
        build = json.loads(pin(v11 / "build-proof.json", "96db190a72ce8057c32a46b5128d9918ffcf0e771ca5cd306f57529fb7c6b4b7"))
        pin(v11 / "incident-post-phase.py", "6e3fde964884be35641212a0016072c214653004110b1e1391f0818a9179d4a6")
        verifier = runpy.run_path(str(v11 / "incident-post-phase.py"))
        iid = V5E

    def current(fleet, status):
        require(fleet["schema"] == "horizon-Root-complete-fleet-operational-review-v1" and
                status["consumer_seal"] == ready["status_consumer_seal"], "status consumer changed")
        writer = writer_owner(ready, fleetref, planref)
        call = subprocess.run([str(executable), str(ready_path), registered["sha256"], str(writer["pid"]),
                               str(writer["start_ticks"]), writer["invocation_id"], fleetref["path"], fleetref["sha256"]],
                              check=True, capture_output=True, timeout=12)
        require(len(call.stdout) < 65536, "oversized selector proof")
        proof = json.loads(call.stdout)
        completion = boundary(proof, writer, fleetref, registered)
        if pinned:
            joined = successor["inspect_v5o"](plan, pin, check_package, read_immutable,
                                  successor["read_inputs"], successor["read_phase"], v5q=v5q, v5r=v5r)
            require(not joined["semantic_pending"] and joined["semantic_complete"] == completion,
                    "different pinned semantic completion or native handoff")
        elif v5n:
            joined = successor["inspect"](pin, check_package, read_immutable, successor["read_inputs"],
                                         successor["read_phase"])
            require(not joined["semantic_pending"] and joined["semantic_complete"] == completion,
                    "different original V5n completion or native handoff")
        else:
            holding_complete(completion, verifier, build, price["s"], iid)
        candidate = pending_candidate(waiter, fence, writer, checked, observation)
        return dict(candidate, writer=writer, selector=registered, semantic_complete=proof["semantic_complete"])

    return price["capture"](145, fleetref, prestart136=current)
