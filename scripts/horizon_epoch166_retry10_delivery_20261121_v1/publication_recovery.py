"""Reconcile an original sync controller's durable admission before retrying delivery."""
import json
import os
from pathlib import Path
import re
import subprocess
import time

import terminal_event as event

IID = re.compile(r"[a-f0-9]{32}")
STARTED = "39f53479d3a045ac8e11786248231fbf"
FIELDS = ("Id,LoadState,ActiveState,SubState,Result,MainPID,ControlPID,Job,InvocationID,"
          "ExecMainPID,ExecMainCode,ExecMainStatus,Transient,ControlGroup")
VERSION = "horizon-publication-event-recovery-v1"


def checked(path):
    return event.document(path, 0o400, 2 << 20)


def boot():
    return Path("/proc/sys/kernel/random/boot_id").read_text().strip()


def journal(*filters):
    raw = subprocess.check_output(["/usr/bin/journalctl", "-b", "-ojson", "--no-pager",
        "--output-fields=UNIT,INVOCATION_ID,MESSAGE_ID,_PID,_EXE,_SYSTEMD_INVOCATION_ID,_SYSTEMD_UNIT,MESSAGE",
        *filters], timeout=20)
    return [json.loads(line) for line in raw.splitlines()]


def manager(unit):
    out = subprocess.run(["/usr/bin/systemctl", "show", unit, "--property=" + FIELDS],
                         capture_output=True, text=True, timeout=12)
    props = dict(line.split("=", 1) for line in out.stdout.splitlines())
    event.need(out.returncode in (0, 4) and props.get("Id") == unit and
               all(k in props for k in FIELDS.split(",")), "missing manager properties")
    return props


def unoccupied(p):
    return (p["LoadState"], p["ActiveState"], p["SubState"], p["MainPID"], p["ControlPID"],
            p["Job"], p["InvocationID"]) == ("not-found", "inactive", "dead", "0", "0", "", "")


def exec_start(unit):
    bus = ["/usr/bin/busctl", "--system", "--json=short"]
    name = "org.freedesktop.systemd1"
    def call(*args):
        return json.loads(subprocess.check_output([*bus, *args], timeout=12))
    unit_path = call("call", name, "/org/freedesktop/systemd1", name + ".Manager", "GetUnit", "s", unit)
    event.need(unit_path["type"] == "o" and len(unit_path["data"]) == 1, "invalid PID1 unit object")
    prop = call("get-property", name, unit_path["data"][0], name + ".Service", "ExecStart")
    event.need(prop["type"] == "a(sasbttttuii)" and len(prop["data"]) == 1, "ambiguous manager command")
    return prop["data"][0]


def admissions(profile, terminal):
    prepared, authorized = set(), []
    for p in profile.delivery.glob("run-*/admission.json"):
        iid = p.parent.name.removeprefix("run-")
        body, ref = checked(p)
        event.need(IID.fullmatch(iid) and body.get("invocation_id") == iid and
                   body.get("epoch") == profile.epoch and body.get("unit") == profile.unit and
                   body.get("schema") == f"horizon-epoch{profile.epoch}-committed-publication-admission-v1" and
                   body.get("operation") == "current-reader-sync-retain-local" and
                   body.get("publication_authorized") in (True, False) and
                   isinstance(body["publication_authorized"], bool), "foreign admission")
        if body["publication_authorized"]:
            event.need(body["terminal_sha256"] == terminal["sha256"], "foreign admitted terminal")
            body_terminal, tr = checked(Path(terminal["path"]))
            cap, cr = checked(p.parent / "capacity.json")
            archive = body_terminal["local_archive"]
            event.need(tr == terminal and body["transaction_id"] == body_terminal["transaction_id"] and
                       body["archive_bytes"] == archive["size"] and body["archive_sha256"] == archive["sha256"] and
                       body["archive_inode"] == archive["inode"] and body["archive_device"] == archive["device"] and
                       cr == body["capacity"] and cap["terminal"] == terminal and cap["invocation_id"] == iid and
                       cap["boot_id"] == body["boot_id"], "native admission does not bind original archive and capacity")
            authorized.append(ref)
        else:
            prepared.add(iid)
    event.need(len(authorized) <= 1, "multiple native sync admissions")
    return prepared, authorized


def classify(profile, intent, known, native, command, history, fit_errors):
    """Classify an exact systemd owner. A failed unrelated job is never reset."""
    iid = native["InvocationID"]
    if unoccupied(native):
        return "absent" if set(history) <= known else "uncertain"
    if (native["Transient"] != "yes" or not IID.fullmatch(iid) or not intent or
            iid in known or set(history) - known - {iid}):
        return "uncertain"
    binary = str(Path(intent["controller"]).with_name("controller"))
    argv = [binary, "sync", intent["fleet"]["path"], intent["fleet"]["sha256"], intent["provider_sha256"]]
    if command is None or command[:3] != [binary, argv, False] or len(command) != 10:
        return "uncertain"
    if native["Job"] or native["ControlPID"] != "0":
        return "uncertain"
    pid = native["ExecMainPID"]
    if not pid.isdecimal() or int(pid) <= 1 or command[7] not in (0, int(pid)):
        return "uncertain"
    if (native["ActiveState"], native["SubState"], native["MainPID"]) == ("active", "running", pid):
        return "running" if STARTED in history.get(iid, ()) else "uncertain"
    if ((native["ActiveState"], native["SubState"], native["Result"], native["MainPID"],
          native["ExecMainCode"], native["ExecMainStatus"]) != ("failed", "failed", "exit-code", "0", "1", "1")
            or command[8:] not in ([0, 0], [1, 1]) or STARTED not in history.get(iid, ())):
        return "uncertain"
    for row in fit_errors:
        if (row.get("_BOOT_ID") == boot().replace("-", "") and row.get("_SYSTEMD_UNIT") == profile.unit
                and row.get("_SYSTEMD_INVOCATION_ID") == iid and row.get("_EXE") == binary and row.get("_PID") == pid
                and row.get("MESSAGE", "").startswith(("Error: fresh publication fit failed:",
                                                      "Error: incomplete, stale or non-fitting terminal capacity"))):
            return "fit-refused"
    return "uncertain"


def observe(profile, terminal, intent, known):
    prepared, authorized = admissions(profile, terminal)
    if authorized:
        return "admitted", {"admission": authorized[0]}
    native = manager(profile.unit)
    history = {}
    for row in journal("_PID=1", "UNIT=" + profile.unit):
        iid = row.get("INVOCATION_ID")
        if iid:
            event.need(IID.fullmatch(iid) and row["_BOOT_ID"] == boot().replace("-", ""), "foreign manager journal")
            history.setdefault(iid, []).append(row.get("MESSAGE_ID"))
    command = None if unoccupied(native) or native["LoadState"] != "loaded" else exec_start(profile.unit)
    iid = native["InvocationID"]
    errors = journal("_SYSTEMD_INVOCATION_ID=" + iid, "_PID=" + native["ExecMainPID"]) if (
        native["ActiveState"] == "failed" and IID.fullmatch(iid) and native["ExecMainPID"].isdigit()) else []
    _, authorized = admissions(profile, terminal)
    if authorized:
        return "admitted", {"admission": authorized[0]}
    if native["ActiveState"] == "active" and native["MainPID"].isdigit() and int(native["MainPID"]) > 1:
        proc = Path("/proc") / native["MainPID"]
        if (not intent or os.readlink(proc / "exe") != str(Path(intent["controller"]).with_name("controller")) or
                (proc / "cgroup").read_text().strip() != "0::" + native["ControlGroup"] or
                native["ControlGroup"] != "/system.slice/" + profile.unit):
            return "uncertain", dict(manager=native)
    if manager(profile.unit) != native:
        raise RuntimeError("publication manager changed during reconciliation")
    result = classify(profile, intent, known | prepared, native, command, history, errors)
    return result, dict(manager=native, exec_start=command, boot=boot(), manager_ids=sorted(history))


def launch(profile, intent, socket):
    """Persist a positive pre-systemd rejection only for a completed, traced sealed preflight."""
    env = dict(os.environ)
    env.pop("BASH_ENV", None)
    env.pop("SHELLOPTS", None)
    fd = os.memfd_create("publication-launch-trace", os.MFD_CLOEXEC)
    try:
        env["BASH_XTRACEFD"] = str(fd)
        env["PS4"] = "+ "
        cmd = ["/bin/bash", "-x", profile.launch, "sync", intent["fleet"]["path"], intent["fleet"]["sha256"],
               socket, intent["provider_sha256"]]
        result = subprocess.run(cmd, env=env, pass_fds=(fd,), timeout=50)
        data = os.pread(fd, (64 << 10) + 1, 0)
    finally:
        os.close(fd)
    lines = data.decode().splitlines()
    preflight = {"+ test -f " + str(profile.authority.T / "TERMINAL_SUCCESS.json"), "+ test -S " + str(socket),
                 "+ /usr/sbin/runuser -u sol -- env SSH_AUTH_SOCK=" + str(socket) + " ssh-add -l",
                 "+ sha256sum --check --strict --status SHA256SUMS"}
    return dict(returncode=result.returncode, pre_manager_refusal=bool(
        0 < result.returncode < 128 and len(data) <= 64 << 10 and lines and lines[-1] in preflight and
        not any("/usr/bin/systemd-run" in line for line in lines)))


def path_for(state, seq, kind):
    if seq == 0 and kind == "intent":
        return state / "INTENT.json"
    return state / f"recovery-{seq:06d}-{kind}.json"


def chain(state, terminal, profile, allowed):
    attempts, known = [], set()
    seq = 0
    while (p := path_for(state, seq, "intent")).exists():
        intent, ref = checked(p)
        event.need(intent["terminal"] == terminal and intent["unit"] == profile.unit and
                   intent.get("controller") in allowed and intent.get("provider_sha256") == allowed[intent["controller"]]
                   and not intent.get("existing"), "foreign or previously occupied publication intent")
        legacy = seq == 0 and "recovery_schema" not in intent
        if legacy:
            event.need(intent["observed_unix_seconds"] >= time.time() - time.clock_gettime(time.CLOCK_BOOTTIME),
                       "legacy intent belongs to an earlier boot")
        else:
            event.need(intent["recovery_schema"] == VERSION and intent["boot"] == boot() and intent["prior"] ==
                       (attempts[-1][3] if attempts else None), "invalid recovery chain")
        closed = path_for(state, seq, "retryable")
        end = None
        if closed.exists():
            proof, end = checked(closed)
            event.need(proof["attempt"] == ref and proof["boot"] == boot() and
                       proof["reason"] in ("fit-refused", "pre-manager-refusal"), "crossed retry evidence")
            if proof["reason"] == "fit-refused":
                known.add(proof["native"]["manager"]["InvocationID"])
        attempts.append((intent, ref, end is not None, end))
        if end is None:
            break
        seq += 1
    submitted = state / "SUBMISSION.json"
    if submitted.exists():
        old, _ = checked(submitted)
        event.need(attempts and old["unit"] == profile.unit and old["terminal"] == terminal and
                   old["manager"]["Id"] == profile.unit, "different immutable prior submission")
        if old.get("recovery_schema") == VERSION:
            event.need(any(old["attempt"] == ref and old["fleet"] == intent["fleet"]
                           for intent, ref, _, _ in attempts), "submission belongs to a different attempt")
        else:
            event.need(old["fleet"] == attempts[0][0]["fleet"], "different original submission fleet")
    return attempts, known


def service(profile, state, terminal, fit, accepted, changes, predecessors=None):
    allowed = dict(predecessors or {})
    allowed[str(profile.launch)] = fit
    result = reconcile(profile, state, terminal, fit, accepted, changes, allowed)
    submission = state / "SUBMISSION.json"
    first = state / "INTENT.json"
    if submission.exists() or not first.exists() or checked(first)[0].get("existing"):
        return result
    body, ref = checked(Path(result["admission"]["path"]))
    cap, cap_ref = checked(Path(body["capacity"]["path"]))
    event.need(ref == result["admission"] and cap_ref == body["capacity"], "admission changed before recording")
    attempts, _ = chain(state, terminal, profile, allowed)
    matching = [(intent, attempt) for intent, attempt, _, _ in attempts if intent["fleet"] == cap["fleet"]
                and intent["provider_sha256"] == cap["provider"]["sha256"]]
    if matching:
        event.need(len(matching) == 1, "multiple intents for one native sync admission")
        intent, attempt = matching[0]
        event.once(submission, dict(intent, recovery_schema=VERSION, attempt=attempt, manager=manager(profile.unit),
                                    admitted_invocation_id=body["invocation_id"], admission=ref))
    return result


def reconcile(profile, state, terminal, fit, accepted, changes, allowed):
    while True:
        # Native sync side effects begin strictly after write_admission() fsyncs this exact record.
        _, admitted = admissions(profile, terminal)
        if admitted:
            return dict(disposition="native-sync-admission", admission=admitted[0])
        attempts, known = chain(state, terminal, profile, allowed)
        current = attempts[-1] if attempts else None
        if current and not current[2]:
            intent, ref = current[:2]
            disposition, native = observe(profile, terminal, intent, known)
            old_submission = state / "SUBMISSION.json"
            if len(attempts) == 1 and old_submission.exists() and disposition in ("running", "fit-refused"):
                prior_manager = checked(old_submission)[0]["manager"]
                event.need(prior_manager.get("InvocationID") in ("", native["manager"]["InvocationID"]),
                           "prior submission names another manager invocation")
            if disposition == "admitted":
                return dict(disposition="native-sync-admission", **native)
            if disposition == "running":
                time.sleep(3)
                continue
            seq = len(attempts)-1
            outcome_path = path_for(state, seq, "launcher")
            if disposition == "absent" and outcome_path.exists():
                outcome, _ = checked(outcome_path)
                if outcome["attempt"] == ref and outcome["result"]["pre_manager_refusal"]:
                    disposition = "pre-manager-refusal"
            event.need(disposition in ("fit-refused", "pre-manager-refusal"),
                       "existing intent requires reconciliation; manager state " + disposition)
            event.once(path_for(state, seq, "retryable"), dict(attempt=ref, boot=boot(), reason=disposition, native=native))
            continue
        proof = accepted()
        if not proof or any(i[0]["fleet"] == proof["fleet"] for i in attempts):
            changes.wait()
            continue
        socket = event.agents()
        event.need(profile.authority.inspect()["terminal"] == terminal, "original terminal changed")
        # Failed transient units remain loaded until reset. Only reset an exact positively proved failure.
        if current:
            last, _ = checked(path_for(state, len(attempts)-1, "retryable"))
            if last["reason"] == "fit-refused":
                iid = last["native"]["manager"]["InvocationID"]
                status, native = observe(profile, terminal, current[0], known - {iid})
                if status == "admitted":
                    return dict(disposition="native-sync-admission", **native)
                if status == "fit-refused" and native["manager"]["InvocationID"] == iid:
                    subprocess.run(["/usr/bin/systemctl", "reset-failed", profile.unit], check=True, timeout=12)
        status, native = observe(profile, terminal, None, known)
        if status == "admitted":
            return dict(disposition="native-sync-admission", **native)
        event.need(status == "absent", "refusing to displace a known or uncertain publication unit")
        if accepted() != proof:
            continue
        seq = len(attempts)
        path = path_for(state, seq, "intent")
        intent = dict(recovery_schema=VERSION, terminal=terminal, **proof, unit=profile.unit, boot=boot(),
                      controller=str(profile.launch), provider_sha256=fit, ssh_socket=str(socket),
                      observed_unix_seconds=int(time.time()), prior=current[3] if current else None)
        event.once(path, intent)
        _, ref = checked(path)
        result = launch(profile, intent, socket)
        event.once(path_for(state, seq, "launcher"), dict(attempt=ref, result=result))
