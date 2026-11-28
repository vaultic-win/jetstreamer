"""Submit the original epoch 166 publisher once, after the accepted cadence report."""

import ctypes
import datetime as dt
import fcntl
import hashlib
from itertools import combinations
import json
import os
import pwd
import re
import stat
import struct
import subprocess
import tempfile
import time
from pathlib import Path

R = Path("/var/lib/jetstreamer/horizon_runtime_data")
REPORTS = Path("/home/sol/.jetstreamer-private/r2-status-receipts")
ROOT = R / "epoch166-publication-event-20261121-v1"
TERMINAL = R / "epoch166-terminal-20261121-v1/TERMINAL_SUCCESS.json"
NATIVE = TERMINAL.parent / "cadence-tools-v3/terminal166"
PARENT = R / "epoch166-post168-cadence-20261121-v1/parent-package/parent136"
DELIVERY = R / "epoch166-committed-delivery-20261121-v1"
LAUNCH = DELIVERY / "controller-v1/run-committed.sh"
FIT = R / "epoch166-publication-capacity-20261121-v1/tools/publication-fit"
FIT_SHA = "d291098e7f1811c032e21cbf92acbca9ee747d128e5d34b782248c2ac94f8430"
UNIT = "horizon-publish-166-committed.service"
GEN = "fa16ee2f14fe44ecbc37c59e197553ac"
PROGRAMS = (
    (NATIVE, "43c67cdd9b7265d29ea806675a0a7aad5a2ef6384471452061b46d7465a00997"),
    (PARENT, "8c02ea20cb8231c66c2f6471a1d9ecf6e7c4bbbd3810dd9b3c1e2aa27fb4e316"),
    (LAUNCH, "dc960202f6001cd8dd0bfe35447cfafecb54e628e58d4ae9b844ec198fbb431d"),
    (FIT, FIT_SHA),
)
FLEET_NAME = "ROOT_COMPLETE_OPERATIONAL_FLEET.json"
CYCLE = re.compile(r"root(\d{6})-live166167170-(\d{8})-v1")
EPOCHS = {136,137,141,145,159,161,163,166,167,168,169,170,171,172,173,185,186,199,200}
COMPLETION_LABELS = {166: "recovered166", 167: "indexed167", 168: "metered168", 170: "recovered170"}


PUBLICATION_EPOCHS = (166, 167, 168, 170)


def report_labels():
    return {**COMPLETION_LABELS, 172: "full172"}


def completion_report_dir(root, epochs):
    ordered = tuple(sorted(epochs))
    if not ordered:
        return root
    need(len(set(ordered)) == len(ordered) and all(e in report_labels() for e in ordered),
         "unknown or duplicate local completion")
    suffix = report_labels()[ordered[0]] if len(ordered) == 1 else "-".join(map(str, ordered))
    return root / ("after-" + suffix)


def registered_report(root, fleet, field):
    registered = fleet["authenticated_status_audit"]["path"]
    base = root / "COMPLETED.json"
    if registered == str(base):
        return base
    fields = {epoch: label + "_local_commit" for epoch, label in report_labels().items()}
    need(field in fields.values(), "crossed cadence report")
    committed = [epoch for epoch, key in fields.items() if fleet.get(key)]
    for size in range(1, len(committed) + 1):
        for group in combinations(committed, size):
            candidate = completion_report_dir(root, group) / base.name
            if registered == str(candidate):
                return candidate
    raise Rejected("crossed or unregistered terminal status directory")


class Rejected(ValueError):
    pass


def need(ok, message):
    if not ok:
        raise Rejected(message)


def member(path, mode, cap=32 << 20):
    need(path.is_absolute() and path.resolve(strict=True) == path, "noncanonical member")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as src:
        m = os.fstat(fd)
        need(stat.S_ISREG(m.st_mode) and m.st_uid == m.st_gid == 0 and m.st_nlink == 1
             and stat.S_IMODE(m.st_mode) == mode and m.st_size <= cap, f"member custody: {path}")
        data = src.read(cap + 1)
        def identity(s):
            return s.st_dev, s.st_ino, s.st_size, s.st_mode, s.st_ctime_ns, s.st_mtime_ns
        need(len(data) == m.st_size and identity(os.fstat(fd)) == identity(m) == identity(path.lstat()),
             "member changed during read")
    return data, dict(path=str(path), sha256=hashlib.sha256(data).hexdigest())


def document(path, mode, cap=32 << 20):
    data, ref = member(path, mode, cap)
    return json.loads(data), ref


def once(path, value):
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as f:
        try:
            f.write(json.dumps(value, sort_keys=True).encode() + b"\n")
            f.flush()
            os.fchmod(f.fileno(), 0o400)
            os.fsync(f.fileno())
            rename = ctypes.CDLL(None, use_errno=True).renameat2
            if rename(-100, os.fsencode(f.name), -100, os.fsencode(path), 1):
                raise OSError(ctypes.get_errno(), f"publish {path}")
        finally:
            Path(f.name).unlink(missing_ok=True)
    directory = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def terminal_evidence(path, native, boot):
    data, ref = document(path, 0o400, 1 << 20)
    need(data["schema"] == "terminal166-success-v1" and data["epoch"] == 166
         and data["producer_invocation_id"] == GEN and data["terminal_166_disposition"] == "node-published-local-cohort"
         and data["manager_terminal"]["_BOOT_ID"] == boot.replace("-", "")
         and data["resource_credit_bytes"] == data["reservation_ending_bytes"] == 0
         and data["canonical_r2_verified"] is False and data["archive_publication_authorized"] is False,
         "terminal is foreign or for another boot")
    need(native() == data, "native original termination or committed artifact changed")
    return ref


class Changes:
    """Watch first, inspect second, then sleep until a relevant directory entry changes."""
    def __init__(self):
        self.lib = ctypes.CDLL(None, use_errno=True)
        self.fd = self.lib.inotify_init1(os.O_CLOEXEC)
        self.seen = set()
        if self.fd < 0:
            raise OSError(ctypes.get_errno(), "inotify_init1")

    def watch(self, path):
        if path not in self.seen:
            wd = self.lib.inotify_add_watch(self.fd, os.fsencode(path), 0x100 | 0x80 | 0x8 | 0x400 | 0x800)
            if wd < 0:
                raise OSError(ctypes.get_errno(), f"inotify_add_watch {path}")
            self.seen.add(path)

    def wait(self):
        while True:
            batch = os.read(self.fd, 65536)
            pos = 0
            while pos < len(batch):
                _, mask, _, n = struct.unpack_from("iIII", batch, pos)
                raw = batch[pos+16:pos+16+n].rstrip(b"\0")
                pos += 16+n
                name = os.fsdecode(raw)
                if mask & (0x4000 | 0x400 | 0x800 | 0x8000):
                    self.seen.clear()
                    return
                if name in (FLEET_NAME, "COMPLETED.json") or CYCLE.fullmatch(name) or name.startswith("cycle"):
                    return

    def close(self):
        os.close(self.fd)


def head(fleet):
    return json.loads(subprocess.check_output(
        [PARENT, "inspect-status", fleet["path"], fleet["sha256"]], timeout=35))["fleet"]


def sample_time(fleet, directory, scheduled):
    sampled = fleet["sampled_at_utc"]
    if sampled == scheduled:
        return sampled
    path = R / ("sample-" + directory.name + ".json")
    sample, ref = document(path, 0o644)
    cadence = sample["cadence"]
    need(fleet["observer"] == ref and sample["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
         and cadence["observation_reason"] == "routine" and cadence["routine_minimum_interval_enforced"] is True
         and cadence["configured_not_before_utc"] == scheduled and sample["recorded_at_utc"] == sampled
         and scheduled <= sampled <= sample["completed_at_utc"], "wrong scheduled or observed sample time")
    return sampled


def accepted(runtime, reports, expected, changes, checked_head, now, field="terminal166_local_commit", check_status=None):
    changes.watch(runtime)
    changes.watch(reports)
    paths = []
    for p in runtime.glob("root??????-live166167170-????????-v1"):
        match = CYCLE.fullmatch(p.name)
        if not match:
            continue
        tag, day = match.groups()
        stamp = dt.datetime.strptime(day+tag, "%Y%m%d%H%M%S").replace(tzinfo=dt.timezone.utc).timestamp()
        if stamp <= now:
            paths.append((stamp,p,tag,day))
    for stamp, directory, tag, day in sorted(paths, reverse=True):
        changes.watch(directory)
        path = directory / FLEET_NAME
        if not path.exists():
            continue
        fleet, ref = document(path, 0o600)
        need(fleet["owner"] == "/root", "wrong root cadence")
        if not 0 <= now-fleet["recorded_unix_seconds"] <= 2400 or not fleet.get(field):
            return None
        scheduled = dt.datetime.fromtimestamp(stamp,dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        sampled = sample_time(fleet, directory, scheduled)
        need(fleet[field] == expected, "different local terminal in fleet")
        report_dir = reports / f"cycle{tag}-live166167170-19-{day}-v1"
        if not report_dir.exists():
            return None
        changes.watch(report_dir)
        rp = registered_report(report_dir, fleet, field)
        if rp.parent != report_dir:
            changes.watch(rp.parent)
        if not rp.exists():
            return None
        doc, report = document(rp,0o600,8 << 20)
        need(fleet["authenticated_status_audit"] == report and fleet["all_active_status_reports_authenticated_readback"] is True
             and fleet["authenticated_status_count"] == 19 and doc["schema"] == "horizon-status-full-range-audit-v1"
             and doc["owner"] == "/root" and doc["sampled_at_utc"] == sampled and doc["observer"] == fleet["observer"]
             and doc["authenticated_readback"] is True and doc["all_nineteen_existing_statuses_authenticated"] is True
             and doc["archive_or_sidecar_mutations"] is False and set(doc["status_epochs"]) == EPOCHS
             and set(doc["receipts"]) == {str(e) for e in EPOCHS}
             and doc["authenticated_status_count"] == 19, "unbound authenticated cadence report")
        if checked_head(ref) != ref:
            return None
        proof=dict(fleet=ref, report=report)
        if check_status:
            proof["status"]=check_status(fleet,doc,expected)
        return proof
    return None


def agents():
    sol = pwd.getpwnam("sol")
    runtime = Path("/run/user") / str(sol.pw_uid)
    candidates = set(Path("/tmp").glob("ssh-*/agent.*"))
    candidates.update(runtime.glob("ssh-agent*"))
    candidates.update((Path(sol.pw_dir)/".ssh/agent").glob("*"))
    candidates.add(runtime/"keyring/ssh")
    if os.environ.get("SSH_AUTH_SOCK"):
        candidates.add(Path(os.environ["SSH_AUTH_SOCK"]))
    for path in sorted(candidates):
        try:
            m = path.lstat()
            if not stat.S_ISSOCK(m.st_mode) or m.st_uid != sol.pw_uid or path.resolve(strict=True) != path:
                continue
            prefix = ["/usr/sbin/runuser","-u","sol","--","/usr/bin/env","-i","HOME="+sol.pw_dir,
                      "PATH=/usr/bin:/bin","SSH_AUTH_SOCK="+str(path),"GIT_TERMINAL_PROMPT=0",
                      "GIT_SSH_COMMAND=/usr/bin/ssh -o BatchMode=yes -o ConnectTimeout=6"]
            for args in (["/usr/bin/ssh-add","-l"],["/usr/bin/git","-C","/home/sol/workspace/jetstreamer",
                         "ls-remote","--exit-code","origin","refs/heads/account-updates"]):
                subprocess.run(prefix+args, check=True, timeout=12, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if (path.stat().st_dev,path.stat().st_ino)==(m.st_dev,m.st_ino):
                return path
        except (OSError,subprocess.SubprocessError):
            continue
    raise RuntimeError("no current sol SSH agent authenticated the branch")


def manager(unit=UNIT):
    result = subprocess.run(["/usr/bin/systemctl","show",unit,"-p",
        "Id,ActiveState,SubState,InvocationID,MainPID,ControlPID,Job,LoadState,Result"],capture_output=True,text=True,timeout=10)
    row=dict(line.split("=",1) for line in result.stdout.splitlines())
    need(row.get("Id")==unit and (result.returncode==0 or result.returncode==4 and row.get("LoadState")=="not-found"),
         "cannot establish publication unit identity")
    return row


def previous(terminal, delivery=DELIVERY, unit=UNIT):
    known_prepares = set()
    for p in delivery.glob("run-*/admission.json"):
        if not re.fullmatch(r"run-[a-f0-9]{32}",p.parent.name):
            continue
        admission, ref = document(p,0o400,2 << 20)
        if admission.get("publication_authorized") is True and admission.get("terminal_sha256")==terminal["sha256"]:
            return {"prior_sync":ref}
        if admission.get("publication_authorized") is False:
            known_prepares.add(p.parent.name[4:])
    state = manager(unit)
    if state["ActiveState"]!="inactive" or state["MainPID"]!="0" or state["ControlPID"]!="0" or state["Job"]:
        return {"existing_publication_unit":state}
    journal = subprocess.check_output(["/usr/bin/journalctl","-b","-ojson","--no-pager",
        "--output-fields=UNIT,INVOCATION_ID,MESSAGE_ID","_PID=1",f"UNIT={unit}"],timeout=12,text=True)
    for line in journal.splitlines():
        event=json.loads(line)
        iid=event.get("INVOCATION_ID","")
        if event.get("UNIT")==unit and re.fullmatch("[a-f0-9]{32}",iid) and iid not in known_prepares:
            return {"earlier_manager_invocation":iid,"existing_publication_unit":state}
    return None


def submit(state, original, proof, socket, launch, existing, unit=UNIT, controller=LAUNCH, fit_sha=FIT_SHA):
    intent = state/"INTENT.json"
    if intent.exists():
        prior, _ = document(intent,0o400,1 << 20)
        need(prior["terminal"] == original, "different terminal at prior submission")
        return "already-submitted-or-uncertain"
    other = existing(original)
    record = dict(terminal=original, **proof, unit=unit, observed_unix_seconds=int(time.time()))
    if other:
        once(intent,dict(record,existing=other))
        return "prior-publication"
    once(intent,dict(record,ssh_socket=str(socket),controller=str(controller),provider_sha256=fit_sha))
    # Even if the caller crashes after manager submission, INTENT is durable.
    result = launch(proof["fleet"],socket)
    once(state/"SUBMISSION.json",dict(record,manager=result))
    return "submitted"


def main():
    need(os.geteuid()==0 and __debug__, "root required")
    state=ROOT/"state"
    m=state.lstat()
    need(state.resolve(strict=True)==state and stat.S_ISDIR(m.st_mode) and m.st_uid==m.st_gid==0
         and stat.S_IMODE(m.st_mode)==0o700,"untrusted event state")
    with (state/"event.lock").open("a+b") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if (state/"INTENT.json").exists():
            prior,_=document(state/"INTENT.json",0o400,1 << 20)
            print(json.dumps(dict(disposition="existing-submission-reconcile",intent=prior["terminal"],manager=manager())))
            return
        changes=Changes()
        try:
            for program, digest in PROGRAMS:
                need(member(program,0o555)[1]["sha256"]==digest, "changed qualified executable")
            native=lambda:json.loads(subprocess.check_output([NATIVE,"inspect"],timeout=45))
            boot=Path("/proc/sys/kernel/random/boot_id").read_text().strip()
            original=terminal_evidence(TERMINAL,native,boot)
            while True:
                proof=accepted(R,REPORTS,original,changes,head,time.time())
                if proof:
                    socket=agents()
                    need(terminal_evidence(TERMINAL,native,boot)==original,"terminal changed before submission")
                    if accepted(R,REPORTS,original,changes,head,time.time())!=proof:
                        continue
                    def launch(fleet, socket):
                        subprocess.run([LAUNCH,"sync",fleet["path"],fleet["sha256"],socket,FIT_SHA],check=True,timeout=45)
                        return manager()
                    print(submit(state,original,proof,socket,launch,previous),flush=True)
                    return
                changes.wait()
        except Exception as err:
            once(state/f"attempt-{time.time_ns()}.json",
                 dict(error=str(err),boot=Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                      intent_present=(state/"INTENT.json").exists()))
            if (state/"INTENT.json").exists() or isinstance(err,Rejected):
                print(f"event retained for reconciliation: {err}",flush=True)
                return
            raise
        finally:
            changes.close()


if __name__=="__main__":
    main()
