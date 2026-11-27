"""Dispatch the read-only archive verifier and reconcile its exact native result."""
import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import runpy
import stat
import subprocess
import time

RT = Path("/var/lib/jetstreamer/horizon_runtime_data")
PROD = RT / "epoch168-exact-private-verification-20261127-v1"
SCOPE = PROD / "scope.json"
SCOPE_SHA = "b914d8570f3fe8fd2cc2bc91cc5285a9598b11515ab8763f17eeb28f13373a9c"
WORK = Path("/home/sol/.jetstreamer-private/epoch168-private-archive-verify-20261127.0VHYTNgF")
BUILD = WORK / "qualification/horizon-168-local-scan-build-1795817186264675279/BUILD.json"
SOURCE = Path(__file__).resolve().parent
ISSUED = PROD / "tools-v1"
REPRICE = PROD / "split-price-v1"
REPO = Path("/home/sol/workspace/jetstreamer")
DEPLOYMENT = PROD / "deployment.json"
ASSEMBLER = "horizon-assemble-168-private-20261127-v1.service"
CADENCE = "horizon-archive-status-cadence-after172-20261120-v1.service"
EXPECTED_FIXTURE = "c5afc2602481c6683ee7eb9018d59948df4dd75056215c90d738cd2497328281"
SUCCESS = "7ad2d189f7e94e70a38c781354912448"
FAIL = "98e322203f7a4ed290d09fe03c09fe15"


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def load(path):
    return json.loads(path.read_bytes())


def ref(path):
    with path.open("rb") as source:
        value = hashlib.file_digest(source, "sha256").hexdigest()
    return {"path":str(path), "sha256":value}


def sealed(path):
    st = path.lstat()
    need(path.resolve(strict=True) == path and stat.S_ISREG(st.st_mode) and st.st_uid == st.st_gid == 0
         and st.st_nlink == 1 and not st.st_mode & 0o222, "unsealed input " + str(path))


def checked(binding):
    path = Path(binding["path"])
    sealed(path)
    need(ref(path) == binding, "changed input " + str(path))
    return load(path)


def save(path, data):
    # Link a complete fsynced file into place. A stopped controller can always
    # reconcile the previous record or write a new, complete one.
    tmp = path.with_name("." + path.name + "." + str(time.time_ns()))
    with tmp.open("x") as f:
        os.fchmod(f.fileno(), 0o400)
        json.dump(data, f, indent=2, sort_keys=True)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    try:
        os.link(tmp,path)
    finally:
        tmp.unlink()
    fd = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return ref(path)


def once(path, data):
    if path.exists():
        sealed(path)
        need(load(path) == data, "existing result differs: " + str(path))
        return ref(path)
    return save(path, data)


def git(args):
    return subprocess.check_output(["/usr/bin/git","-c","safe.directory="+str(REPO),"-C",str(REPO),*args])


def fetch():
    user = pwd.getpwnam("sol")
    hint = os.environ.get("SSH_AUTH_SOCK")
    paths = [Path(hint)] if hint else []
    for pattern in ("/tmp/ssh-*/agent.*", "/run/user/"+str(user.pw_uid)+"/keyring/ssh",
                    "/run/user/"+str(user.pw_uid)+"/ssh-agent.socket"):
        paths.extend(Path("/").glob(pattern.lstrip("/")))
    for path in dict.fromkeys(paths):
        with contextlib.suppress(FileNotFoundError):
            s = path.stat()
            if s.st_uid != user.pw_uid or not stat.S_ISSOCK(s.st_mode):
                continue
            env = ["runuser","-u",user.pw_name,"--","/usr/bin/env","HOME="+user.pw_dir,
                   "GIT_TERMINAL_PROMPT=0","SSH_AUTH_SOCK="+str(path)]
            if subprocess.run([*env,"/usr/bin/ssh-add","-l"],stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL,timeout=5).returncode:
                continue
            attempt = subprocess.run([*env,"/usr/bin/git","-C",str(REPO),"fetch","--quiet",
                                      "--no-write-fetch-head","origin",
                                      "refs/heads/account-updates:refs/remotes/origin/account-updates"],
                                     capture_output=True,timeout=60)
            if attempt.returncode == 0:
                return git(["rev-parse","refs/remotes/origin/account-updates"]).decode().strip()
    raise ValueError("no loaded sol SSH agent completed the branch fetch")


def deployment(fixture):
    if fixture:
        sealed(BUILD)
        result = load(BUILD)["binary"]
        sources = load(BUILD)["source"]
        for name, item in sources.items():
            need(ref(SOURCE/name) == {"path":str(SOURCE/name),"sha256":item["sha256"]},
                 "wrapper differs from compiler input")
    else:
        sealed(DEPLOYMENT)
        release = load(DEPLOYMENT)
        need(release["scope"] == {"path":str(SCOPE),"sha256":SCOPE_SHA}
             and release["directory"] == str(ISSUED) and SOURCE in (ISSUED, REPRICE)
             and release["native_build"] == ref(BUILD),
             "incorrect production verification deployment")
        proof = checked(release["qualification"])
        need(proof["accepted"] and proof["counts_rejected"] and proof["digest_rejected"]
             and proof["native_build"] == release["native_build"], "unqualified private receiver")
        rev = release["commit"]
        git(["merge-base","--is-ancestor",rev,"refs/remotes/origin/account-updates"])
        for name, item in release["source"].items():
            raw = git(["show",rev+":scripts/horizon_epoch168_private_verify/"+name])
            need(hashlib.sha256(raw).hexdigest() == item["sha256"], "operator not in fetched branch")
            if name.endswith(".py"):
                sealed(ISSUED/name)
                need(ref(ISSUED/name) == item, "installed dispatch source differs")
        if SOURCE == REPRICE:
            bind = load_published_pricing()
            need(bind["original_deployment"] == ref(DEPLOYMENT), "different verifier for split-fleet pricing")
        for name, binding in checked(release["native_build"])["source"].items():
            need(binding["sha256"] == release["source"][name]["sha256"], "compiled verifier source differs")
        result = release["binary"]
        need(result["sha256"] == checked(release["native_build"])["binary"]["sha256"], "different native wrapper")
    binpath = Path(result["path"])
    sealed(binpath)
    need(ref(binpath) == result, "native verifier changed")
    return binpath


def load_published_pricing():
    registration = PROD / "SPLIT_PRICE_DEPLOYMENT.json"
    sealed(registration)
    item = load(registration)
    receipt = checked(item["package"])
    need(item["package"]["path"] == str(REPRICE/"deployment-seal-receipt.json") and
         receipt["destination"] == str(REPRICE) and
         {m["name"] for m in receipt["members"]} == {"dispatch.py","split_price.py"},
         "different private pricing registration")
    git(["merge-base","--is-ancestor",item["commit"],"refs/remotes/origin/account-updates"])
    for member in receipt["members"]:
        p = REPRICE/member["name"]
        sealed(p)
        committed = git(["show",item["commit"]+":scripts/horizon_epoch168_private_verify/"+p.name])
        need(ref(p)["sha256"] == member["sha256"] == hashlib.sha256(committed).hexdigest(),
             "split-fleet pricing differs from the merged source")
    return item


def run_native(binary, *args):
    cmd = [str(binary),*map(str,args)]
    result = subprocess.run(cmd, capture_output=True, text=True,timeout=120)
    if result.returncode:
        raise ValueError("native "+str(args[0])+": "+result.stderr.strip())
    return json.loads(result.stdout)


def props(unit):
    keys = "Id,ActiveState,Job,MainPID,ControlPID,ControlGroup,InvocationID,LoadState"
    cmd = subprocess.run(["/usr/bin/systemctl","show","--all","-p",keys,"--",unit],capture_output=True,text=True)
    need(cmd.returncode in (0,4), "cannot inspect " + unit)
    result = dict(line.split("=",1) for line in cmd.stdout.splitlines())
    need(result.get("Id") == unit and set(result) == set(keys.split(",")), "invalid native service state")
    return result


def recognized_boot(unit, iid=None):
    args = ["journalctl","-q","-b","--no-pager","-o","json","_PID=1","_UID=0","UNIT="+unit]
    if iid:
        args.append("INVOCATION_ID="+iid)
    return [json.loads(s) for s in subprocess.check_output(args,text=True).splitlines()]


def managed_argv(binary, scope, control, target, unit):
    limits = ["CPUQuota=100%","CPUQuotaPeriodSec=100ms","MemoryMax=2G","MemorySwapMax=0",
              "TasksMax=96","RuntimeMaxSec=120h","Restart=no","Nice=12","IOSchedulingClass=idle",
              "LimitCORE=0","LimitFSIZE=1M","UMask=0077","PrivateNetwork=yes","PrivateMounts=yes",
              "PrivateTmp=yes","ProtectSystem=strict","ProtectHome=read-only","NoNewPrivileges=yes",
              "ReadWritePaths="+str(target)]
    return ["systemd-run","--quiet","--unit="+unit,"--slice=horizonaudit.slice","--service-type=exec",
            "--setenv=RUST_MIN_STACK=67108864",*["--property="+p for p in limits],"--",str(binary),
            "run",scope["path"],scope["sha256"],control["path"],control["sha256"],str(target)]


def finalize(binary, intent, attempt, fixture):
    scope = intent["scope"]
    ad = intent["admission"]
    target = attempt/"output"
    scan = load(target/"SCAN.json")
    need(scan["scope"] == scope and scan["admission"] == ad, "wrong native scan")
    unit = intent["unit"]
    end = run_native(binary,"terminal",unit,scan["scan_invocation"])
    terminal = once(attempt/"TERMINAL.json",end)
    current = fetch()
    out = target/"ACCEPTANCE.json"
    if not out.exists():
        result = run_native(binary,"finish",scope["path"],scope["sha256"],ad["path"],ad["sha256"],
                            target,terminal["path"],terminal["sha256"])
    else:
        result = ref(out)
    accepted = checked(result)
    need(accepted["scope"] == scope and accepted["admission"] == ad and accepted["native_terminal"] == terminal
         and not accepted["canonical_writes"] and not accepted["publication_authorized"]
         and accepted["fixture"] == fixture, "wrong verification result")
    git(["merge-base","--is-ancestor",accepted["reader_branch"]["fetched_commit"],current])
    equivalent = run_native(binary,"scope",scope["path"],scope["sha256"])["reader_branch"]
    need(equivalent["compiled_from"] == accepted["reader_branch"]["compiled_from"]
         and equivalent["reader_comparison"] == accepted["reader_branch"]["reader_comparison"]
         and equivalent["fetched_commit"] == current, "accepted reader inputs changed")
    if fixture:
        need(bytes(accepted["counters"]["stream_digest"]).hex() == EXPECTED_FIXTURE, "unexpected synthetic semantic digest")
    return result


def reconcile(control_root, binary, fixture):
    """Return active, rejected, complete or empty. Only an unstarted expired intent can be retried."""
    for attempt in sorted(control_root.glob("attempt-*")):
        plan = attempt/"INTENT.json"
        if not plan.exists() or (attempt/"UNSTARTED.json").exists():
            continue
        sealed(plan)
        intent = load(plan)
        unit = intent["unit"]
        native = props(unit)
        target = attempt/"output"
        adb = checked(intent["admission"])
        need(adb["output"] == str(target) and adb["scan_unit"] == unit and
             intent["command"] == managed_argv(binary,intent["scope"],intent["admission"],target,unit)
             and (intent.get("binary") == ref(binary) or (fixture and "binary" not in intent)),
             "wrong verification intent or verifier")
        entered = target/"STARTED.json"
        if native["ActiveState"] in {"active","activating","deactivating"} or native["Job"]:
            if entered.exists():
                x = checked(ref(entered))
                need(x["invocation"] == native["InvocationID"] and x["scan_unit"] == unit
                     and x["admission"] == intent["admission"] and x["exclusive_serial_lock"], "unbound live verification")
                if native["ActiveState"] == "active" and native["MainPID"] != "0":
                    need(int(native["MainPID"]) == x["pid"] and (Path("/proc")/native["MainPID"]/"exe").samefile(binary),
                         "different running verifier")
            return "active",unit
        if (target/"SCAN.json").exists():
            result = finalize(binary,intent,attempt,fixture)
            return "complete",once(control_root/"ACCEPTED.json",dict(acceptance=result,unit=unit))
        native_events = recognized_boot(unit)
        if entered.exists() or native_events:
            diagnostic = once(attempt/"REFUSED.json",dict(unit=unit,enter=ref(entered) if entered.exists() else None,
                               messages=[{"id":r.get("MESSAGE_ID"),"message":r.get("MESSAGE"),
                                          "invocation":r.get("INVOCATION_ID")} for r in native_events
                                         if r.get("MESSAGE_ID") in {SUCCESS,FAIL}]))
            return "rejected",diagnostic
        if time.time() <= adb["valid_until"]:
            return "awaiting-native-launch",unit
        once(attempt/"UNSTARTED.json",dict(admission=intent["admission"],unit=unit,
                                           reason="expired with no native unit, start evidence or boot journal"))
    return "empty",None


def dispatch(scope_path, fixture):
    binary = deployment(fixture)
    content = load(scope_path)
    root = scope_path.parent
    scope = ref(scope_path)
    if fixture:
        need(content["fixture"] and re.fullmatch(r"horizon-168-verifier-fixture-[0-9]+",root.name)
             and root.parent == WORK/"qualification", "foreign fixture")
    else:
        need(scope == {"path":str(SCOPE),"sha256":SCOPE_SHA} and not content["fixture"], "foreign epoch")
    with (root/"dispatch.lock").open("a") as local:
        fcntl.flock(local,fcntl.LOCK_EX)
        if (root/"ACCEPTED.json").exists():
            completed = ref(root/"ACCEPTED.json")
            result = checked(checked(completed)["acceptance"])
            need(result["scope"] == scope and result["fixture"] == fixture
                 and not result["canonical_writes"], "different accepted scope")
            return "complete",completed
        state, record = reconcile(root,binary,fixture)
        if state != "empty":
            return state,record
        source = props(content["unit"])
        if source["ActiveState"] in {"active","activating","deactivating"} or source["Job"]:
            need(source["InvocationID"] == content["invocation"], "foreign archive assembler")
            return "awaiting-assembly",source["InvocationID"]
        events = recognized_boot(content["unit"],content["invocation"])
        failures = [dict(message=r.get("MESSAGE"),message_id=r.get("MESSAGE_ID"),usec=r.get("__REALTIME_TIMESTAMP"))
                    for r in events if r.get("MESSAGE_ID") == FAIL]
        if failures:
            return "rejected",once(root/"ASSEMBLY_FAILED.json",
                    dict(assembler=content["unit"],invocation=content["invocation"],failures=failures,scope=scope))
        ready = run_native(binary,"ready",scope["path"],scope["sha256"])
        fetched = fetch()
        capacity = runpy.run_path(str(SOURCE/("split_price.py" if SOURCE == REPRICE else "capacity.py")))
        with capacity["OPERATION"].open("rb") as op, capacity["SERIAL"].open("rb") as serial:
            fcntl.flock(op,fcntl.LOCK_EX)
            fcntl.flock(serial,fcntl.LOCK_EX|fcntl.LOCK_NB)
            priced_at = int(time.time())
            q = capacity["price"](fixture=fixture)
            if not q["fits"]:
                return "awaiting-fit",save(root/("FIT_REFUSED_"+str(time.time_ns())+".json"),q)
            ready = run_native(binary,"ready",scope["path"],scope["sha256"])
            need(fetched == ready["reader_branch"]["fetched_commit"] and int(time.time())-priced_at < 120,
                 "verification price or reader branch changed during admission")
            binary = deployment(fixture)
            token = str(time.time_ns())
            unit = ("horizon-168-private-fixture-scan-" if fixture else "horizon-168-private-archive-verify-")+token+".service"
            attempt = root/("attempt-"+token)
            attempt.mkdir(mode=0o700)
            target = attempt/"output"
            target.mkdir(mode=0o700)
            evidence = save(attempt/"FIT.json",q)
            ad = save(attempt/"ADMISSION.json",dict(schema="horizon-168-private-native-scan-admission-v1",
                      scope=scope,assembly=ready["assembly"],assembly_terminal=ready["assembly_terminal"],
                      reader_branch=ready["reader_branch"],archive_stamp=ready["archive_stamp"],fit=evidence,
                      output=str(target),scan_unit=unit,ram_bytes=2<<30,issued_at=priced_at,valid_until=priced_at+180,
                      fits=True,canonical_writes=False))
            cmd = managed_argv(binary,scope,ad,target,unit)
            save(attempt/"INTENT.json",dict(scope=scope,admission=ad,command=cmd,unit=unit,binary=ref(binary)))
            fcntl.flock(serial,fcntl.LOCK_UN)
            subprocess.run(cmd,check=True,timeout=45)
            expires = time.monotonic()+20
            while not (target/"STARTED.json").exists() and time.monotonic()<expires:
                check = props(unit)
                if check["ActiveState"] not in {"active","activating"} and not check["Job"]:
                    break
                time.sleep(.15)
            if (target/"STARTED.json").exists():
                entered = checked(ref(target/"STARTED.json"))
                need(entered["admission"] == ad and entered["scope"] == scope and entered["scan_unit"] == unit
                     and entered["exclusive_serial_lock"], "private verifier did not bind its admission")
                now_state = props(unit)
                if now_state["ActiveState"] == "active":
                    need(entered["invocation"] == now_state["InvocationID"] and int(now_state["MainPID"]) == entered["pid"]
                         and (Path("/proc")/now_state["MainPID"]/"exe").samefile(binary), "different private scan PID")
                save(attempt/"LAUNCH.json",dict(native=now_state,started=ref(target/"STARTED.json"),admission=ad))
                return "launched",unit
            raise ValueError("native scan did not enter: "+unit)


def wake_event(row, units):
    if row.get("_UID") != "0":
        return False
    if row.get("_PID") == "1":
        unit = row.get("UNIT","")
        return row.get("MESSAGE_ID") in {SUCCESS,FAIL} and (unit in units
            or re.fullmatch(r"horizon-(?:170-[0-9]+-closed-read|qualify-170-from-[0-9]+)-[a-z0-9-]+\.service",unit)
            or re.fullmatch(r"horizon-closed186-(?:park|retire|restore)-[a-z]+-[0-9]+\.service",unit)
            or re.fullmatch(r"horizon-anza-ready-audit@(149|15[0-6])\.service",unit))
    if row.get("_SYSTEMD_UNIT") != CADENCE:
        return False
    message = row.get("MESSAGE","")
    if not message.startswith('{"fleet":'):
        return False
    receipt = json.loads(message)["fleet"]
    path = Path(receipt["path"])
    return path.parent.parent == RT and path.name == "ROOT_COMPLETE_OPERATIONAL_FLEET.json" and ref(path) == receipt


def watch():
    # Subscribe before reconciliation so an immediate native exit cannot be lost.
    start = "@"+str(int(time.time()))
    cmd = ["journalctl","-q","-b","--no-pager","-o","json","--follow","--no-tail","--since",start,
           "_UID=0","_PID=1","+","_UID=0","_SYSTEMD_UNIT="+CADENCE]
    with subprocess.Popen(cmd,stdout=subprocess.PIPE,text=True) as stream:
        try:
            units = {ASSEMBLER}
            def reconcile_event():
                try:
                    state, result = dispatch(SCOPE,False)
                except (ValueError,OSError,subprocess.SubprocessError) as err:
                    print(json.dumps(dict(event="dispatch refused",reason=str(err))),flush=True)
                    return False
                print(json.dumps(dict(state=state,result=result)),flush=True)
                if state in {"launched","active","awaiting-native-launch"}:
                    units.add(result)
                return state in {"complete","rejected"}
            if reconcile_event():
                return
            for line in stream.stdout:
                if wake_event(json.loads(line),units) and reconcile_event():
                    return
            raise RuntimeError("native event stream ended")
        finally:
            stream.terminate()


def main():
    os.umask(0o077)
    need(os.getuid()==0 and __debug__,"privileged checked entry required")
    parser=argparse.ArgumentParser()
    parser.add_argument("mode",choices=["tick","watch","fixture"])
    parser.add_argument("path",nargs="?")
    args=parser.parse_args()
    if args.mode=="watch":
        need(not args.path, "unexpected watcher arguments")
        watch()
    else:
        fixture=args.mode=="fixture"
        need(fixture==bool(args.path), "synthetic source must be named explicitly")
        print(json.dumps(dispatch(Path(args.path)/"scope.json" if fixture else SCOPE,fixture)),flush=True)


if __name__=="__main__":
    main()
