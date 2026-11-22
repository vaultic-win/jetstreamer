"""Authenticate the conditional 96-GiB extension of the original epoch 170 booking."""
import hashlib
import os
from pathlib import Path
import stat

R=Path("/var/lib/jetstreamer/horizon_runtime_data")
D=R/"epoch170-retry10-recovery-20261121-v1"
G=R/"epoch170-retry10-guard384-20261121-v1"
OLD=R/"epoch170-ancestor-accounts-20261121-v1"
IMAGE_SOURCE="e72ae5b535920079d665a11a088bd76e90447f2a"
UNIT="horizon-qualify-170-replacement-local3retry10-20261121-v1.service"
ORIGINAL="8d120ed88adc4afb9485fb3f61dfa29c"
CAP=384<<30
EXTRA=96<<30

def guard(s):
    q,qr=s.read(G/"GUARD_QUALIFIED.json")
    s.need(q["schema"]=="horizon-170-384-native-guard-qualified-v1" and not q["physical_launch"] and
           set(q["static_controls"])=={"positive","wrong-cap","wrong-epoch","wrong-root","missing-witness"},"foreign extended guard controls")
    build=s.bound(q["build"],G/"BUILD.json")
    seal=s.bound(q["seal"],G/"tools/deployment-seal-receipt.json")
    sha=q["guard"]["sha256"];exe=G/"tools/guard"
    s.need(build["commit"]==IMAGE_SOURCE and s.iid(build["build_iid"]) and build["test_count"]==102 and
           build["artifact"]["sha256"]==sha and q["guard"]["path"]==str(exe) and seal["destination"]==str(exe.parent) and
           any(v["name"]=="guard" and v["sha256"]==sha for v in seal["members"]),"foreign 170 guard build")
    with exe.open("rb") as f:
        st=os.fstat(f.fileno())
        s.need(exe.resolve(strict=True)==exe and st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o555 and
               hashlib.file_digest(f,"sha256").hexdigest()==sha,"changed 170-only image")
    witness=s.bound(q["witness"],G/"NATIVE_WITNESS.json")
    binding=q["contract"];contract=s.bound(binding["contract"],G/"contract/contract.json")
    cs=s.bound(binding["deployment_seal"],G/"contract/deployment-seal-receipt.json")
    s.need(witness["native_identity"]["executable_sha256"]==sha and witness["native_identity"]["executable"]==str(exe) and
           len(witness["allocation"]["first"])==12 and witness["allocation"]["first"]==witness["allocation"]["second"] and
           contract["qualified_native_witness"]==q["witness"] and cs["destination"]==str(G/"contract") and
           any(v["name"]=="contract.json" and v["sha256"]==binding["contract"]["sha256"] for v in cs["members"]),"extended native DATA witness changed")
    return dict(image=sha,qualification=qr,contract=binding)

def funding(s,epoch):
    accepted=D/"ACCEPTED_384_BOOKING.json"
    if epoch!=170 and not accepted.exists():
        s.need(s.show(UNIT)["ActiveState"] in ("inactive","failed"),"unexpected unbooked 170 generation")
        return None
    final,retirement=s.read(OLD/"CLOSED_6_7_RETIRED.json","c246bb365dd59d234fd389d7dfcaed30910cbab36dfeeacff62cd2e9d64196dc")
    s.need(final["net_removed_bytes"]==65619279872 and final["resource_credit_bytes"]==0,"unbound cleanup total")
    result={}
    for n,size,inode in [(6,32506998784,109772806),(7,33112289280,110902340)]:
        label="local3retry"+str(n);p=OLD/"post-stop-state"/label
        c,cr=s.read(p/"COMPLETE.json");check,_=s.read(p/"CHECK.json",c["check_sha256"])
        intent,_=s.read(p/"INTENT.json",c["intent_sha256"])
        target=Path(c["scope"]);m=target.lstat()
        s.need(c["schema"]=="horizon170-closed-accounts-complete-v1" and c["attempt"]==label and c["original_iid"]==ORIGINAL
               and c["scope_empty"] and c["archive_or_snapshot_removed"] is False and c["resource_credit_bytes"]==0 and
               c["retired_tree_before_bytes"]==size and check["target"]==intent["scope"]==str(target) and
               check["inode"]==intent["inode"]==inode and check["anchors"]["closed_retry9"]["successor_inode"]==113710084 and
               target.resolve(strict=True)==target and target.name=="accounts-state" and (m.st_dev,m.st_ino)==(64512,inode) and
               m.st_blocks*512==c["scope_root_remaining_bytes"] and not any(target.iterdir()),"170 closed extent or custody differs")
        s.need(final["completions"][str(n)]["completion"]==cr,"foreign closed scope")
        result[str(n)]=cr
    g=guard(s)
    if accepted.exists():
        a,ar=s.read(accepted)
        s.need(a["epoch"]==170 and a["cap_bytes"]==CAP and a["extra_bytes"]==EXTRA and a["retired"]==result and
               a["guard"]==g["qualification"] and a["prestart"]["fits"] is True and a["prestart"]["epoch"]==170 and
               a["prestart"]["bookings"]["170"]["cap_bytes"]==CAP,"foreign accepted 170 extension")
    else:ar=None
    return dict(cap_bytes=CAP,extra_bytes=EXTRA,retired=result,guard=g["qualification"],retirement=retirement,accepted=ar)

def held(s,unit,run,pid,proc,intent):
    profile,pref=s.read(D/"profile.json")
    prep=s.bound(intent["prepared"],D/"PREPARED.json");s.need(prep["profile"]==pref,"unbound held profile")
    tools=D/"controller";seal=s.bound(intent["controller"],tools/"deployment-seal-receipt.json")
    src=tools/"gate.py";members={v["name"]:v["sha256"] for v in seal["members"]}
    args=[os.fsdecode(a) for a in (proc/"cmdline").read_bytes().split(b"\0") if a]
    expected=["/usr/bin/python3","-IB","/run/horizon-recovered170/gate.py",*profile["normal_argv"]]
    path=proc/"root/run/horizon-recovered170";env=(proc/"environ").read_bytes().split(b"\0")
    status=dict((l.split(":",1)[0],l.split(":",1)[1].split()) for l in (proc/"status").read_text().splitlines() if ":" in l)
    s.need(unit==UNIT and s.same_file(proc/"exe",Path("/usr/bin/python3")) and status["Uid"]==["1001"]*4 and status["Gid"]==["1003"]*4 and
           args==expected and hashlib.sha256(src.read_bytes()).hexdigest()==members["gate.py"] and s.same_file(path/"gate.py",src) and
           s.same_file(path/"profile.json",D/"profile.json") and s.same_file(path/"barrier",D/"barrier") and
           ("HORIZON_REPLAY170_PROFILE_SHA256="+pref["sha256"]).encode() in env and not (D/"barrier/allow").exists(),"foreign 170 held gate")


FAILED_VERIFIER = "5e0e20bc974149f096ea4bab10b15e1b"
FAILED_REJOIN = "dc043eb78c4a4349b0098760dc764a1f"
FAILED_CADENCE = "d37f36f898a44932a19fd50d7014a6fe"
FAILED_QUALIFIER = "500c8d717a4147b087ff302b5afa7fc0"
FAILED_QUALIFICATION_CENSUS = "a99ed8b51e8a482b805b8a36a11b2700"
FAILED_GUARD_FIXTURE = "50af3d8ab5da47e8bdc2828feab53908"
FAILED_TIMER_INSPECTION = "e6551a0bb8a14b989902e15c9ecc0751"
VERIFIER_UNIT = "horizon-holding-export145-20261121-v1.service"


def guard_fixture_failure(s, incident, manager, started, failed, recovery, failure, state):
    fixture = R / "epoch142-next-lane-20261122-v1/guard-fixture"
    semantic = R / "epoch145-semantic-continuity-20261121-v1"
    proof = s.bound(incident["qualifier"], fixture / "QUALIFIED.json")
    owner = proof["holder"]
    actual = s.bound(incident["advancing"], semantic / "V5F_ACTUAL_ADVANCING_WORKER.json")
    original = s.bound(incident["manager"], semantic / "V5F_ACTUAL_MANAGER.json")
    intent = s.bound(original["intent"], semantic / "V5F_START_INTENT.json")
    unit = "horizon-qualify-142-guard-holder-20261122-v1.service"
    iid = "992e0ab969d34bbab4ff885cac4cd421"
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip().replace("-", "")
    s.need(incident["boot"] == boot == intent["boot"] and owner["Id"] == unit
           and owner["InvocationID"] == iid and owner["MainPID"] == "361889"
           and proof["holder_start_ticks"] == 367889965 and proof["holder_exe"] == "/usr/bin/sleep"
           and proof["production_replay_started"] is False and proof["holder_terminal"]["MainPID"] == "0"
           and not (Path("/sys/fs/cgroup") / owner["ControlGroup"].lstrip("/")).exists(),
           "unexpected 142 observer or undrained fixture")
    rows = incident["observed_pid1"]
    s.need(all(row["_PID"] == "1" and row["_BOOT_ID"] == boot for row in rows)
           and {row["UNIT"] for row in rows if row["UNIT"].startswith("horizon-qualify-")} == {unit},
           "different incident manager or qualifier population")
    def event(unit_name, generation, event_id):
        row, = (r for r in rows if (r["UNIT"], r["INVOCATION_ID"], r["MESSAGE_ID"]) ==
                (unit_name, generation, event_id))
        return int(row["__REALTIME_TIMESTAMP"])
    start = event(unit, iid, "39f53479d3a045ac8e11786248231fbf")
    exit_time = event(VERIFIER_UNIT, FAILED_GUARD_FIXTURE, "98e322203f7a4ed290d09fe03c09fe15")
    stop = event(unit, iid, "de5b426a63be47a7b6ac3eaac82e2f6f")
    s.need(start < exit_time < stop and start // 1000000 <= failed["at"] <= exit_time // 1000000
           and failed["error"].rstrip().endswith("ValueError: foreign qualifier unit")
           and incident["failed"] == failure and incident["recovery"] == recovery == actual["start"]
           and actual["manager"] == incident["manager"] and actual["invocation_id"] ==
               original["new"]["InvocationID"] == manager["InvocationID"] == FAILED_GUARD_FIXTURE
           and actual["observations"] and all((r["parent_pid"],r["child_pid"],r["parent_ticks"],r["child_ticks"]) ==
               (320133,320351,367594995,367597991) for r in actual["observations"])
           and started["fresh_fit"]["provider_seal"] == intent["semantic_provider"]
           and set(p.name for p in state.iterdir()) == {"failed.json", "recovery-started.json"}
           and manager["Result"] == "exit-code" and not manager["ControlGroup"],
           "different failed verifier, time window, or crossed native owner")


def failed_verifier(s, manager, expected=FAILED_VERIFIER):
    """Preserve the failed verifier's reservation and its exact unpublished candidate."""
    import json
    import subprocess

    iid = manager["InvocationID"]
    s.need(expected in (FAILED_VERIFIER, FAILED_REJOIN, FAILED_CADENCE, FAILED_QUALIFIER, FAILED_TIMER_INSPECTION, FAILED_QUALIFICATION_CENSUS, FAILED_GUARD_FIXTURE) and iid == expected and manager["Id"] == VERIFIER_UNIT
           and manager["ActiveState"] == manager["SubState"] == "failed"
           and manager["ExecMainStatus"] == "1" and manager["MainPID"] == manager["ControlPID"] == "0"
           and manager["NRestarts"] == "0" and not manager["Job"]
           and not (Path("/sys/fs/cgroup/system.slice") / VERIFIER_UNIT).exists(),
           "failed verifier still occupied or generation changed")
    state = R / "epoch145-guarded-export-20261121-v1/state" / iid
    if expected == FAILED_VERIFIER:
        failure_sha = "00de799e968fa8c6e31a76284f0610bcc84bbe617193361ef457629b7294d38f"
        start_sha = "03cf2deacc6d38f5107bb894c59ced4ba2381aac425a1e3d9c401260053ca04f"
        image_sha = "0a24d0ab666e532630c3223a9ede9ba86107a65a211041ed0ecd12b35f0b5061"
    elif expected == FAILED_GUARD_FIXTURE:
        failure_sha = "38d828362fed1910cc60c605200380576c165168738dbf00520ce2b2522a0fcd"
        start_sha = "3dd15e821b9972e3f7f69f787d585bbe86fd9898ec1df5e8e5d08cab14231bb8"
        image_sha = "016f1beab41795dae2bbaa1cef5173773eeafae617a5f5db92ebd4aaa1887c21"
    elif expected == FAILED_QUALIFICATION_CENSUS:
        failure_sha = "da29d82a4349444ccc15e0be020aa12918ae5bbb4634f9b62e13cc83a93c5f43"
        start_sha = "6e06652ea695717b18fc29b955e463da8dc2dde16f8173da552df707c478e624"
        image_sha = "148804337a0c47093f67ae642fe01dc3a529cb07dbc809bfd9ab0ff9ca714a7c"
    elif expected == FAILED_TIMER_INSPECTION:
        failure_sha = "9ef9c938290ea2b43d3b2ce4aa617f08b33f4c893961e63f53ba3f48768e215f"
        start_sha = "55d2a0504271e8a1eea2ca8c105a288be9497f1a2b80177279481692d06e041f"
        image_sha = "3d60de86d45a497bcd1b9836c485ffab4ce1da19cb6d989d56c9d3b92ad60066"
    elif expected == FAILED_QUALIFIER:
        failure_sha = "04c96683252ad3815d906d43dbbfb2f80d3ebcf542d7e671f28119f74767b107"
        start_sha = "0a82bc0b2666ec668a3d235ed3e24f7ec39900e2ca53649a9c01a47b024fa890"
        image_sha = "3d60de86d45a497bcd1b9836c485ffab4ce1da19cb6d989d56c9d3b92ad60066"
    elif expected == FAILED_CADENCE:
        failure_sha = "6533e594be11534e7fb58ac0f1fd752ead37cfd114e36899a956970b8318bb29"
        start_sha = "a3d623b47ea9612824d102714703b0d095db18e07bf8ce3570ec08331ad84e81"
        image_sha = "34d90f2a5ae8a821109b2bbf99c5527d43c3eb141f68cea212109fc876f28c8d"
    else:
        failure_sha = "baa00ca8b52aca80b105bf5582f955af8a3f9e22ce662908ce7a75afccfb1943"
        start_sha = "e992566275e63b28a020c847c02637626b245161a2e39f843ac1da4d64793b2f"
        image_sha = "710b9c840fe26d964874fa6fadc2b0be9fc59d011755ce5da57a46c6ca2349f1"
    failed, failure = s.read(state / "failed.json", failure_sha)
    started, recovery = s.read(state / "recovery-started.json", start_sha)
    incident_ref = None
    if expected == FAILED_GUARD_FIXTURE:
        incident, incident_ref = s.read(R / "incident-replay-fit-20261121-v1/GUARD142_V5F_TERMINAL.json",
                                       "f4a13a58292296c22dd870d5ecdf4ab4c056f3e06562bb5bb121a899c89f3bb7")
        guard_fixture_failure(s, incident, manager, started, failed, recovery, failure, state)
    elif expected == FAILED_QUALIFICATION_CENSUS:
        import runpy
        bounded = runpy.run_path(str(Path(__file__).with_name("bounded142.py")))
        incident, incident_ref = s.read(bounded["INCIDENT"], bounded["INCIDENT_SHA"])
        q = s.bound(incident["qualifier"], bounded["Q"] / "NORMAL_ENTRY_QUALIFIED.json")
        route = s.bound(q["route"], bounded["Q"] / "ROUTE.json")
        base = R / "epoch145-semantic-continuity-20261121-v1"
        actual = s.bound(incident["advancing"], base / "V5E_ACTUAL_ADVANCING_WORKER.json")
        parent = s.bound(actual["manager"], base / "V5E_ACTUAL_MANAGER.json")
        intent = s.bound(parent["intent"], base / "V5E_START_INTENT.json")
        provider = R / "incident-replay-fit-20261121-v1/tools-v16"
        for ref, folder, name, digest in ((intent["provider"], provider, "post-stop-fit", incident["provider"]["sha256"]),
                                          (intent["verifier"], base / "tools-v5e", "export145", image_sha)):
            package = s.bound(ref, folder / "deployment-seal-receipt.json")
            s.need(package["destination"] == str(folder) and any(r["name"] == name and r["sha256"] == digest
                   for r in package["members"]), "changed incident provider or verifier")
        qual = incident["managers"]["qualification"]
        a,b = incident["journal"]["qualification"]
        s.need(qual["ExecMainPID"] == "227497" and q["native"]["InvocationID"] == bounded["IID"] == qual["InvocationID"]
               and q["route"] == incident["available_route"] and q["argv"] == incident["argv"]
               and not q["worker_started"] and not q["payload_replay_started"] and not route["admission_granted"]
               and a["MESSAGE_ID"] == "39f53479d3a045ac8e11786248231fbf"
               and b["MESSAGE_ID"] == "98e322203f7a4ed290d09fe03c09fe15" and b["EXIT_STATUS"] == "1"
               and int(a["__REALTIME_TIMESTAMP"]) // 1000000 <= failed["at"] <= int(b["__REALTIME_TIMESTAMP"]) // 1000000
               and failed["error"].rstrip().endswith("ValueError: unregistered replay process 227497")
               and incident["incident"] == failure and incident["recovery"] == recovery == actual["start"]
               and actual["invocation_id"] == iid == parent["new"]["InvocationID"] and parent["parent_pid"] == 94449
               and all(x["child_pid"] == 94696 and x["parent_pid"] == 94449 for x in actual["observations"])
               and len(actual["observations"]) == 2 and intent["boot"] == incident["boot"] == bounded["BOOT"]
               and Path("/proc/sys/kernel/random/boot_id").read_text().strip().replace("-","") == incident["boot"]
               and set(p.name for p in state.iterdir()) == {"recovery-started.json", "failed.json"}
               and manager["Result"] == "exit-code" and not manager["ControlGroup"],
               "foreign bounded 142 incident or advanced verifier")
    elif expected == FAILED_TIMER_INSPECTION:
        progress = R / "epoch145-semantic-continuity-20261121-v1/V5D_RETRY1_ACTUAL_ADVANCING_WORKER.json"
        observed, _ = s.read(progress, "3a41dac31746938b482133b9ff224f9d9d821569cc16f63c83f872fe907c13e0")
        inspected = R / "incident-replay-fit-20261121-v1/tools-v14/retire-original-timers.py"
        timeout = f"subprocess.TimeoutExpired: Command '['/usr/bin/python3', '-IB', PosixPath('{inspected}'), 'inspect']' timed out after 20 seconds"
        s.need(failed["error"].rstrip().endswith(timeout) and observed["invocation_id"] == iid
               and observed["start"] == recovery and len(observed["observations"]) == 2
               and set(p.name for p in state.iterdir()) == {"recovery-started.json", "failed.json"}
               and manager["Result"] == "exit-code" and not manager["ControlGroup"],
               "unbound timer inspection or changed failed verifier")
    elif expected == FAILED_QUALIFIER:
        prior = started["prior_frozen_recovery"]["failed_status_owner"]["current_boot_failure"]["failure"]
        progress = R / "epoch145-semantic-continuity-20261121-v1/V5D_ACTUAL_ADVANCING_WORKER.json"
        observed, _ = s.read(progress, "619fb2e8063399d3501d06bcd89a6a6ac999b2ac2f087c08531a6bd319247e3d")
        compiler = "horizon-qualify-native-observer-resident-20261121-a.service"
        compiler_iid = "3548aa49b01c40c6b4d70aaeb6bd75ab"
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip().replace("-", "")
        raw = subprocess.check_output(["/usr/bin/journalctl", "--no-pager", "-ojson",
            "--output-fields=UNIT,INVOCATION_ID,MESSAGE_ID,EXIT_CODE,EXIT_STATUS", "_BOOT_ID=" + boot,
            "_PID=1", "UNIT=" + compiler, "INVOCATION_ID=" + compiler_iid], text=True, timeout=10)
        events = [json.loads(line) for line in raw.splitlines()]
        a = [row for row in events if row["MESSAGE_ID"] == "39f53479d3a045ac8e11786248231fbf"]
        b = [row for row in events if row["MESSAGE_ID"] == "98e322203f7a4ed290d09fe03c09fe15"]
        s.need(len(a) == len(b) == 1 and b[0]["EXIT_CODE"] == "exited" and b[0]["EXIT_STATUS"] == "1"
               and int(a[0]["__REALTIME_TIMESTAMP"]) // 1000000 <= failed["at"] <= int(b[0]["__REALTIME_TIMESTAMP"]) // 1000000
               and not (Path("/sys/fs/cgroup/system.slice") / compiler).exists()
               and failed["error"].rstrip().endswith("ValueError: foreign qualifier unit")
               and prior["sha256"] == "6533e594be11534e7fb58ac0f1fd752ead37cfd114e36899a956970b8318bb29"
               and observed["invocation_id"] == iid and observed["start"] == recovery and len(observed["observations"]) == 2
               and set(p.name for p in state.iterdir()) == {"recovery-started.json", "failed.json"}
               and manager["Result"] == "exit-code" and not manager["ControlGroup"],
               "unregistered observer compiler or foreign failed verifier")
    elif expected == FAILED_CADENCE:
        s.need(failed["error"].startswith("complete 145 capacity observation failed exit status: 1: Traceback") and
               failed["error"].rstrip().endswith("ValueError: cadence publisher absent") and
               'tools-v10/post-stop-fit", line 456, in registered_status' in failed["error"] and
               set(p.name for p in state.iterdir()) == {"recovery-started.json", "failed.json"} and
               manager["Result"] == "exit-code" and not manager["ControlGroup"],
               "unregistered failed status-publisher crossing")
    elif expected == FAILED_VERIFIER:
        s.need(failed["error"] == "stopped worker fresh-census deadline", "unexpected census failure")
    else:
        s.need(set(p.name for p in state.iterdir()) == {"failed.json", "recovery-started.json"}
               and manager["Result"] == "exit-code" and not manager["ControlGroup"]
               and "subprocess.TimeoutExpired" in failed["error"]
               and "horizon-qualify-168-full-metered-20261121-v1.service']' timed out after 10 seconds" in failed["error"]
               and started["prior_frozen_recovery"]["failed_fresh_census"]["source_checkpoint_exists"] is False,
               "failed rejoin advanced or terminal differs")
    s.need(failed["iid"] == started["iid"] == iid and started["image"] == image_sha
           and started["r2_mutations"] is False
           and not any((state / n).exists() for n in ("source-semantics.json", "verified-frozen.json", "complete.json")),
           "failed verification phase changed")
    candidate = Path(started["file"])
    s.need(candidate == Path("/home/sol/.jetstreamer-private/epoch145-prefix-extract-funded-20261121-v1/.tmp36MvkN")
           and candidate.resolve(strict=True) == candidate, "failed verifier candidate path changed")
    m = candidate.lstat()
    identity = dict(bytes=m.st_size, ctime_ns=m.st_ctime_ns, device=m.st_dev, gid=m.st_gid, inode=m.st_ino,
                    mode=m.st_mode, mtime_ns=m.st_mtime_ns, uid=m.st_uid)
    s.need(m.st_nlink == 1 and stat.S_ISREG(m.st_mode) and identity == started["prior_frozen_recovery"]["failed_preincident_verifier"]["original_candidate"],
           "failed verifier candidate replaced")
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip().replace("-", "")
    raw = subprocess.check_output(["/usr/bin/journalctl", "--no-pager", "-ojson",
        "--output-fields=_PID,_BOOT_ID,UNIT,INVOCATION_ID,MESSAGE_ID,EXIT_CODE,EXIT_STATUS",
        "_BOOT_ID=" + boot, "_PID=1", "UNIT=" + VERIFIER_UNIT, "INVOCATION_ID=" + iid], text=True, timeout=10)
    rows = [json.loads(line) for line in raw.splitlines()]
    exits = [r for r in rows if r["MESSAGE_ID"] == "98e322203f7a4ed290d09fe03c09fe15"]
    starts = [r for r in rows if r["MESSAGE_ID"] == "39f53479d3a045ac8e11786248231fbf"]
    s.need(len(starts) == len(exits) == 1 and all(r["_PID"] == "1" and r["_BOOT_ID"] == boot
           and r["UNIT"] == VERIFIER_UNIT and r["INVOCATION_ID"] == iid for r in rows)
           and exits[0]["EXIT_CODE"] == "exited" and exits[0]["EXIT_STATUS"] == "1"
           and int(starts[0]["__MONOTONIC_TIMESTAMP"]) < int(exits[0]["__MONOTONIC_TIMESTAMP"]),
           "missing original verifier PID 1 failure")
    return dict(failure=failure, recovery=recovery, candidate=identity, manager_exit=exits[0],
                source_checkpoint_exists=False, resource_credit_bytes=0,
                **({"qualification_census_incident": incident_ref} if incident_ref else {}))
