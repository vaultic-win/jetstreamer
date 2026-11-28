"""Close the ungranted 03:47 invocation and retain its actual post-guard price."""
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess


RT = Path("/var/lib/jetstreamer/horizon_runtime_data")
FIRST = RT / "epoch169-hourly-retry-20261128-v1"
OPERATOR = FIRST / "operator-v1"
IID = "9c271e621bd9484ba6fe8ac1508ffaac"
HELD = "f63eab0e6e18e6c7f94e8827edef2e9f7447491ac0ebdc69048379327c973db6"
END = "a25522f69b21b42e6f353e6733dd7075844d02468e63f8c5d5ea15e87f4694b0"
POST = "99b66cfcadc911c81c5639e88a44b9e813334a8a57593dcb082a75f5ce61e425"
FLEET = "fce265c2b9b3911784089b2cb076a06e0c66a3127cf6ea899c3ddaa0b408a206"
CONTRACT = "b0bd0f2f03868b17b557ad24d227be0b152bb5f530044ecfcbca80cb54d0156b"


def close():
    helper = OPERATOR / "contract.py"
    if hashlib.sha256(helper.read_bytes()).hexdigest() != CONTRACT:
        raise ValueError("different original evidence reader")
    c = runpy.run_path(str(helper))
    read, need = c["read"], c["need"]
    held, hr = read(FIRST/"HELD_GATE.json", HELD)
    terminal, tr = read(FIRST/"results/TERMINAL.json", END)
    start, sr = read(FIRST/"START_INTENT.json", "24678c26bfa8ce057eb3a38d3316c4793ccadf2c448f1f9b34e775b7528eb889")
    pre, pr = read(Path(start["prestart"]["path"]), start["prestart"]["sha256"])
    plan, ar = read(Path(start["guard_plan"]["path"]), start["guard_plan"]["sha256"])
    post, qr = read(FIRST/"JOINT_1795837687264105700.json", POST)
    fleet, fr = read(RT/"root034808-live166167170-20261128-v1/ROOT_COMPLETE_OPERATIONAL_FLEET.json", FLEET, sealed=False)
    row = fleet["current_private169_retry"]
    need(row["phase"] == "terminal" and row["invocation_id"] == start["producer_invocation_id"]
         == plan["invocation_id"] == held["invocation_id"] == IID and row["terminal"] == tr and row["held"] == hr
         and terminal == dict(canonical_publication_authorized=False, disposition="private-payload-never-released"),
         "different retained invocation or cadence closure")
    unit = c["UNIT"]
    timer = "horizon-guard-169-hourly-retry-20261128-v1.timer"
    watch = "horizon-169-hourly-retry-terminal-20261128-v1.service"
    states = {}
    for name in (unit, timer, timer.replace(".timer",".service"), watch):
        fields = "Id,ActiveState,SubState,Job,ControlGroup,MainPID,ControlPID,InvocationID,Result,ExecMainStatus"
        args = ["/usr/bin/systemctl","show","--all","-p",fields,name]
        out = subprocess.run(args, check=False, capture_output=True, text=True, timeout=8)
        st = dict(line.split("=",1) for line in out.stdout.splitlines())
        need(out.returncode in (0,4) and st["Id"] == name and st["ActiveState"] in ("failed","inactive")
             and not st["Job"] and not st.get("ControlGroup") and int(st.get("MainPID",0))==int(st.get("ControlPID",0))==0
             and not (Path("/sys/fs/cgroup/system.slice")/name/"cgroup.procs").exists(), "old unit still owns resources")
        states[name] = st
    raw = subprocess.check_output(["/usr/bin/journalctl","--no-pager","-o","json","_PID=1","UNIT="+unit,
        "INVOCATION_ID="+IID,"_BOOT_ID="+held["boot_id"].replace("-","")],timeout=15)
    events = [json.loads(line) for line in raw.splitlines()]
    exits = [e for e in events if e.get("MESSAGE_ID")=="98e322203f7a4ed290d09fe03c09fe15"]
    final = [e for e in events if e.get("MESSAGE_ID")=="d9b373ed55a64feb8242e02dbe79a49c"]
    need(len(exits)==len(final)==1 and exits[0].get("EXIT_STATUS")=="1" and exits[0].get("EXIT_CODE")=="exited"
         and final[0].get("UNIT_RESULT")=="exit-code", "gate lacks its native terminal")
    tree=c["RETRY"]
    files = sorted((tree/"hourly-guard-receipts").glob("sample-*.json"))
    samples=[]
    for path in files:
        data, ref = read(path,sealed=False)
        need(data["producer_invocation_id"] == IID and data["plan_sha256"] == ar["sha256"] and not data["workers"]
             and data["producer_stop_enabled"] and data["trip_reason"] is None, "foreign first-attempt guard evidence")
        samples.append(ref)
    need(start["first_guard"] in samples, "missing armed guard")
    for path in (FIRST/"GRANT.json", FIRST/"POST_GUARD_PRICE.json", c["BARRIER"]/"allow.json",
                 tree/"v158"/c["BASE_NAME"], tree/"v158"/(c["BASE_NAME"]+".segment.json")):
        need(not os.path.lexists(path), "unexpected private grant or payload "+str(path))
    log, body = c["stable"](tree/"hourly-run/producer.log",keep_bytes=True)
    need(body.endswith(b"TimeoutError: expired before the first guard and postguard grant\n")
         and b"progress slot" not in body, "different held-gate terminal log")
    peer=post["whole_roster"]["base_169"]["native"]["independent_retry169"]
    need(post["stage"]=="native-postguard" and post["fits"] and not post["preliminary"]
         and peer["invocation"]==IID and peer["guard_plan"]==ar and peer["floor"]==plan["minimum_free_bytes"]
         and peer["phase"]=="held" and post["writer"]==pre["writer"] and post["whole_roster"]["fleet"]==pre["whole_roster"]["fleet"]
         and pre["guard_floor"]<plan["minimum_free_bytes"]<post["guard_floor"], "different held reproduction")
    return c["recorded"](FIRST/"UNRELEASED_HELD_CLOSURE.json",dict(schema="horizon-169-unreleased-held-closure-v1",
        invocation_id=IID,held=hr,prestart=pr,intent=sr,guard=ar,samples=samples,terminal=tr,retained_log=log,
        postguard_reproduction=qr,fleet=fr,manager=states,pid1=[exits[0],final[0]],
        initial_protected_floor=pre["guard_floor"],armed_floor=plan["minimum_free_bytes"],
        reproduced_protected_floor=post["guard_floor"],uncovered_bytes=post["guard_floor"]-plan["minimum_free_bytes"],
        reproduced_home_margin=post["home_margin"],reproduced_ram_margin=post["ram_margin"],
        native_worker_started=False,resource_credit_bytes=0,canonical_publication_authorized=False))


if __name__=="__main__":
    print(json.dumps(close()))
