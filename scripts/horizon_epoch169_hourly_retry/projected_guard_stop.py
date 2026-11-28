"""Bind the second 169 worker's concrete guard stop to PID1, its grant and the layout fixture."""
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess

RT=Path("/var/lib/jetstreamer/horizon_runtime_data")
ROOT=RT/"epoch169-hourly-retry-20261128-v2"
IID="1446633fdd224bab9297255a7ad66330"
FIXTURE=ROOT/"guard-alias-fixture.j_jktslk/COMPLETE.json"
FIXTURE_SHA="2e772ec0fd3582d02c9f7f29b24810ab4389e8d05684851f0bc271a30827f5ec"
CONTRACT="cc673a4da90aab415f4cf98628492297d0c4b9b713239db24db41e8e89774736"


def close():
    source=ROOT/"operator-v1/contract.py"
    if hashlib.sha256(source.read_bytes()).hexdigest()!=CONTRACT:
        raise ValueError("different second-attempt evidence reader")
    c=runpy.run_path(str(source))
    read,need=c["read"],c["need"]
    unit,tree=c["UNIT"],c["RETRY"]
    receipt=tree/"hourly-guard-receipts"
    stage,sr=read(ROOT/"SCOPE.json","322698c6be8e7632654eea5b9074a395b61f27db648bb6ebb818f79b0ee1bd0e")
    held,hr=read(ROOT/"HELD_GATE.json","600384a36715d3a517b7c1a4d399966970bd61e3d8a32eb5dd8d1cf9e5abc594")
    start,ir=read(ROOT/"START_INTENT.json","cac3f609be863104fea4075d170c8d189a80dbccf4d20c59cff7d9c8bb5d1101")
    plan,pr=read(ROOT/"GUARD_PLAN.json","c946d07cf05b6271235d9cd263c97fe95706b970bc8a995413eea964ea58746d")
    grant,gr=read(ROOT/"GRANT.json","260b9cf6950e2d0716c1c10f49fd002c0b4cb9a964a2daa5ac732a5e5e614c66")
    post,qr=read(ROOT/"POST_GUARD_PRICE.json",grant["native_post_guard_price_sha256"])
    terminal,tr=read(ROOT/"results/TERMINAL.json","900841555d64dddb45cec4d0904e90ff8923f22b8f5746f0a54e3bf46874e2ad")
    intent,ar=read(receipt/"stop-intent.json","adf7cd91e0af1f7f6307ab11f5e951c9d75bf7aaf5a3b12cea20fadf9d4b6b4a",sealed=False)
    stop,er=read(receipt/"stop-completion.json","8be50829930c5ca075b5b33478dfab18544364656b391576b053e4b3474d4c65",sealed=False)
    check,fr=read(FIXTURE,FIXTURE_SHA)
    sample=intent["sample"]
    need(held["invocation_id"]==plan["invocation_id"]==start["producer_invocation_id"]==grant["invocation_id"]
         ==terminal["invocation_id"]==stop["producer_invocation_id"]==intent["producer_invocation_id"]==IID
         and start["scope"]==sr and start["held"]==hr and terminal["grant_sha256"]==gr["sha256"]
         and terminal["unit"]==stage["producer_unit"]==unit and grant["guard_plan_sha256"]==stop["plan_sha256"]
         ==sample["plan_sha256"]==pr["sha256"] and stop["intent"]==ar["path"]
         and sample["producer"]["pid"]==held["pid"]==grant["pid"] and sample["producer_stop_enabled"]
         and sample["worker_observation_error"]=="worker escaped the bound generation"
         and sample["trip_reason"]==intent["reason"]=="worker-observation-failed"
         and sample["available_bytes"]>=plan["minimum_free_bytes"]==sample["minimum_free_bytes"]
         and not sample["root_physical_observation"]["exceeds_budget"] and not sample["workers"]
         and stop["terminal"]["pid"]==0 and not stop["scratch_deleted"]
         and post["fits"] and all(post["postguard_checks"].values()) and not terminal["private_span"]
         and terminal["archive"] is None and not terminal["canonical_publication_authorized"]
         and terminal["disposition"]=="interrupted-or-unclassified" and check["original_terminal"]==tr
         and check["outcomes"]["original"]["reason"]=="worker-observation-failed"
         and check["outcomes"]["projected"]["reason"] is None and check["outcomes"]["disk"]["reason"]=="root-physical-budget",
         "different guarded termination")
    log,body=c["stable"](tree/"hourly-run/producer.log",keep_bytes=True)
    need(log["inode"]==grant["log_inode"] and log["device"]==grant["log_device"]
         and all(terminal["log"][k]==log[k] for k in terminal["log"])
         and b"starting isolated solana-v1.5.8 worker" in body and b"progress slot" not in body
         and not os.path.lexists(stage["output"]) and not os.path.lexists(stage["output"]+".segment.json"),"changed closed output")
    events=subprocess.check_output(["journalctl","--no-pager","-o","json","_PID=1","UNIT="+unit,"INVOCATION_ID="+IID,
                                     "_BOOT_ID="+held["boot_id"].replace("-","")],text=True)
    wanted={"de5b426a63be47a7b6ac3eaac82e2f6f","7ad2d189f7e94e70a38c781354912448"}
    observed=[json.loads(line) for line in events.splitlines()]
    rows=[e for e in observed if e.get("MESSAGE_ID") in wanted]
    need(len(rows)==2 and {e["MESSAGE_ID"] for e in rows}==wanted and rows[-1]["MESSAGE_ID"].startswith("7ad2"),
         "missing matched PID1 stop")
    names=(unit,stage["watcher"],stage["guard_timer"],stage["guard_timer"].replace(".timer",".service"))
    states={}
    for name in names:
        args=["systemctl","show","--all","-p","Id,Job,ActiveState,MainPID,ControlPID,ControlGroup,InvocationID",name]
        raw=subprocess.run(args,check=False,capture_output=True,text=True)
        st=dict(line.split("=",1) for line in raw.stdout.splitlines())
        need(raw.returncode in (0,4) and st["Id"]==name and st["ActiveState"]=="inactive" and not st["Job"]
             and not st.get("ControlGroup") and int(st.get("MainPID",0))==int(st.get("ControlPID",0))==0
             and not (Path("/sys/fs/cgroup/system.slice")/name/"cgroup.procs").exists(),"previous 169 still owns resources")
        states[name]=st
    return c["recorded"](ROOT/"WORKER_ALIAS_STOP.json",dict(schema="horizon-169-second-worker-guard-stop-v1",
        invocation_id=IID,scope=sr,held=hr,start=ir,guard_plan=pr,grant=gr,postguard=qr,terminal=tr,
        stop_intent=ar,stop_completion=er,proof=fr,log=log,states=states,pid1=rows,
        guard_disk_margin=sample["available_bytes"]-sample["minimum_free_bytes"],guard_observed_worker=False,
        first_replay_slot_observed=False,resource_credit_bytes=0,canonical_publication_authorized=False))


if __name__=="__main__":
    print(json.dumps(close()))
