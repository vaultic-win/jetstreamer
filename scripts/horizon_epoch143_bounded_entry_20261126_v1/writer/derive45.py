"""Derive the second-continuation reader from every member of the accepted V44 deployment."""
import ast
import hashlib
import json
from pathlib import Path
import sys
from derive41 import one

HERE = Path(__file__).resolve().parent
OLD = "tools-cold168-retry5-failed166-v44-entry146"
NEW = OLD.replace("v44","v45")
PREVIOUS_SEAL = "ffbcf9381420fe08966f35d24e4b7fada4e3e8684339c92600a4a1169fb1629b"


def cycle(text):
    text = text.replace(", 44)",", 44, 45)")
    old = "        if FAILED166_VERSION == 44:\n            import transition_v44"
    text = one(text,old,old.replace("== 44",">= 44")+"""
        if FAILED166_VERSION == 45:
            import transition_v45
            import rolling170_status as successor170_status""")
    old = "            if FAILED166_VERSION == 44:\n                modules.append(transition_v44)"
    text = one(text,old,old.replace("== 44",">= 44")+"""
            if FAILED166_VERSION == 45:
                modules += [transition_v45, successor170_status.previous, successor170_status.following,
                            import_module('continuation170_contract')]""")
    old = "    elif FAILED166_VERSION == 44:\n        transition_v44.validate"
    text = one(text,old,"    elif FAILED166_VERSION == 45:\n        transition_v45.validate(globals(), ready, receipt)\n"+old)
    old = "                44: (transition_v44.V43_SHA, transition_v44.V43_SEAL),\n"
    text = one(text,old,old+"                45: (transition_v45.V44_SHA, transition_v45.V44_SEAL),\n")
    old = "                    44: 'fb9db4e77c4dd78a49865d46e903a5c081f332ddc10ffdfc099c366cb3742182',\n"
    text = one(text,old,old+old.replace("44:","45:"))
    old = "        time.sleep(max(0,(due-now()).total_seconds()+2))"
    text = one(text,old,"""        delay = max(0,(due-now()).total_seconds()+2)
        if FAILED166_VERSION == 45:
            successor170_status.wait_on_existing_clock(globals(),delay)
        else:
            time.sleep(delay)""")
    old = "    if FAILED166_VERSION == 44 and len(sys.argv) == 4:"
    return one(text,old,"""    if FAILED166_VERSION == 45 and len(sys.argv) == 4:
        head = dict(path=str(Path(sys.argv[2])), sha256=sys.argv[3])
        if sys.argv[1] == '--check-v45-handoff':
            print(json.dumps(transition_v45.ready(globals(), head, receipt)))
            return
        if sys.argv[1] == '--enroll-next-bounded-170':
            writer_ref = bound(ROOT/'FAILED166_CADENCE_V45_ACTIVE.json')
            print(json.dumps(successor170_status.enroll(globals(), head, writer_ref)))
            return
"""+old)


def native(text):
    start,end = text.index('ROOT = BASE /'), text.index('FIELD =')
    text = text[:start]+"from continuation170_contract import INTERFACE, ROOT, interface, closed_comparison\n"+text[end:]
    text = text.replace("from-73726716","from-73746882")
    start,end = text.index("def interface():"),text.index("def read_actor():")
    text = text[:start]+text[end:]
    start,end = text.index('    if prior and prior["interface"] != INTERFACE:'),text.index("    if prior is None:")
    text = text[:start]+text[end:]
    start,end = text.index('        scope = interface()\n        predecessor ='),text.index('        return None\n    scope = interface()')
    text = text[:start]+text[end:]
    return one(text,'    fleet["retained_170_failed_successor"] = interface()["failed_predecessor"]',
               '    fleet["retained_170_bounded_predecessor_comparison"] = closed_comparison(interface())')


def cutover(text):
    text = text.replace('v43-entry146','v44-entry146').replace('V44','V45').replace('--check-v44-handoff','--check-v45-handoff')
    text = one(text,'NEW = BASE / "'+OLD+'"','NEW = BASE / "'+NEW+'"')
    text = one(text,'replace("-v43-", "-v44-")','replace("-v44-", "-v45-")')
    start,end = text.index('        need(live[SUCCESSOR]'), text.index('        observed_clock = clock(timer)')
    text = text[:start]+'''        fleet = json.loads(Path(target["fleet"]["path"]).read_bytes())
        for r in fleet["actual_executing_replays"] + fleet["actual_active_private_diagnostics"]:
            u = r["unit"]
            need(u["Id"] in live and live[u["Id"]]["InvocationID"] == u["InvocationID"]
                 and live[u["Id"]]["MainPID"] == u["MainPID"] and live[u["Id"]]["ActiveState"] == "active",
                 "protected process changed since the accepted fleet")
        roster = {line.split()[0] for line in command("/usr/bin/systemctl", "list-units", "--plain", "--no-legend",
            "--type=service", "--state=running,activating,deactivating", "horizon-qualify-*").decode().splitlines()}
        expected = {r["unit"]["Id"] for r in fleet["actual_executing_replays"] + fleet["actual_active_private_diagnostics"]}
        need(roster == expected and SUCCESSOR in roster, "unpriced producer appeared before writer transfer")
        need(live[SUCCESSOR]["InvocationID"] == "04b0750aead84a83914d18edea9c8736" and
             json.loads(RELEASE.read_bytes())["producer_invocation_id"] == live[SUCCESSOR]["InvocationID"],
             "the validated 170 predecessor changed")
''' + text[end:]
    text = one(text,'/epoch170-from-73726716-20261127-v1/SUCCESSOR_RELEASE.json"',
               '/epoch170-from-73726716-20261127-v1/attempt-2/SUCCESSOR_RELEASE.json"') if '/epoch170-from-73726716-20261127-v1/SUCCESSOR_RELEASE.json"' in text else one(text,
               ' / "epoch170-from-73726716-20261127-v1/SUCCESSOR_RELEASE.json"',' / "epoch170-from-73726716-20261127-v1/attempt-2/SUCCESSOR_RELEASE.json"')
    return text.replace("V43 is no longer","V44 is no longer").replace("unexpected V43 service","unexpected V44 service")


def stage(old,new):
    raw=(old/"deployment-seal-receipt.json").read_bytes()
    if hashlib.sha256(raw).hexdigest()!=PREVIOUS_SEAL: raise ValueError("different V44 deployment")
    seal=json.loads(raw);new.mkdir(mode=0o700);rows=[]
    def add(name,data,mode):
        if name.endswith(".py"): ast.parse(data, filename=name)
        path=new/name;path.write_bytes(data);path.chmod(mode)
        rows.append(dict(name=name,source=str(path),sha256=hashlib.sha256(data).hexdigest(),mode=mode))
    for item in seal["members"]:
        name=item["name"]
        if name=="SHA256SUMS": continue
        data=(old/name).read_bytes()
        if hashlib.sha256(data).hexdigest()!=item["sha256"]: raise ValueError("changed V44 member "+name)
        if name=="status_cycle.py": data=cycle(data.decode()).encode()
        if name in ("full170_status.py","joint168_status.py","cold170_status.py"):
            data=data.replace(f"'{OLD}')".encode(),f"'{OLD}', '{NEW}')".encode())
        add(name,data,int(item["mode"],8))
    add("continuation170_native.py",native((old/"successor170_status.py").read_text()).encode(),0o444)
    add("cutover45.py",cutover((old/"cutover44.py").read_text()).encode(),0o444)
    for n in ("continuation170_contract.py","rolling170_status.py","transition_v45.py"):
        add(n,(HERE/n).read_bytes(),0o444)
    return dict(schema="jetstreamer-sealed-deployment-plan-v1",destination=str(Path(seal["destination"]).with_name(NEW)),members=rows)


if __name__=="__main__": print(json.dumps(stage(*map(Path,sys.argv[1:])),indent=2))
