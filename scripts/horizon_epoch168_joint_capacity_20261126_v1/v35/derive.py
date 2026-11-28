"""Seal the V35 receiver by adapting the verified V34 bytes."""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import re

HERE=Path(__file__).resolve().parent
V34_SEAL="d62ac67045ac3162352ba27202dee7aed63521ba7ba50f3fc816b4b9d78d0b33"
OLD="tools-cold168-retry5-failed166-v34-entry146"
NEW="tools-cold168-retry5-failed166-v35-entry146"


def change(text,old,new):
    if text.count(old)!=1:
        raise ValueError(f"unexpected V34 source around {old.strip().splitlines()[0]}")
    return text.replace(old,new)


def cycle(text):
    text=re.sub(r", 34\)",", 34, 35)",text)
    text=text.replace("FAILED166_VERSION == 34","FAILED166_VERSION >= 34")
    text=text.replace("FAILED166_VERSION != 34","FAILED166_VERSION < 34")
    text=change(text,"    import bridge170_status","    import bridge170_status\n\nif FAILED166_VERSION == 35:\n    import transition_v35")
    text=change(text,"transition_v33, transition_v34, bridge170_status]",
                "transition_v33, transition_v34, bridge170_status]\n            if FAILED166_VERSION == 35:\n                modules.append(transition_v35)")
    text=change(text,"    cold_workers.reconcile(c,cycle.observed_lane)",
                "    c.bridge170_prior = bridge_prior\n    cold_workers.reconcile(c,cycle.observed_lane)")
    text=change(text,"        cold_workers.full170.historical_diagnostic(fleet)",
                """        prior = bridge170_status.retained_population(fleet, sealed(ready['config'])) if FAILED166_VERSION == 35 else None
        cold_workers.full170.historical_diagnostic(fleet, private_successor=prior)""")
    text=change(text,"    elif FAILED166_VERSION >= 34:\n        transition_v34.validate",
                "    elif FAILED166_VERSION == 35:\n        transition_v35.validate(globals(), ready, receipt)\n"
                "    elif FAILED166_VERSION == 34:\n        transition_v34.validate")
    row="                34: (transition_v34.V33_SHA, transition_v34.V33_SEAL_SHA),"
    text=change(text,row,"                35: (transition_v35.V34_SHA, transition_v35.V34_SEAL_SHA),\n"+row)
    row="                    34: 'fb9db4e77c4dd78a49865d46e903a5c081f332ddc10ffdfc099c366cb3742182',"
    text=change(text,row,row.replace("34:","35:")+"\n"+row)
    cli="    if FAILED166_VERSION >= 34 and len(sys.argv) == 4 and sys.argv[1] == '--check-v34-handoff':"
    return change(text,cli,"""    if FAILED166_VERSION == 35 and len(sys.argv) == 4 and sys.argv[1] == '--check-v35-handoff':
        head = dict(path=str(Path(sys.argv[2])), sha256=sys.argv[3])
        print(json.dumps(transition_v35.ready(globals(), head, receipt)))
        return
"""+cli.replace(">= 34","== 34"))


def full170(text):
    text=change(text,f"'{OLD}')",f"'{OLD}', '{NEW}')")
    text=change(text,"def historical_diagnostic(fleet):","def historical_diagnostic(fleet, *, private_successor=None):")
    return change(text,"    need(not any(item['epoch'] == 170 for item in fleet['actual_active_private_diagnostics'])",
                  """    need(not any(item['epoch'] == 170 and item != private_successor
                 for item in fleet['actual_active_private_diagnostics'])""")


def cold170(text):
    text=change(text,f"V34_PACKAGE = '{OLD}'",f"V34_PACKAGE = '{OLD}'\nV35_PACKAGE = '{NEW}'")
    text=change(text,"        full170.historical_diagnostic(c.fleet)",
                "        full170.historical_diagnostic(c.fleet, private_successor=getattr(c, 'bridge170_prior', None))")
    return text.replace("V33_PACKAGE, V34_PACKAGE)","V33_PACKAGE, V34_PACKAGE, V35_PACKAGE)")


def joint168(text):
    start=f"('tools-cold168-retry5-failed166-v32-entry146', 'tools-cold168-retry5-failed166-v33-entry146', '{OLD}')"
    if text.count(start)!=2:
        raise ValueError("unexpected V34 joint exit branches")
    text=text.replace(start,start[:-1]+f", '{NEW}')")
    tail=f"                   'tools-cold168-retry5-failed166-v32-entry146', 'tools-cold168-retry5-failed166-v33-entry146', '{OLD}')"
    return change(text,tail,tail[:-1]+f", '{NEW}')")


def stage(baseline,staging):
    original=(baseline/"deployment-seal-receipt.json").read_bytes()
    if hashlib.sha256(original).hexdigest()!=V34_SEAL:
        raise ValueError("expected exact immutable V34 package")
    receipt=json.loads(original)
    staging.mkdir(mode=0o700)
    patches={"status_cycle.py":cycle,"full170_status.py":full170,"cold170_status.py":cold170,"joint168_status.py":joint168}
    rows=[]
    def write(name,data,mode):
        if any(row["name"]==name for row in rows) or Path(name).name!=name:
            raise ValueError("foreign V34 member")
        if name.endswith(".py"):
            ast.parse(data,filename=name)
        file=staging/name
        file.write_bytes(data)
        file.chmod(mode)
        rows.append(dict(name=name,source=str(file),mode=mode,sha256=hashlib.sha256(data).hexdigest()))
    for member in receipt["members"]:
        name=member["name"]
        if name=="SHA256SUMS":
            continue
        data=(baseline/name).read_bytes()
        if hashlib.sha256(data).hexdigest()!=member["sha256"]:
            raise ValueError(f"V34 member changed: {name}")
        if name in patches:
            data=patches[name](data.decode()).encode()
        write(name,data,int(member["mode"],8))
    write("transition_v35.py",(HERE/"transition_v35.py").read_bytes(),0o444)
    return dict(schema="jetstreamer-sealed-deployment-plan-v1",destination=str(Path(receipt["destination"]).with_name(NEW)),members=rows)


if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("baseline",type=Path)
    parser.add_argument("staging",type=Path)
    args=parser.parse_args()
    print(json.dumps(stage(args.baseline,args.staging),indent=2))
