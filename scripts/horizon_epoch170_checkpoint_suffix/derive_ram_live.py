"""Derive the mutual live 169/170 price from the exact already-issued joint prestart provider."""
import ast
from pathlib import Path

import following_prepare as f
from derive_gap_price import one
from derive_ram_price import BASE, DEST as PRESTART, RETRY

DEST=BASE/"issued-price-v8"
SEAL="070160cc684e1f97a5b6bc89388473626ca58e1d717ce97e70c92af2000ee8f9"


def extend(name,body):
    if name=="capacity.py":
        body=one(body,str(PRESTART/"capacity.py"),str(DEST/"capacity.py"))
        return one(body,"'ram170_capacity.py'","'ram170_capacity.py','ram170_live.py'")
    if name=="continuation_price.py":
        return one(body,str(PRESTART),str(DEST))
    if name=="successor_price.py":
        f.need(body.count(str(PRESTART))==3,"different joint lower roster paths")
        body=body.replace(str(PRESTART),str(DEST))
        body=one(body,'unit = "horizon-qualify-170-from-73760367-20261128-v1.service"',f'unit = "{RETRY}"')
        return one(body,'actual["MemoryMax"] == str(48*G)','actual["MemoryMax"] == str(56*G)')
    if name=="after_stop.py":
        body=one(body,"    gap170 = retry['before_issue'](core, fleet)",
                 "    live = runpy.run_path(str(directory/'ram170_live.py'))\n    gap170 = live['owner'](core,fleet)")
        return one(body,"retry['before_issue'](core,fleet)==gap170","live['owner'](core,fleet)==gap170")
    return body


def members(staging,revision):
    expected=dict(path=str(PRESTART/"deployment-seal-receipt.json"),sha256=SEAL)
    seal=f.read(expected)
    f.need(seal["destination"]==str(PRESTART),"different joint provider")
    staging.mkdir(mode=0o700,exist_ok=True)
    members={}
    for entry in seal["members"]:
        name=entry["name"];path=PRESTART/name
        f.need(path.parent==PRESTART and f.reference(path)["sha256"]==entry["sha256"],"changed joint roster source")
        if name=="SOURCE.json":
            continue
        body=extend(name,path.read_text())
        ast.parse(body,filename=name)
        out=staging/name;out.write_text(body);members[name]=(out,0o444)
    extra=Path(__file__).with_name("ram170_live.py")
    members[extra.name]=(extra,0o444)
    doc=staging/"SOURCE.json"
    f.save(doc,dict(revision=revision,branch="origin/account-updates",joint_prestart=expected,
        ram170_interface="cf7836a48efd71f886924a07657101691d27d24f6ccf05cbe7938b4be1daedaf",replay_authorized=False))
    members[doc.name]=(doc,0o444)
    return members
