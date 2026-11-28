"""Add the retry as a separately authenticated actor to both native V7 censuses."""
import hashlib
import json
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import contract as c
import prepare
import quote

OLD = c.RT/"epoch162-first-hourly-completion-20261127-v2/issued-price-v7"
OLD_SEAL = "8f9377d8b0405d60fb7687b4195b8c69b45451f864971358d902b4221df748ee"
DEST = c.CONTROL/"roster-v1"


def extend(name, source):
    one=prepare.once
    if name=="capacity.py":
        source=one(source,"STOPPED = ROOT / 'issued-price-v7/capacity.py'",
                   f"STOPPED_V7 = ROOT / 'issued-price-v7/capacity.py'\nSTOPPED = Path('{DEST}/capacity.py')")
        old="{'path':str(STOPPED_V6), 'sha256':'dc2f6f03ff83089c3d8874b85a49bf2503bcdd32012397c78ce8f12bdcb7138b'}"
        source=one(source,old,old+", {'path':str(STOPPED_V7), 'sha256':'e3038d926906d0197cba3edbc41fed9a16d3aac8a44ba09dac0592138439e0e6'}")
        source=one(source,"{'after_stop.py','scan_handback.py','gap170_capacity.py'}",
                   "{'after_stop.py','scan_handback.py','gap170_capacity.py','retry169_peer.py'}")
        # Only the bounded retry's quote may consume the raw result. It applies
        # the incremental 8-GiB RAM and entire new writable tree exactly once.
        return one(source,"def whole_roster():","def base_for_retry_only():")
    if name=="continuation_price.py":
        source=one(source,'SPLIT162_PRICE.with_name("issued-price-v7")',f'Path("{DEST}")')
        source=one(source,"native162=None, gap170=None):","native162=None, gap170=None, retry169=None):")
        return one(source,"gap170=gap170, **options)","gap170=gap170, retry169=retry169, **options)")
    if name=="successor_price.py":
        original='RT/"epoch162-first-hourly-completion-20261127-v2/issued-price-v7"'
        c.need(source.count(original)==2, "changed roster package path guards")
        source=source.replace(original,f'Path("{DEST}")')
        source=one(source,"native162=None, gap170=None):","native162=None, gap170=None, retry169=None):")
        marker='    need(units == expected, "replay owner changed: "+repr(units ^ expected))'
        return one(source,marker,f'''    if retry169 is not None:
        actual = state("{c.UNIT}")
        need(Path(__file__).resolve().parent == Path("{DEST}") and phase == "start"
             and actual["Id"] == retry169["unit"] == "{c.UNIT}"
             and actual["InvocationID"] == retry169["invocation"] and actual["MainPID"] == str(retry169["pid"])
             and actual["MemoryMax"] == str(56*G) and actual["CPUQuotaPerSecUSec"] == "2s"
             and actual["MemorySwapMax"] == "0" and not actual["Job"], "unregistered hourly retry")
        expected.add(actual["Id"])
''' +marker)
    if name=="following_peers.py":
        marker="    peer169 = price['actor']"
        return one(source,marker,'''    original169 = price['actor']
    receiver = runpy.run_path(str(Path(__file__).with_name("retry169_peer.py")))["load"]()
    peer169 = dict(original169)
    peer169["current"] = lambda full: original169["current"](receiver["predecessor_view"](full))
    peer169["recheck"] = lambda full, row: original169["recheck"](receiver["predecessor_view"](full), row)''')
    if name=="after_stop.py":
        source=one(source,"def observations(core, fleet, raw, first, gap170):",
                   "def observations(core, fleet, raw, first, gap170, retry169):")
        marker="    actual = {line.split()[0] for line in core.cmd("
        source=one(source,marker,'''    if retry169:
        native[169] = dict(Id=retry169["unit"], InvocationID=retry169["invocation"])
'''+marker)
        marker="    gap170 = gap['owner'](core,fleet)"
        source=one(source,marker,marker+'''
    receiver = runpy.run_path(str(directory/"retry169_peer.py"))["load"]()
    retry169 = receiver["census"](fleet)''')
        source=one(source,"gap170=gap170)","gap170=gap170,retry169=retry169)")
        marker="observations(core,fleet,raw,first,gap170)"
        c.need(source.count(marker)==2, "changed native before/after roster checks")
        source=source.replace(marker,"observations(core,fleet,raw,first,gap170,retry169)")
        marker="    native['independent_gap170'] = gap170"
        source=one(source,marker,"    native['independent_retry169'] = retry169\n"+marker)
        marker="core.need(gap['owner'](core,fleet)==gap170 and "
        return one(source,marker,"core.need(receiver['census'](fleet)==retry169 and gap['owner'](core,fleet)==gap170 and ")
    return source


def plan(staging):
    prior_ref=quote.verified_provider(OLD,OLD_SEAL)
    spec,ref=c.read(prepare.DEPLOY/"deployment-seal-receipt.json")
    quote.verified_provider(prepare.DEPLOY,ref["sha256"])
    known={m["name"]:m["sha256"] for m in spec["members"]}
    c.need({"observe.py","actor.py","contract.py","namespace.py","quote.py","scratch_mount.py"}<=known.keys(),
           "missing independent observer dependencies")
    seal=quote.bound(prior_ref)
    files={}
    for member in seal["members"]:
        name=member["name"]
        if name!="SOURCE.json":
            files[name]=extend(name,(OLD/name).read_text())
    # The external observer and every imported sibling have immutable provenance.
    files["retry169_peer.py"]=f'''import hashlib
from pathlib import Path
import runpy
import stat

DIRECTORY=Path("{prepare.DEPLOY}")
MEMBERS={known!r}

def load():
    for name, digest in MEMBERS.items():
        path=DIRECTORY/name
        st=path.lstat()
        if (path.parent!=DIRECTORY or path.resolve(strict=True)!=path or not stat.S_ISREG(st.st_mode)
            or st.st_uid!=0 or st.st_nlink!=1 or st.st_mode&0o222
            or hashlib.sha256(path.read_bytes()).hexdigest()!=digest):
            raise ValueError("unsealed retry observer dependency " + name)
    return runpy.run_path(str(DIRECTORY/"observe.py"))
'''
    files["SOURCE.json"]=json.dumps(dict(predecessor=prior_ref,operator=ref,
                                       purpose="169 only; both native rosters bind the held retry"),sort_keys=True)+"\n"
    members=[]
    for name,data in sorted(files.items()):
        if name.endswith(".py"):
            compile(data,name,"exec")
        path=staging/name
        with path.open("x") as fd:
            fd.write(data)
        members.append(dict(name=name,source=str(path),mode=0o444,sha256=hashlib.sha256(data.encode()).hexdigest()))
    return c.recorded(c.CONTROL/f"ROSTER_PLAN_{time.time_ns()}.json",
                      dict(schema="jetstreamer-sealed-deployment-plan-v1",destination=str(DEST),members=members))


if __name__=="__main__":
    print(json.dumps(plan(Path(sys.argv[1]))))
