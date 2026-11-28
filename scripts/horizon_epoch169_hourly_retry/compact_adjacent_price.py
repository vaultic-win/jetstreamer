"""Substitute the 48 GiB hard bound only after the sole writer selects the compact 169 operator."""
import ast
import hashlib
import json
from pathlib import Path
import sys

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import compact_adjacent_operator as c
import compact_adjacent_writer as writer

a=c.a
OLD=c.PRIOR_PRICE
NEW=OLD.with_name("issued-price-v34")
REF=c.V33
one=c.one
G=1<<30


def hard_cap(native,before,after):
    """Replace one exclusive ceiling. General availability, other owners and the prior debit are untouched."""
    need=native_need
    old=native["planned_169_retry"]
    donor=native["stopped_169_compute_handoff"]
    need("adjacent_169_effective_cap" not in native and donor["retained_159_ram"]==48*G
         and old["additional_ram"]==8*G and donor["retained_guard_ram"]==G
         and native["ram_margin"]==native["available_ram"]-native["required_ram"]
         and before["enrolled"] is after["enrolled"] and before["enrollment"]==after["enrollment"]
         and not native["resource_credit_bytes"],"unknown or already reconciled 169 hard limit")
    selected=before["enrolled"]
    if selected:
        need(before["phase"]==after["phase"] and (before["phase"]=="precharged" or before["enrollment"])
             and all(0<=r["resident"]<=48*G for r in (before,after)),"different compact 169 owner")
    else:
        need(all(r["phase"]=="precharged" and not r["enrollment"] and r["owner"] is None
                 and not r["resident"] for r in (before,after)),"legacy writer cannot own the compact 169 slot")
    replaced=8*G if selected else 0
    native["adjacent_169_effective_cap"]=dict(selected=selected,previous_producer_max=56*G,
        producer_max=56*G-replaced,guard_max=G,replaced_reserved_bytes=replaced,previous_required_ram=native["required_ram"],
        qualification=COMPACT_QUALIFICATION,interface=INTERFACE,resource_credit_bytes=0)
    native["required_ram"]-=replaced
    native["ram_margin"]+=replaced


def native_need(value,message):
    if not value:
        raise ValueError(message)


def original_files():
    package=a.bind(REF)
    a.need(package["destination"]==str(OLD),"different V33")
    files={}
    for row in package["members"]:
        n=row["name"]
        p=OLD/n
        st=p.lstat()
        a.need(p.parent==OLD and p.resolve(strict=True)==p and st.st_uid==0 and st.st_nlink==1 and not st.st_mode & 0o222
               and st.st_size==row["bytes"] and row["mode"]=="0444" and n not in files
               and a.digest(p)==row["sha256"],"changed V33 member "+n)
        files[n]=p.read_bytes(),0o444
    return files


def build(revision):
    files=original_files()
    refs=writer.bindings()
    legacy=a.bind(writer.prior.INTERFACE)
    def edit(file,old,new):
        data,mode=files[file]
        files[file]=one(data.decode(),old,new).encode(),mode
    counts={n:data.count(bytes(OLD)) for n,(data,_) in files.items() if n.endswith(".py") and bytes(OLD) in data}
    a.need(counts=={"capacity.py":1,"continuation_price.py":1,"successor_price.py":3},"different V33 self-references")
    for n in counts:
        data,mode=files[n]
        files[n]=data.replace(bytes(OLD),bytes(NEW)),mode
    peer="adjacent169_peer.py"
    price="adjacent169_price.py"
    edit(peer,'PKG = ROOT/"operator-v1"','PKG = ROOT/"operator-48-v1"')
    for field,old in (("INTERFACE",writer.prior.INTERFACE),("PROVIDER",legacy["provider"]),("READER",legacy["reader"])):
        edit(peer,field+" = "+repr(old),field+" = "+repr(refs["OPERATOR" if field=="PROVIDER" else field]))
    anchor='    if "adjacent169_reader" not in ready and "adjacent169_provider" not in ready:'
    legacy_reader=f'dict(path=str(directory/"adjacent169_status.py"),sha256={legacy["reader"]["sha256"]!r})'
    edit(peer,anchor,f'''    if ready.get("adjacent169_interface")=={writer.prior.INTERFACE!r}:
        directory=Path(active["new"]["program"]).parent
        prior_reader={legacy_reader}
        peer["need"](ready["adjacent169_provider"]=={legacy["provider"]!r} and ready["adjacent169_scope"]=={legacy["scope"]!r}
                     and ready["adjacent169_reader"]==prior_reader and ready["adjacent169_predecessor"]==TERMINAL
                     and peer["read"](directory/"adjacent169_provider.json")[0]==ready["adjacent169_provider"],
                     "changed legacy 169 writer")
        peer["frozen"](prior_reader["path"],prior_reader)
        return False
'''+anchor)
    edit(peer,'profile["combined_ram"] == 57*G','profile["combined_ram"] == 49*G')
    edit(peer,'profile["producer_memory_max"] == 56*G','profile["producer_memory_max"] == 48*G')
    anchor='    native["adjacent_169_resident_bytes"] = lower'
    edit(peer,anchor,anchor+'\n    hard_cap(native,before,after)')
    text=Path(__file__).read_text()
    functions=text[text.index("def hard_cap("):text.index("def original_files(")]
    initial,mode=files[peer]
    files[peer]=initial+b"\n"+functions.encode()+f"\nCOMPACT_QUALIFICATION = {writer.QUALIFICATION!r}\n".encode(),mode
    edit(price,'ROOT/"operator-v1/layout.py"','ROOT/"operator-48-v1/layout.py"')
    anchor='    raw=native["raw"]'
    edit(price,anchor,'''    effective=native["adjacent_169_effective_cap"]
    need(effective["selected"] and effective["producer_max"]==48*G and effective["guard_max"]==G
         and effective["previous_producer_max"]==56*G and effective["replaced_reserved_bytes"]==8*G
         and effective["previous_required_ram"]-8*G==native["required_ram"]
         and not effective["resource_credit_bytes"],"169 producer cap was not replaced exclusively")
'''+anchor)
    target='and actual["MemoryMax"] == str(56*G) and actual["CPUQuotaPerSecUSec"] == "2s"'
    edit("successor_price.py",target,'and actual["MemoryMax"] == str((48 if retry169["unit"]=='+repr(a.UNIT)+' else 56)*G) and actual["CPUQuotaPerSecUSec"] == "2s"')
    meta=json.loads(files["SOURCE.json"][0])
    a.need(meta["adjacent169_interface"]==writer.prior.INTERFACE,"different V33 writer history")
    meta.update(prior_shared_price=REF,revision=revision,adjacent169_original_interface=writer.prior.INTERFACE,
                adjacent169_interface=writer.INTERFACE,adjacent169_kernel_qualification=writer.QUALIFICATION,
                adjacent169_full_size_refusal=c.REFUSAL)
    files["SOURCE.json"]=(json.dumps(meta,indent=2)+"\n").encode(),0o444
    for n,(raw,_) in files.items():
        if n.endswith(".py"):
            ast.parse(raw,filename=n)
    return files
