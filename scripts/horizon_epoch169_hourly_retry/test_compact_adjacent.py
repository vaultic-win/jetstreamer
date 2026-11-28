"""Exercise both writer registrations and the real fleet without giving the fixture a production booking."""
import argparse
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import time

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import compact_adjacent_price as price
import compact_adjacent_writer as w

a=price.a
c=price.c


def unit():
    d=runpy.run_path(str(HERE/"compact_adjacent_price.py"))
    adjust=d["hard_cap"]
    adjust.__globals__.update(COMPACT_QUALIFICATION=w.QUALIFICATION,INTERFACE=w.INTERFACE)
    profile=dict(planned_169_retry=dict(additional_ram=8*c.G),stopped_169_compute_handoff=dict(
        retained_159_ram=48*c.G,retained_guard_ram=c.G),required_ram=100*c.G,available_ram=95*c.G,
        ram_margin=-5*c.G,resource_credit_bytes=0)
    closed=dict(enrolled=False,phase="precharged",owner=None,enrollment=None,resident=0)
    for selected in (False,True):
        n=profile.copy()
        state=dict(closed,enrolled=selected)
        adjust(n,state,state)
        assert n["required_ram"]==profile["required_ram"]-(8*c.G if selected else 0) and n["available_ram"]==profile["available_ram"]
        assert n["ram_margin"]==(3*c.G if selected else -5*c.G) and not n["resource_credit_bytes"]
        try:
            adjust(n,state,state)
        except ValueError:
            pass
        else:
            raise AssertionError("accepted duplicate cap change")
    for left,right in ((closed,dict(closed,enrolled=True)),(dict(closed,phase="held"),dict(closed,phase="held")),
                       (dict(closed,enrolled=True,resident=49*c.G),dict(closed,enrolled=True,resident=49*c.G))):
        try:
            adjust(profile.copy(),left,right)
        except ValueError:
            continue
        raise AssertionError("invalid writer or owner accepted")


def native(simulate):
    a.need(os.geteuid()==0 and not Path("/proc/self/ns/mnt").samefile("/proc/1/ns/mnt"),
           "run the native fixture in a private mount namespace")
    unit()
    info,model,l=c.evidence()
    c.not_issued(l)
    save=l["save"]
    parent=price.OLD.parent
    with tempfile.TemporaryDirectory(dir=a.BASE,prefix="compact-price-namespace-") as scratch:
        tmp=Path(scratch)
        for n in ("upper","work","source","writer-source"):
            (tmp/n).mkdir(mode=0o700)
        argv=["mount","-t","overlay","overlay","-o",f"lowerdir={parent},upperdir={tmp/'upper'},workdir={tmp/'work'}",str(parent)]
        subprocess.run(argv,check=True)
        try:
            a.need(subprocess.check_output(["findmnt","-n","-M",str(parent),"-o","FSTYPE"],text=True).strip()=="overlay"
                   and not price.NEW.exists(),"foreign shared price in fixture namespace")
            a.shared.BASE=tmp
            members={}
            for n,(body,mode) in price.build("isolated-native-48g-fixture").items():
                path=tmp/"source"/n
                save(path,body,mode)
                members[n]=path,mode
            pkg=a.shared.seal(members,price.NEW,save)
            replacement=w.members()
            official=a.RT/"survivor172-cadence-20261122-v1"
            current=max(official.glob("FAILED166_CADENCE_V*_ACTIVE.json"),key=lambda p:int(p.name.split("_V")[1].split("_")[0]))
            active,original_writer=l["pinned"](current)
            native_dir=Path(active["new"]["program"]).parent
            ready=l["bound"](active["ready"])
            actual_compact=ready.get("adjacent169_interface")==w.INTERFACE
            selected_writer=original_writer
            if simulate and not actual_compact:
                dest=tmp/"writer"
                staged={}
                for n,body in replacement.items():
                    path=tmp/"writer-source"/n
                    save(path,body)
                    staged[n]=path,0o444
                writer_pkg=a.shared.seal(staged,dest,save)
                sys.path[0:0]=[str(dest),str(native_dir),str(a.RT/"prefix140-status-cadence-20261122-v1/cadence-tools")]
                entry=runpy.run_path(str(dest/"adjacent169_route.py"))
                ready_fields=entry["ready_fields"](dest)
                assert ready_fields["adjacent169_interface"]==w.INTERFACE
                fake_ready=save(tmp/"fixture-ready.json",dict(ready_fields,package=writer_pkg))
                selected_writer=save(tmp/"fixture-active.json",dict(ready=fake_ready,new=dict(program=str(dest/"status_cycle.py"))))
            normal_run=runpy.run_path
            seen={}
            def qualified_reader(path,*args,**kwargs):
                module=normal_run(path,*args,**kwargs)
                if Path(path)==price.NEW/"adjacent169_peer.py" and selected_writer!=original_writer:
                    read=module["registered_writer"]
                    def select(peer,writer):
                        assert writer==original_writer and not read(peer,writer) and read(peer,selected_writer)
                        seen["native_registration_checked"]=True
                        return True
                    read.__globals__["registered_writer"]=select
                return module
            runpy.run_path=qualified_reader
            try:
                whole=runpy.run_path(str(price.NEW/"capacity.py"))["complete_roster"](False,adjacent169=True)
            finally:
                runpy.run_path=normal_run
            assert whole["writer"]==original_writer and (not simulate or actual_compact or seen)
            engine=runpy.run_path(str(price.NEW/"adjacent169_price.py"))
            engine["startup"](l["bound"])
            cap=whole["base_169"]["native"]["adjacent_169_effective_cap"]
            geometry=None
            if cap["selected"]:
                fs=os.statvfs(a.BASE)
                ram=next(int(s.split()[1])*1024 for s in Path("/proc/meminfo").read_text().splitlines() if s.startswith("MemAvailable:"))
                geometry=engine["geometry"](whole,"prestart",None,fs.f_bavail*fs.f_frsize,ram)
            assert cap["selected"]==(actual_compact or simulate)
            result=dict(package=pkg,actual_writer=original_writer,exercised_writer=selected_writer,
                        simulated_activation=(selected_writer!=original_writer),native=(selected_writer==original_writer),
                        native_roster=whole,geometry=geometry,ordinary_production_admission=False,resource_credit_bytes=0)
            ref=save(a.BASE/("REDUCED_169_NATIVE_FIXTURE_"+str(time.time_ns())+".json"),result,0o400)
            return dict(receipt=ref,geometry=geometry,simulated_activation=result["simulated_activation"],home_margin=whole["home_margin"],
                        ram_margin=whole["ram_margin"],effective=cap)
        finally:
            subprocess.run(["umount",str(parent)],check=True)


if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--native",choices=("actual","projected"))
    args=p.parse_args()
    if args.native:
        print(json.dumps(native(args.native=="projected"),sort_keys=True),flush=True)
    else:
        unit()
        print("Passed cap selection, duplicate, foreign owner and resident bounds")
