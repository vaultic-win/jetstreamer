"""Replace the unissued 56 GiB 169 reader registration at the next standard cadence handoff."""
import json
from pathlib import Path
import sys

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import compact_adjacent_operator as compact
import derive_adjacent_writer as prior

a=compact.a
INTERFACE=dict(path=str(compact.INTERFACE),sha256="f026dcb7ec477936c55ccc558cae4580254d91d4c7d0e7ba5c23a69308dc245e")
QUALIFICATION=dict(path=str(a.BASE/"REDUCED_48_KERNEL_QUALIFICATION.json"),
                   sha256="8f0d64d340394517267c62eaa0e4f3c4795735d9e11fa62a854950db29085b48")


def bindings():
    packet=a.bind(INTERFACE)
    scope=a.bind(packet["scope"])
    package=a.bind(packet["provider"])
    qual=a.bind(QUALIFICATION)
    need=a.need
    need(scope["quota"]["producer_ram"]==48*a.G and scope["quota"]["guard_ram"]==a.G
         and scope["quota"]["scratch"]==44*a.G and scope["unit"]==packet["unit"]==a.UNIT
         and scope["unissued_full_size_scope"]==a.bind(prior.INTERFACE)["scope"]
         and packet["prior_interface"]==scope["original_interface"]==prior.INTERFACE and packet["refusal"]==compact.REFUSAL
         and packet["scope"]["path"]==str(compact.SCOPE) and packet["field"]==a.FIELD
         and scope["reduced_memory_qualification"]==packet["reduced_memory_qualification"]==QUALIFICATION
         and qual["prior_kernel_peak"]==compact.PEAK and qual["cgroup"]["kernel_values"]==
             [str(48*a.G),str(45*a.G),"0","200000 100000"] and not qual["cgroup"]["exit_status"]
         and package["destination"]==str(compact.PKG) and packet["reader"]["path"]==str(compact.PKG/"status169.py")
         and a.reference(Path(packet["reader"]["path"]))==packet["reader"] and any(
             m["name"]=="status169.py" and m["sha256"]==packet["reader"]["sha256"] for m in package["members"]),
         "different compact 169 contract or kernel qualification")
    return dict(INTERFACE=INTERFACE,SCOPE=packet["scope"],OPERATOR=packet["provider"],READER=packet["reader"],
                PREVIOUS=packet["previous"],PREVIOUS_HELD=packet["previous_held"])


def members():
    refs=bindings()
    # V70+ already routes exactly this unit and cadence field. Replace only its
    # immutable registration and reader. The progress and route code is identical.
    files=prior.members()
    files["adjacent169_bindings.py"]="".join(f"{key} = {val!r}\n" for key,val in refs.items()).encode()
    files["adjacent169_status.py"]=Path(refs["READER"]["path"]).read_bytes()
    files["adjacent169_provider.json"]=(json.dumps(refs["OPERATOR"],sort_keys=True)+"\n").encode()
    return files


if __name__=="__main__":
    print(json.dumps(dict(bindings=bindings(),members=sorted(members())),sort_keys=True))
