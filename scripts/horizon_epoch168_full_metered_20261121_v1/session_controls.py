"""Exercise fit selection, native-generation binding and atomic nonreplacement in isolation."""
from copy import deepcopy
from pathlib import Path
import sys
import tempfile

sys.path.insert(0,str(Path(__file__).resolve().parent))
import fit
import session


def run():
    pre=dict(eligible_with_168_alone=True,registered_population_compatible=True,fresh_phase_compatible=True,
             available_HOME_bytes=140,complete_required_DATA_bytes=100,available_memory_bytes=150,
             required_available_memory_bytes=130,population={"167":{"pid":10,"ticks":12},"169":{"timer":"a"*32}},
             phase145={"final":"verified-original"},status_registration={"sha256":"b"*64},fleet={"sha256":"c"*64},
             retired_original_peers={},standalone_guard_floor=100)
    assert fit.select(pre)==100 and fit.select(pre,dict(pre,standalone_guard_floor=101),110)==101
    early=dict(pre,phase145={"window":{"original_five_peer_failure":{"sha256":"f"*64}}},
               combined_disk_fits=True,combined_required_HOME_bytes=138)
    assert fit.select(early)==100
    for late in (dict(early,combined_disk_fits=False),dict(early,combined_required_HOME_bytes=141)):
        try: fit.select(early,late,110)
        except ValueError: pass
        else: raise AssertionError("accepted unfunded 136 donor")
    changes=[("population",{"167":{"pid":10,"ticks":13},"169":{"timer":"a"*32}}),
             ("population",{"167":{"pid":10,"ticks":12},"169":{"timer":"d"*32}}),
             ("phase145",{"final":"another-generation"}),("status_registration",{}),
             ("fleet",{}),("retired_original_peers",{"terminal":"new"}),("fresh_phase_compatible",False),
             ("registered_population_compatible",False),("standalone_guard_floor",111),("available_HOME_bytes",99),
             ("available_memory_bytes",129)]
    for name,value in changes:
        post=deepcopy(pre);post[name]=value
        try: fit.select(pre,post,110)
        except ValueError: continue
        raise AssertionError("accepted altered proof "+name)
    with tempfile.TemporaryDirectory() as td:
        d=Path(td); a=d/"source";b=d/"dest"
        a.write_bytes(b"first");b.write_bytes(b"other")
        try:session.move(a,b)
        except FileExistsError: pass
        else:raise AssertionError("replaced existing path")
        assert a.read_bytes()==b"first" and b.read_bytes()==b"other"
        b.unlink();session.move(a,b)
        assert not a.exists() and b.read_bytes()==b"first"
    return dict(fixture_only=True,stage_positive=2,fit_denials=len(changes),native_rename_noreplace=True)


if __name__=="__main__":
    print(run())
