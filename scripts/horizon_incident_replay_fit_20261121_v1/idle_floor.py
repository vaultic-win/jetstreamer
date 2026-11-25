"""Existing epoch 168 host allocation equation with the sealed shared audit CPU policy."""
from pathlib import Path
import runpy
from fit import ANCHOR, BASELINE, CAP, G, MEM, F169, P169, BOOK
import status168 as s
observe_cpu=runpy.run_path(str(Path(__file__).with_name('idle_audit_cpu.py')))['profile']

def floor(fleet,ledger,tree,peers):
    anchor=s.read(ANCHOR,BASELINE)[0]["fit"]
    x=ledger["native_inputs"];roots=x["roots"];audit=fleet["continuing_audit_obligation"]
    s.need(anchor["charged_cpu_micros"]==64000000 and anchor["existing_total_memory"]==MEM
           and anchor["temporary"]==x["temporary_workers"]==[] and anchor["holding_transfer_memory"]==2*G
           and anchor["holding_transfer_cpu_micros"]==1000000 and all(x["auxiliary"][k]==anchor["auxiliary"][k] for k in ("cpu_quota_micros","memory_bytes","retained_bookings"))
           and audit["additional_cpu_quota_micros"]==4000000 and audit["additional_memory_bytes"]==24*G
           and audit["current_storage"]["remaining_DATA_growth_bytes"]==18*G and roots["root_cap_bytes"]==CAP,
           "changed complete host, holding, temporary or audit commitments")
    observe_cpu()
    # Allocated bytes already reduce statvfs. An overrun cannot turn the unpaid
    # part of a closed booking into negative growth or an admission credit.
    remaining=max(0,CAP-tree["physical_bytes"])
    fixed=max(x["historical_floor_bytes"],audit["configured_free_floor_bytes"])
    other=(fixed+roots["peer_remaining_growth_bytes"]+10*G+x["auxiliary"]["remaining_growth_bytes"]+
           (64<<20)+x["independent166_whole_cap_bytes"]+18*G)
    prior169=s.read(F169/"POST_GUARD_CAPACITY.json","803bb540a6601238e8754c733a8cf900a9b6d103116ad6dac50bdcc2a081defc")[0]["protected_raw_floor_bytes"]
    def base(unspent):
        return max(other+unspent,prior169,8297502499408+unspent)
    s.need(base(roots["remaining_standard_root_bytes"])==anchor["reservation_baseline"],"original fit does not reproduce")
    b=peers["172"]["guard"]
    if "169" in peers:
        a=peers["169"]["guard"]
    else:
        plan=s.bound(P169,Path(P169["path"]))
        a=dict(floor=plan["minimum_free_bytes"],remaining=plan["maximum_root_physical_bytes"])
    complete=max(max(base(remaining),a["floor"])+a["remaining"]+16*G,b["floor"])+b["remaining"]+(128<<20)
    return complete,dict(retained_168_remaining=remaining,historical_168_remaining=roots["remaining_standard_root_bytes"],
        rebased_floor=base(remaining),original_base=anchor["reservation_baseline"],source=BOOK,shared_host=s.ref(ANCHOR,BASELINE))


