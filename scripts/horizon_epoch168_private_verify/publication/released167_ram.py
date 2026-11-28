"""Transfer the unassigned part of the original 167 RAM reservation to the common roster."""

from pathlib import Path

G = 1 << 30
M = 1 << 20
RETURN = 22_682_796_032
FAMILY = Path("/var/lib/jetstreamer/horizon_runtime_data")
DONOR = FAMILY / "epoch167-checkpoint-tail-20261127-v1/NATIVE_TAIL_AND_GUARD_DRAIN.json"
DRAIN = "84f37a4cb4886968c932b624b47a7863fde5b115eff2bbd11a4255f4c5f4bee9"
BASELINE = FAMILY / "epoch172-current-delivery-20261121-v1/V39_ORIGINAL_172_LIVE_QUOTE.json"
BASELINE_SHA = "ac1226a7e2e64c06a09c688c46b1fcb4756362fef9786ead79b19c388dba0285"
ASSEMBLY = FAMILY / "epoch167-assembly-20261127-v1/assembly-turnover-v1"
BOOKING = "76196db58c045a44b3b910823a60ae16db769302c4bff681ccd1598eb3b856e9"
DISPATCH = "34f8da8e9b786d6374f371252485fd794f4c64bee47d2adcafc554455099053e"
PUB = "93558ae93485439d45eabe3c032f525efd318fd7fcada69db6a23ff7be2a5246"
SHARES = dict(source_qualification=(4*G,"ab8147b379d144a696b1d210127ea866"),
              epoch168_classifier_build=(768*M,"9ea5ace532d34416afe0a678ef51a437"),
              checksum_read=(128*M,"e88bd2815ad54ea4aef39c4f59adfcbb"))
FIELD = "returned_unassigned_167_ram"


def need(condition, reason):
    if not condition:
        raise ValueError("167 RAM handback: " + reason)


def ratify_base(base, core):
    """Apply the fixed grant before each inherited RAM gate. Commit it only after both native accountants."""
    baseline, reference = core.read(BASELINE, BASELINE_SHA)
    original = baseline["whole_roster"]
    tail = base["native"]["raw"]["joint"]["closed_167_tail"]
    need(core.bound(base["fleet"])["owner"] == "/root" and FIELD not in base and not base["resource_credit_bytes"]
         and tail["drain"] == original["closed_167_suballocations"]["native_drain"] == dict(path=str(DONOR),sha256=DRAIN)
         and tail["retained_ram"] == 42*G and tail["released_ram"] == 0
         and original["closed_167_suballocations"]["unassigned"]["ram_bytes"] == RETURN
         and original["closed_167_suballocations"]["unassigned"]["cpu_micros_per_second"] == 0
         and original["publication168_allocation"]["operator"]["sha256"] == PUB
         and original["epoch167_private_assembly"]["booking"]["sha256"] == BOOKING,
         "different baseline or already counted")
    # budget169() has exactly the disk and RAM predicates at this point. Keep its
    # original result as evidence and pass the reduced commitment through all
    # existing protection, candidate and installed-floor checks.
    before = base["ram_margin"]
    need(type(before) is int and base["fits"] == (min(before,base["home_margin"]) >= 0), "unknown base predicate")
    base[FIELD] = dict(source=reference,owner="/root",pool="whole-roster",returned_bytes=RETURN,
                       previous_ram_margin=before,previous_home_margin=base["home_margin"])
    base["ram_margin"] = before + RETURN
    base["fits"] = min(base["ram_margin"],base["home_margin"]) >= 0


def reconcile(whole, core):
    sharing = whole["closed_167_suballocations"]
    previous = sharing["unassigned"]
    assembly = whole["epoch167_private_assembly"]
    publication = whole["publication168_allocation"]
    grant = whole["base_169"][FIELD]
    need(FIELD not in whole and "ram_return_to_fleet" not in sharing
         and grant["returned_bytes"] == RETURN and grant["owner"] == "/root"
         and grant["source"] == {"path":str(BASELINE),"sha256":BASELINE_SHA}
         and whole["base_169"]["ram_margin"] == grant["previous_ram_margin"] + RETURN
         and sharing["retained_producer_ram"] == 42*G and sharing["guard_ram_separate"] == G
         and sharing["native_drain"] == {"path":str(DONOR),"sha256":DRAIN}
         and sharing["retained_cpu_micros_per_second"] == 3_000_000 and sharing["additional_ram"] == 0
         and whole["epoch157_lanej_rotation"]["sublease"]["ram_bytes"] == 0 and not whole["resource_credit_bytes"],
         "duplicate handback, different recipient or competing sublease")
    named = 0
    for name,(memory,iid) in SHARES.items():
        phase = sharing["phases"][name]
        need(sharing[name]["ram_bytes"] == memory and phase["phase"] == "terminal" and phase["invocation"] == iid
             and phase["manager_message"] == "7ad2d189f7e94e70a38c781354912448" and phase["cursor"]
             and publication["closed_subleases"][name]["terminal"] == phase, "different named sublease " + name)
        named += memory
    book, book_ref = core.read(ASSEMBLY / "BOOKED.json", BOOKING)
    dispatch, dr = core.read(ASSEMBLY / "DISPATCH_RESULT.json", DISPATCH)
    name = book["unit"]
    need(dispatch["booking"] == book_ref and dispatch["unit"]["Id"] == name and book["memory"] == 8*G
         and book["cpu"] == 1000000 and publication["operator"]["sha256"] == PUB
         and publication["memory_max"] == 8*G and publication["cpu_micros_per_second"] == 2000000
         and publication["additional_ram"] == assembly["additional_compute_ram"] == 0
         and sharing["additional_home"] == 0, "changed assembly or publication charge")
    if assembly["phase"] == "booked":
        need(assembly["booking"] == book_ref, "different assembler booking")
        native = core.state(name, "Id,ActiveState,SubState,InvocationID,MainPID,ControlPID,ControlGroup,Job,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,NRestarts")
        need(all(dispatch["unit"][k] == value for k,value in native.items())
             and native["InvocationID"] == "ef910ddc2a6545bf9691d23389ad0bfa"
             and native["MemoryMax"] == str(8*G) and native["CPUQuotaPerSecUSec"] == "1s"
             and native["MemorySwapMax"] == "0", "different live protected assembler")
        assembly_ram = book["memory"]
    else:
        need(assembly["phase"] == "closed" and core.bound(assembly["terminal"])["booking"] == book_ref,
             "unreconciled assembler")
        core.inactive(name)
        assembly_ram = 0
    phase168 = publication["owner"]["phase"]
    need(publication["charged"] == (phase168 != "closed")
         and (publication["charged"] or publication["owner"]["closure"]), "unreconciled publisher")
    publisher_ram = publication["memory_max"] if publication["charged"] else 0
    need(previous["ram_bytes"] == sharing["retained_producer_ram"]-named-assembly_ram-publisher_ram
         and previous["ram_bytes"] >= RETURN and set(previous) == {"ram_bytes","home_bytes","cpu_micros_per_second"},
         "unassigned balance already claimed")
    sharing["unassigned"] = dict(previous, ram_bytes=previous["ram_bytes"]-RETURN)
    sharing["ram_return_to_fleet"] = RETURN
    sharing["remaining_producer_ram"] = sharing["retained_producer_ram"]-RETURN
    whole[FIELD] = dict(grant, native_drain=sharing["native_drain"], assembly_dispatch=dr,
                        assembly_ram=assembly_ram, publication_ram=publisher_ram, named_subleases_ram=named,
                        existing_guard_ram=G, previously_unassigned_ram=previous["ram_bytes"],
                        remaining_donor_unassigned_ram=sharing["unassigned"]["ram_bytes"],
                        returned_cpu_micros=0, returned_home_bytes=0, newly_freed_physical_ram=0)
    return whole
