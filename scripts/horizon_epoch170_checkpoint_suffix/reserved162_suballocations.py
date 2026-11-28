"""Attribute the paid closed-167 resources and retain epoch 170's native replay evidence."""
import json
from pathlib import Path

RT = Path("/var/lib/jetstreamer/horizon_runtime_data")
GROUPS = Path("/sys/fs/cgroup/system.slice")
SOURCE = dict(path=str(RT/"epoch167-assembly-20261127-v1/qualifier-run-1795847372426869765/DISPATCH_RESULT.json"),
              sha256="05f86476ac682d00e31a1267f38b5434b47d89cc814979b858d2d0ac46dab3bf")
BUILD = dict(path=str(RT/"epoch168-private-playback-reconciliation-20261128-v1/HANDOFF.json"),
             sha256="8d88fb6c8241719db479e5fe703b562b420ae0fd4a591d3f4492428afe085051")
CHECKSUM = dict(path=str(RT/"closed-retry-indexes-166-167-170-20261128-v1/COMPARE_DISPATCH.json"),
                sha256="576fb87ae2b7610cd51e29d8143bb40f0df030e60a94a94dabe148bfa3420d80")
PROGRESS = dict(path=str(RT/"epoch170-from-73760367-ram-20261128-v3/FIRST_PROTECTED_PROGRESS.json"),
                sha256="142dd34052a7377936fdeb140d79c14de9889d0be23f67fc1ca89c1c51b5adcb")
TERMINAL_IDS = {"7ad2d189f7e94e70a38c781354912448", "be02cf6855d2428ba40df7e9d022f03d"}


def closed(core, unit, iid, boot):
    group = GROUPS/unit
    status = core["inactive"](unit)
    need = core["need"]
    need(not status["ControlGroup"] and not group.exists(), "closed work still has a cgroup: " + unit)
    lines = core["cmd"]("/usr/bin/journalctl", "-q", "--no-pager", "-o", "json", "_PID=1", "_UID=0",
                        "_BOOT_ID="+boot, "UNIT="+unit, "INVOCATION_ID="+iid,
                        *("MESSAGE_ID="+value for value in sorted(TERMINAL_IDS))).splitlines()
    need(len(lines) == 1, "no unique native terminal for " + unit)
    event = json.loads(lines[0])
    return dict(phase="terminal", unit=unit, invocation=iid, boot=boot,
                manager_message=event["MESSAGE_ID"], timestamp_usec=event["__REALTIME_TIMESTAMP"], cursor=event["__CURSOR"])


def dispatched(core, ref, iid, share, quota, boot):
    receipt = core["bound"](ref)
    at_launch = receipt["unit"]
    name = at_launch["Id"]
    fields = "Id,InvocationID,ActiveState,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,ControlGroup,NRestarts,MainPID"
    need = core["need"]
    need(at_launch["InvocationID"] == iid and at_launch["ActiveState"] == "active"
         and at_launch["MemoryMax"] == str(share["ram_bytes"]) and at_launch["CPUQuotaPerSecUSec"] == quota
         and at_launch["MemorySwapMax"] == at_launch["NRestarts"] == "0" and int(at_launch["MainPID"]) > 1
         and at_launch["ControlGroup"] == "/system.slice/"+name, "dispatch outside retained allocation")
    live = core["state"](name, fields)
    if live["ActiveState"] in ("inactive", "failed"):
        return dict(closed(core, name, iid, boot), dispatch=ref)
    need(all(live[key] == at_launch[key] for key in fields.split(",")), "new source or checksum invocation")
    group = GROUPS/name
    memory = int((group/"memory.max").read_text())
    swap = int((group/"memory.swap.max").read_text())
    use, period = map(int, (group/"cpu.max").read_text().split())
    need(memory == share["ram_bytes"] and swap == 0 and use*1_000_000 == share["cpu_micros_per_second"]*period
         and at_launch["MainPID"] in (group/"cgroup.procs").read_text().split(), "kernel limit or process changed")
    return dict(phase="active", unit=name, invocation=iid, pid=at_launch["MainPID"], dispatch=ref,
                memory_max=memory, swap_max=swap, cpu_quota=[use,period])


def reserve(core, final, native):
    need, bind = core["need"], core["bound"]
    shares = final["closed_167_suballocations"]
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip().replace("-", "")
    need("checksum_read" not in shares and shares["additional_home"] == shares["additional_ram"] == 0
         and not shares["replay_execution_authorized"] and not shares["archive_publication_authorized"], "167 envelope changed")
    source = bind(SOURCE)
    intent = bind(source["intent"])
    admission = bind(intent["fit"])
    need(source["boot_id"].replace("-", "") == boot and admission["fits"] and intent["quote"] == admission["whole_roster"]
         and admission["suballocation"] == shares["source_qualification"] and not admission["publication_authorized"]
         and not admission["resource_credit_bytes"], "different source qualifier admission")
    source_phase = dispatched(core, SOURCE, "ab8147b379d144a696b1d210127ea866", shares["source_qualification"], "1s", boot)
    build = bind(BUILD)
    need(build["build_invocation"] == "9ea5ace532d34416afe0a678ef51a437" and build["tests_passed"] == 5
         and not build["publication_authorized"], "different completed classifier")
    build_phase = closed(core, "horizon-168-private-terminal-qualify-20261128-v2.service", build["build_invocation"], boot)
    need(build_phase["manager_message"] == "7ad2d189f7e94e70a38c781354912448" and build_phase["timestamp_usec"] == "1795847406206090",
         "different classifier terminal")
    scan = bind(bind(CHECKSUM)["intent"])
    need(not scan["mutations"] and scan["ram_bytes"] == 128<<20 and scan["cpu_quota_us"] == 250_000
         and scan["home_bytes"] == 2<<20, "different cold index comparison")
    allocation = dict(ram_bytes=scan["ram_bytes"], cpu_micros_per_second=scan["cpu_quota_us"], home_evidence_bytes=scan["home_bytes"])
    scan_phase = dispatched(core, CHECKSUM, "e88bd2815ad54ea4aef39c4f59adfcbb", allocation, "250ms", boot)
    available = shares["unassigned"]
    unassigned = dict(ram_bytes=available["ram_bytes"]-allocation["ram_bytes"],
                      cpu_micros_per_second=available["cpu_micros_per_second"]-allocation["cpu_micros_per_second"],
                      home_bytes=available["home_bytes"]-allocation["home_evidence_bytes"])
    need(min(unassigned.values()) >= 0, "167 checksum exceeds the unassigned balance")
    shares.update(checksum_read=allocation, unassigned=unassigned,
                  phases=dict(source_qualification=source_phase, epoch168_classifier_build=dict(build_phase, handoff=BUILD),
                              checksum_read=scan_phase))
    progress = bind(PROGRESS)
    need(progress["producer_invocation_id"] == "5f7a0dc3b03346b7b7cfa17a51e150aa" and progress["progress"]["slot"] == 73_760_392
         and progress["release"]["sha256"] == "bbbd90b4e78b50abd57e2dac56bf32c9384981a561d85bcf1b3b7b8c46725459"
         and not progress["resource_credit_bytes"] and not progress["canonical_publication_authorized"], "different 170 first block")
    current = native["ram_gap170"]
    if current:
        need(current["invocation"] == progress["producer_invocation_id"] and current["release"] == progress["release"]
             and current["actor"] == progress["actor"], "different priced 170 actor")
    final["third_170_first_progress"] = PROGRESS
