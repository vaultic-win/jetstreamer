"""Authenticate the failed original V5j invocation before retrying the same paid verifier."""
import json
from pathlib import Path

IID = "48ad7b2234d74e74b0498e7110e0aee3"
ORIGINAL = "afcf6cdd1ec0400ea2757f81472987b3"
IMAGE = "52d2dd991c69b24079308fafefd054af9aa4fe1d095d0469ec3d90ef851f1cc4"
ROOT = Path("/var/lib/jetstreamer/horizon_runtime_data")
UNIT = "horizon-holding-export145-20261121-v1.service"
STATE = ROOT / "epoch145-guarded-export-20261121-v1/state" / IID
BASE = ROOT / "epoch145-semantic-continuity-20261121-v1"
OLD_HANDOFF = BASE / "v5j-name-handoff"
ORIGINAL_REVIEW = ROOT / "incident-replay-fit-20261121-v1/tools-homefloor-145-handoff-v1/admission-review.json"
ORIGINAL_REVIEW_SHA = "4b8963f5490bd9dba3d9d6db521b9e9e864a28108c7b79bbe420417eefaf82e6"
SAMPLE = Path("/home/sol/.jetstreamer-private/epoch145-v5j-phase-handoff-20261123/first-live-48ad7b22.json")
MEMBERS = {
    "failure": (STATE/"failed.json", "1d6f85a599d024f03b464be7bc628e4544517dde588a706d60b43ca2ea39ea57"),
    "recovery": (STATE/"recovery-started.json", "16c6ea789c40e3aab07a866d8889f200220b54a52cdaf4402d626522710c0e60"),
    "submission": (OLD_HANDOFF/"submission-result.json", "02324358c448ecfcd2138e67105749364761ed7e09ac7add3c64e0798da0094f"),
    "intent": (OLD_HANDOFF/"submission-intent.json", "7b6030259a9963aa81f88b04ad164a16f0c79352abd1876f2fedf62c21c63fc0"),
    "attempt": (OLD_HANDOFF/"submission-attempt.json", "062af86caab214a90e038d046a3e096a6eb78bdf146608a719b576e114722671"),
    "worker": (SAMPLE, "b7825473b69ca06fe0fa5be1f5b515b51ea010725e0eb2d64edb118a99c3c1e5"),
}
FRAGMENT_SHA = "1a248163d7f788ea114b4abd0bcfa93f136ae59d6282e73c9b9508e48c5f5240"
BIRTH_CURSOR = "s=7f76387dd96140468b39dcf01e726fea;i=392b381;b=763ea84ca81f4dddad364b1ea2ba36dd;m=3702b0e45d7;t=660eff7e1a30f;x=1046b69d8019d1e6"
EXIT_CURSOR = "s=7f76387dd96140468b39dcf01e726fea;i=392b6d3;b=763ea84ca81f4dddad364b1ea2ba36dd;m=3703d69f7bc;t=660f00a3d54f4;x=b6c12c805fadcf5"


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def profile(read, pid1_rows, state=STATE):
    original, _ = read(ORIGINAL_REVIEW, ORIGINAL_REVIEW_SHA)
    refs = {}; values = {}
    for name, (p, digest) in MEMBERS.items():
        values[name], refs[name] = read(p, digest)
    failure, recovery = values["failure"], values["recovery"]
    submission, intent, attempt = (values[n] for n in ("submission", "intent", "attempt"))
    sample = values["worker"]
    w = sample["leased_worker_observation"]
    begin, = [e for e in pid1_rows if e["MESSAGE_ID"] == "39f53479d3a045ac8e11786248231fbf"]
    end, = [e for e in pid1_rows if e["MESSAGE_ID"] == "98e322203f7a4ed290d09fe03c09fe15"]
    boot = original["original_pid1_exit"]["_BOOT_ID"]
    need(all(e["_PID"] == "1" and e["UNIT"] == UNIT and e["INVOCATION_ID"] == IID and e["_BOOT_ID"] == boot
             for e in pid1_rows), "foreign native journal")
    need(end["__CURSOR"] == EXIT_CURSOR and begin["__CURSOR"] == BIRTH_CURSOR and end["COMMAND"] == "ExecStart"
         and end["EXIT_CODE"] == "exited" and end["EXIT_STATUS"] == "1" and
         int(begin["__MONOTONIC_TIMESTAMP"]) < int(end["__MONOTONIC_TIMESTAMP"]) and
         int(begin["__REALTIME_TIMESTAMP"])//1000000 <= failure["at"] <= int(end["__REALTIME_TIMESTAMP"])//1000000,
         "wrong 48ad7b22 native terminal")
    need(failure["iid"] == recovery["iid"] == sample["invocation_id"] == submission["invocation_id"] == IID
         and set(p.name for p in state.iterdir()) == {"failed.json","recovery-started.json"}
         and intent["original"] == original["original_pid1_exit"] and intent["original"]["INVOCATION_ID"] == ORIGINAL
         and submission["argv"] == intent["argv"] == attempt and sample["submission"] == refs["submission"]
         and sample["intent"] == refs["intent"] and refs["recovery"] == sample["recovery"] == w["recovery"]
         and recovery["fresh_fit"]["phase145"]["window"]["native_parent"] == sample["native_parent"] == w["native_parent"]
         and sample["manager_start_cursor"] == w["manager_start_cursor"] == submission["manager_start_cursor"] == BIRTH_CURSOR
         and w["native_parent"] == {"pid":1330508, "start_ticks":378029348}
         and w["native_child"] == {"pid":1330880, "start_ticks":378032154}
         and w["cgroup"] == "0::/system.slice/" + UNIT
         and set(w["leases_parent"]) == set(w["leases_worker"]) == {str(m["ino"]) for m in original["retained_inputs"]}
         and w["invocation_id"] == IID and w["image_sha256"] == recovery["image"] == IMAGE
         and recovery["fresh_fit"]["serial_145_holding_handback"] == intent["preflight"]["serial_handback"]
         and failure["error"].rstrip().endswith("ValueError: unregistered replay process 1333509")
         and recovery["r2_mutations"] is False and w["rchar"] > 0, "wrong paid-verifier lineage")
    argv = attempt[attempt.index("--") + 1:]
    need(begin["MESSAGE"] == "Started " + UNIT + " - " + " ".join(argv) + "."
         and argv == [str(BASE/"tools-v5j/export145"),"recover-full-output",
                      intent["fleet"]["path"],intent["fleet"]["sha256"], IMAGE], "foreign reader command")
    retained = original["retained_inputs"][-1]
    candidate = original["failed_phase"]["candidate"]
    need(recovery["file"] == retained["path"] and
         recovery["prior_frozen_recovery"]["failed_preincident_verifier"]["original_candidate"] == candidate,
         "wrong retained source")
    exit_fields = {k:v for k,v in end.items() if k != "MESSAGE"}
    failed = dict(Id=UNIT, ActiveState="failed",SubState="failed",MainPID="0",InvocationID=IID,
                  failure=refs["failure"], recovery=refs["recovery"],retry_worker=refs["worker"],
                  candidate=candidate,manager_exit=exit_fields,source_checkpoint_exists=False,resource_credit_bytes=0)
    fields = ("stock_launcher","retained_inputs","retained_manifest","seal","provider","holding","sealed_service_argv","reader")
    return dict({k:original[k] for k in fields},schema="horizon-145-v5j-first-retry-review-v1",
                old_manager=dict(original["old_manager"],InvocationID=IID), original_pid1_exit=exit_fields,
                original_fragment=dict(original["original_fragment"],sha256=FRAGMENT_SHA), failed_phase=failed,
                predecessor_receipts=refs, original_review={"path":str(ORIGINAL_REVIEW),"sha256":ORIGINAL_REVIEW_SHA})


def journal(command):
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip().replace("-","")
    fields = "_PID,_BOOT_ID,UNIT,INVOCATION_ID,MESSAGE,MESSAGE_ID,EXIT_CODE,EXIT_STATUS,COMMAND"
    return [json.loads(r) for r in command(["/usr/bin/journalctl","--no-pager","-ojson","--output-fields="+fields,
            "_BOOT_ID="+boot,"_PID=1","UNIT="+UNIT,"INVOCATION_ID="+IID]).splitlines()]
