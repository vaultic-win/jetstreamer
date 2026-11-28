"""Price the original paid epoch 145 after its frozen semantic reader succeeds."""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import subprocess

ROOT = Path("/var/lib/jetstreamer/horizon_runtime_data")
PKG = ROOT / "epoch145-semantic-continuity-20261121-v1/tools-v7"
VERSION = Path(__file__).resolve().parent.name
V7_INVOCATION = "f7043fd6595a4151b659d4b098bede11"
V7_START_SHA = "4c83262f7bb705f30f1850dcc1274a549b2f08b80618bc23c3c9955fae4f4163"
V7_SEAL_SHA = "589d1da9f51c305be8699a9dc01e443c9ec2367d1f67e7905ba67fdeb0d35c7b"
V7_POST = VERSION in ("tools-v13r", "tools-homefloor-145-post-v7-build-v1", "tools-homefloor-145-post-v7-current-v1")
V9_POST = VERSION == "tools-v13s"
V9_INVOCATION = "ebdfc34db47c4e7699ea5ccbada5d604"
V9_SUBMISSION_SHA = "33cef3c0ae1bc0aebe1bd8ab950c781c518ce646656f8ffbc66229aaf823c973"
V9_RECOVERY_SHA = "eaf570320604963b6270c1aa2854c48f6cc0c3a5254c829a699d9b6272e6b2c4"
V9_SEAL_SHA = "8766c269034824f114eb1906e1913188f615309b51243e8e23ca111936efeebd"
V10_POST = VERSION == "tools-v13t"
V10_INVOCATION = "104f023c5cd24a55b6585ef525b80067"
V10_SUBMISSION_SHA = "63afb9ef8ffa492e2fe12b05b9eccd6bd2e1c533d024f59ebeb21460e43da8cf"
V10_RECOVERY_SHA = "ed1dd13fb7803f31e90b7040b09359a484f0fef2608bce74a0c65bd2c37fa605"
V10_SEAL_SHA = "29aac4e0527dcea47f4e9bcb14c5e071b67b8d749669873cc04d7cd1cc5d4e75"
V6_HANDOFF = ROOT / "epoch145-semantic-continuity-20261121-v1/v6-guard-walk-name-handoff"
V6_INVOCATION = "a71285e56d674de3bf793692f93dfbb3"
V6_START_SHA = "6eb0a91c59e96a6e0be337c130610f8264e8195c6a2da7a84b456551c2b2b996"
V6_SEAL_SHA = "cdd5008739fb790d52fd7d659efec63a5932bd4e375f40cb3e1679611c6d2f68"
V6_POST = (VERSION in ("tools-homefloor-145-post-v6-build-v1", "tools-homefloor-145-post-v6-current-v1")
           or VERSION == "tools-v13q" and (V6_HANDOFF / "SEMANTIC_COMPLETION.json").is_file())
FOCUSED_SUCCESSOR = VERSION == "tools-v9"
RETRIED_SEMANTIC = VERSION == "tools-v10"
V5Z_POST = V10_POST or V9_POST or V7_POST or V6_POST or VERSION in ("tools-v13q", "tools-homefloor-145-post-v5z-build-v1")
V5X_POST = VERSION == "tools-v13p" or V5Z_POST
V5W_POST = VERSION == "tools-v13o" or V5X_POST
V5U_POST = VERSION in ("tools-v13m", "tools-v13n") or V5W_POST
ENCODED_POST = VERSION == "tools-v13l"
ENCODED_CUSTODY_SHA = "1343de96384e52ff061262a2d80c217d187a1fc8b0ce0e07e32940ee88e89b3b"
AUDIT_POST = VERSION == "tools-v13k"
PRESSURE_POST = VERSION == "tools-v13j"
GUARD_POST = ENCODED_POST or AUDIT_POST or PRESSURE_POST or VERSION in ("tools-v13h", "tools-v13i")
MISSED_POST = GUARD_POST or VERSION == "tools-v13g"
LEASE_POST = MISSED_POST or VERSION == "tools-v13f"
V5J_RETRY = LEASE_POST or VERSION == "tools-v13e"
V5J_SUCCESSOR = V5J_RETRY or VERSION == "tools-v13d"
SAME_IMAGE_RETRY = VERSION == "tools-v13c"
FIXTURE_SUCCESSOR = SAME_IMAGE_RETRY or VERSION in ("tools-v13", "tools-v13b")
TIMER_SUCCESSOR = V5U_POST or V5J_SUCCESSOR or FIXTURE_SUCCESSOR or VERSION in ("tools-v11", "tools-v12")
TIMEOUT_SUCCESSOR = TIMER_SUCCESSOR or VERSION in ("tools-v8", "tools-v9", "tools-v10")
if TIMEOUT_SUCCESSOR:
    PKG = PKG.parent / VERSION
IMAGE = PKG / "export145"
STATE = ROOT / "epoch145-guarded-export-20261121-v1/state"
PUBLICATION = ROOT / "epoch145-publication-20261121-v1"
HOME = Path("/home/sol/.jetstreamer-private")
OUTPUT = HOME / "epoch145-prefix-extract-funded-20261121-v1"
ARCHIVE = OUTPUT / "epoch-145.jet"
SIDECAR = OUTPUT / "epoch-145.jet.sha256"
HOLDING = HOME / "r2-holding-state-dev-samjohnson-v1/transition.lock"
UNIT = "horizon-holding-export145-20261121-v1.service"
CGROUP = "/system.slice/" + UNIT
PIPE = Path("/usr/local/lib/jetstreamer/horizon-r2-audit-readers-20261118-v1/consumer-bench-image-20261120-v1/regular-consumer-true-updates-8822f0ba8391/horizon_pipeline")
VERIFIER = PUBLICATION / "current-reader-tools-v2/verify_archive"
UPLOADER = PUBLICATION / "uploader-tools/jetstreamer-r2"
BOOTSTRAP = "dc043eb78c4a4349b0098760dc764a1f"
ADVANCING = "c8c4a5572906fb348658759ed4c81a7edaf4ee790faab391d700ad9fd4e4c199"
ADVANCING_NAME = "V5B_ACTUAL_ADVANCING_WORKER.json"
if TIMEOUT_SUCCESSOR:
    PIPE = Path("/usr/local/lib/jetstreamer/horizon-r2-audit-readers-20261118-v1/public-rseek-reconnect-56bf2bf0937f/horizon_pipeline")
    BOOTSTRAP = "d37f36f898a44932a19fd50d7014a6fe"
    ADVANCING = "6235fbd8e36064d57a9cd6b7af2ad0d05ce8b41766134cde7be7337ebc133d76"
    ADVANCING_NAME = "V5C_ACTUAL_ADVANCING_WORKER.json"
if RETRIED_SEMANTIC:
    BOOTSTRAP = "e6551a0bb8a14b989902e15c9ecc0751"
    ADVANCING = "3a41dac31746938b482133b9ff224f9d9d821569cc16f63c83f872fe907c13e0"
    ADVANCING_NAME = "V5D_RETRY1_ACTUAL_ADVANCING_WORKER.json"


if TIMER_SUCCESSOR:
    PIPE = Path("/usr/local/lib/jetstreamer/horizon-r2-audit-readers-20261118-v1/fast-range-residency-0f29fd116ef5/horizon_pipeline")
    if FIXTURE_SUCCESSOR:
        SEMANTIC_PREFIX = "V5F_RETRY1" if SAME_IMAGE_RETRY else "V5F"
        ADVANCING_NAME = SEMANTIC_PREFIX + "_ACTUAL_ADVANCING_WORKER.json"
    else:
        ADVANCING_NAME = "V5E_ACTUAL_ADVANCING_WORKER.json"

if VERSION in ("tools-v13q", "tools-v13r", "tools-v13s", "tools-v13t"):
    PIPE = Path("/usr/local/lib/jetstreamer/horizon-r2-audit-readers-20261118-v1/pinned-http500-4bc299e03b21/horizon_pipeline")


def argv(pid):
    return [os.fsdecode(x) for x in Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0") if x]


def procids(path):
    return tuple(sorted(map(int, (path / "cgroup.procs").read_text().split())))


def generation(s, parent, mode, args, fleet, m, profile):
    seal, sr = s.read(PKG / "deployment-seal-receipt.json", profile["seal_sha256"])
    build, br = s.read(PKG / "build-proof.json", profile["build_sha256"])
    members = {x["name"]: x["sha256"] for x in seal["members"]}
    h = profile["image_sha256"]
    s.need(seal["destination"] == str(PKG) and members["export145"] == h
           and build["verifier_sha256"] == h and members["build-proof.json"] == br["sha256"]
           and len(args) == (6 if mode == "publish" else 5) and args[0] == str(IMAGE)
           and args[-1] == h and fleet.name == "ROOT_COMPLETE_OPERATIONAL_FLEET.json"
           and fleet.parent.parent == ROOT and s.iid(m["InvocationID"])
           and m["Id"] == UNIT and m["ControlGroup"] == CGROUP and m["ActiveState"] == "active"
           and m["SubState"] == "running" and not m["Job"] and m["NRestarts"] == "0"
           and m["ControlPID"] == "0" and m["CPUQuotaPerSecUSec"] == "1s"
           and m["MemoryMax"] == str(2 << 30) and m["MemorySwapMax"] == "0"
           and s.process(parent)[2] == "0::" + CGROUP, "unknown 145 publication manager")
    with IMAGE.open("rb") as stream:
        s.need(hashlib.file_digest(stream, "sha256").hexdigest() == h, "changed 145 controller")
    s.read(fleet, args[3])
    lock = HOLDING.stat()
    p = Path("/proc") / str(parent)
    s.need((lock.st_dev, lock.st_ino) == (64512, 95818311) and any(
        os.path.samestat(fd.stat(), lock) and any(" FLOCK " in l and " WRITE " in l
            for l in (p / "fdinfo" / fd.name).read_text().splitlines()) for fd in (p / "fd").iterdir())
        and ("INVOCATION_ID=" + m["InvocationID"]).encode() in (p / "environ").read_bytes().split(b"\0"),
        "different holding owner")
    return sr, br


def fixture_semantic(s, build):
    """Authenticate the V5F worker that restarted the retained V5E candidate."""
    failed = "a99ed8b51e8a482b805b8a36a11b2700"
    old_failure = {"path": str(STATE / failed / "failed.json"),
                   "sha256": "da29d82a4349444ccc15e0be020aa12918ae5bbb4634f9b62e13cc83a93c5f43"}
    old_start = {"path": str(STATE / failed / "recovery-started.json"),
                 "sha256": "6e06652ea695717b18fc29b955e463da8dc2dde16f8173da552df707c478e624"}
    advancing = s.bound(build["prior_phase"], PKG.parent / ADVANCING_NAME)
    new = advancing["invocation_id"]
    manager = s.bound(advancing["manager"], PKG.parent / (SEMANTIC_PREFIX + "_ACTUAL_MANAGER.json"))
    intent = s.bound(manager["intent"], PKG.parent / (SEMANTIC_PREFIX + "_START_INTENT.json"))
    predecessor, failure, recovery = failed, old_failure, old_start
    if SAME_IMAGE_RETRY:
        predecessor = "50af3d8ab5da47e8bdc2828feab53908"
        failure = {"path": str(STATE / predecessor / "failed.json"),
                   "sha256": "38d828362fed1910cc60c605200380576c165168738dbf00520ce2b2522a0fcd"}
        recovery = {"path": str(STATE / predecessor / "recovery-started.json"),
                    "sha256": "3dd15e821b9972e3f7f69f787d585bbe86fd9898ec1df5e8e5d08cab14231bb8"}
        s.need(build["retry_failure"] == failure and build["retry_start"] == recovery
               and intent["previous_advancement"] == {
                   "path": str(PKG.parent / "V5F_ACTUAL_ADVANCING_WORKER.json"),
                   "sha256": "a2a888054492a2be68c5e332ae36daa070b9688c143005cbc97e5cace7cfd496"},
               "different V5F same-image retry predecessor")
    s.need(s.iid(new) and new not in (failed, predecessor) and manager["new"]["Id"] == UNIT
           and manager["new"]["InvocationID"] == new and intent["old"] == predecessor
           and intent["schema"] == "horizon-145-retry-after-fixture-census-intent-v1"
           and build["semantic_manager"] == advancing["manager"] and build["semantic_intent"] == manager["intent"]
           and build["old_failure"] == old_failure and intent["failure"] == failure
           and build["old_start"] == old_start and intent["recovery"] == recovery
           and build["semantic_start"] == advancing["start"], "different V5F recovery")
    start = s.bound(advancing["start"], STATE / new / "recovery-started.json")
    prior = start["prior_frozen_recovery"]["failed_qualification_census"]
    s.need(start["iid"] == new and start["file"] == str(OUTPUT / ".tmp36MvkN")
           and start["r2_mutations"] is False and prior["current_boot_failure"]["failure"] == old_failure
           and prior["prior_started"] == old_start and prior["source_checkpoint_exists"] is False
           and prior["original_candidate"] == build["original_candidate"]
           and prior["original_candidate"]["inode"] == 103237059 and prior["original_candidate"]["bytes"] == 105610995833
           and prior["resource_credit_bytes"] == 0, "different retained V5F semantic source")
    a, b = advancing["observations"]
    s.need(all(a[k] == b[k] for k in ("parent_pid", "parent_ticks", "child_pid", "child_ticks",
                                      "source_inode", "cgroup", "native_leases"))
           and a["parent_pid"] == manager["parent_pid"] and a["parent_ticks"] == manager["parent_start_ticks"]
           and a["cgroup"] == "/sys/fs/cgroup" + CGROUP and len(a["native_leases"]) >= 6
           and b["time_ns"] > a["time_ns"] and b["worker_cpu_ticks"] > a["worker_cpu_ticks"]
           and b["source_offset"] > a["source_offset"], "unproven V5F semantic progress")
    return new, advancing


def v5w_completion(s):
    parent = PKG.parent
    authority = parent / "tools-v5w"
    name = "v5v_semantic_completion.py"
    tool = authority / name
    digest = "42118f1624e540ed5973d37e358ad4a9f0ba68e3c8c2100c9f777e01c0f2a9bf"
    seal, _ = s.read(authority / "deployment-seal-receipt.json",
                     "8768935daed0a99dd01d467da957dabdb218c3741c04f6597cf663dbcf36314e")
    member, = [item for item in seal["members"] if item["name"] == name]
    file = tool.lstat()
    s.need(seal["destination"] == str(authority) and member["sha256"] == digest and member["mode"] == "0444"
           and tool.resolve(strict=True) == tool
           and (file.st_uid, file.st_gid, file.st_nlink, file.st_mode) == (0, 0, 1, stat.S_IFREG | 0o444)
           and hashlib.sha256(tool.read_bytes()).hexdigest() == digest, "different sealed V5w semantic checker")
    handoff = parent / "v5w-name-handoff"
    start = handoff / "START_RESULT.json"
    iid = "97bd2045ebe449e3ae77330c7e4ec7b4"
    selected = json.loads(subprocess.check_output(
        ["/usr/bin/python3", "-IB", tool, start, "5671b19df2e673656d4ddca27c6218b60a7f5b60f4e9bea72f69792a0af5c379"],
        timeout=45))
    captured, _ = s.read(handoff / "SEMANTIC_COMPLETION.json")
    s.need(selected == captured
           and selected["schema"] == "horizon-epoch145-v5v-custody-successor-semantic-completion-v1"
           and selected["invocation_id"] == iid and selected["publication_authorized"] is False
           and selected["r2_mutations"] is False, "foreign V5w semantic completion")
    state = STATE / iid
    done = s.bound(selected["completion"], state / "complete.json")
    extraction = s.bound(selected["extraction"], state / "extraction-complete.json")
    s.need(done["receipt"] == selected["extraction"], "different V5w completion receipt")
    return selected["completion"], extraction["extraction"]


def v5x_completion(s):
    generation = "v6-guard-walk" if V6_POST else "v5z" if V5Z_POST else "v5x"
    authority = ROOT / "epoch145-semantic-continuity-20261121-v1" / ("tools-" + generation)
    handoff = authority.parent / (generation + "-name-handoff")
    if V7_POST:
        authority = authority.parent / "tools-v7-168-stop-v2"
        handoff = authority.parent / "v7-168-stop-name-handoff"
    schema = ("horizon-epoch145-v5z-custody-successor-semantic-completion-v1" if V5Z_POST
              else "horizon-epoch145-v5x-donor-successor-semantic-completion-v1")
    if V10_POST:
        authority = authority.parent / "tools-v10-census-recovery"
        handoff = authority.parent / "v10-census-name-handoff"
        schema = "horizon-epoch145-v9-census-successor-semantic-completion-v1"
        census_owner = V10_INVOCATION, V10_SEAL_SHA, V10_SUBMISSION_SHA, V10_RECOVERY_SHA
    elif V9_POST:
        authority = authority.parent / "tools-v9-census-recovery"
        handoff = authority.parent / "v9-census-name-handoff"
        schema = "horizon-epoch145-v8-census-successor-semantic-completion-v1"
        census_owner = V9_INVOCATION, V9_SEAL_SHA, V9_SUBMISSION_SHA, V9_RECOVERY_SHA
    tool = authority / "v5v_semantic_completion.py"
    seal, seal_ref = s.read(authority / "deployment-seal-receipt.json")
    build, build_ref = s.read(authority / "build-proof.json")
    _, start_ref = s.read(handoff / "START_RESULT.json")
    captured, _ = s.read(handoff / "SEMANTIC_COMPLETION.json")
    if V10_POST or V9_POST:
        owner, seal_sha, submit_sha, recovery_sha = census_owner
        generation = "V10" if V10_POST else "V9"
        s.need(seal_ref["sha256"] == seal_sha and start_ref["sha256"] == submit_sha,
               f"different authenticated {generation} semantic owner")
    elif V7_POST:
        s.need(seal_ref["sha256"] == V7_SEAL_SHA and start_ref["sha256"] == V7_START_SHA,
               "different authenticated V7 semantic owner")
    elif V6_POST:
        s.need(seal_ref["sha256"] == V6_SEAL_SHA and start_ref["sha256"] == V6_START_SHA,
               "different authenticated V6 semantic owner")
    members = {row["name"]: row for row in seal["members"]}
    member = members[tool.name]
    info = tool.lstat()
    expected = {"path": str(tool), "sha256": member["sha256"]}
    s.need(seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
           and seal["destination"] == str(authority)
           and members["build-proof.json"]["sha256"] == build_ref["sha256"]
           and members["export145"]["sha256"] == build["verifier_sha256"]
           and build["semantic_checker"] == expected and member["mode"] == "0444"
           and tool.resolve(strict=True) == tool and 0 < info.st_size <= 128 << 10
           and (info.st_uid, info.st_gid, info.st_nlink, info.st_mode) == (0, 0, 1, stat.S_IFREG | 0o444)
           and hashlib.sha256(tool.read_bytes()).hexdigest() == expected["sha256"],
           "different sealed V5x semantic checker")
    selected = json.loads(subprocess.check_output(
        ["/usr/bin/python3", "-IB", tool, start_ref["path"], start_ref["sha256"]], timeout=45))
    actor = selected["invocation_id"]
    startup = selected["startup_evidence"]
    if V10_POST or V9_POST:
        recovery = {"path": str(STATE / owner / "recovery-started.json"), "sha256": recovery_sha}
        s.need(actor == owner and selected["start"] == startup["start"] == recovery,
               f"different authenticated {generation} recovery start")
    s.need(selected == captured and s.iid(actor) and actor != "97bd2045ebe449e3ae77330c7e4ec7b4"
           and (not V7_POST or (actor == V7_INVOCATION and selected["start"] == start_ref))
           and (not V6_POST or actor == V6_INVOCATION)
           and selected["schema"] == schema
           and startup["invocation_id"] == actor and startup["submission_result"] == start_ref
           and startup["worker_build"] == build_ref and startup["worker_seal"] == seal_ref
           and startup["predecessor_terminal"] == build["guard_terminal"]
           and selected["r2_mutations"] is selected["publication_authorized"] is False,
           "foreign V5x semantic completion")
    done = s.bound(selected["completion"], STATE / actor / "complete.json")
    extraction = s.bound(selected["extraction"], STATE / actor / "extraction-complete.json")
    s.need(done["receipt"] == selected["extraction"], "different V5x completion receipt")
    return selected["completion"], extraction["extraction"]


def completion(s, build=None):
    if V5X_POST:
        return v5x_completion(s)
    if V5W_POST:
        return v5w_completion(s)
    if V5U_POST:
        seal, _ = s.read(PKG / "deployment-seal-receipt.json")
        helper = PKG / "v5u-post-evidence.py"
        member, = [row for row in seal["members"] if row["name"] == helper.name and row["mode"] == "0444"]
        st = helper.lstat()
        s.need(seal["destination"] == str(PKG) and helper.resolve(strict=True) == helper
               and stat.S_ISREG(st.st_mode) and st.st_uid == st.st_gid == 0
               and stat.S_IMODE(st.st_mode) == 0o444 and st.st_nlink == 1
               and 0 < st.st_size <= 128 << 10
               and hashlib.sha256(helper.read_bytes()).hexdigest() == member["sha256"]
               and build["semantic_checker"] == dict(path=str(helper), sha256=member["sha256"]),
               "different V5u completion checker deployment")
        selected = json.loads(subprocess.check_output(["/usr/bin/python3", "-IB", helper], timeout=45))
        iid = "8452dba9df42437b9874b35cb44d059f"
        state = STATE / iid
        s.need(selected["schema"] == "horizon-epoch145-v5u-semantic-completion-v1"
               and selected["invocation_id"] == iid and selected["archive_publication_authorized"] is False,
               "foreign V5u semantic completion")
        done = s.bound(selected["completion"], state / "complete.json")
        extracted = s.bound(selected["extraction"], state / "extraction-complete.json")
        s.need(done["receipt"] == selected["extraction"], "different V5u extraction")
        return selected["completion"], extracted["extraction"]

    if ENCODED_POST or AUDIT_POST or PRESSURE_POST:
        if ENCODED_POST:
            version, build_key = "v5r", "encoded_prefix_custody"
            runtime_hash = ENCODED_CUSTODY_SHA
            runtime = s.bound(build[build_key], PKG.parent / "v5r-name-handoff/ACTUAL_ADVANCING_AND_136_CUSTODY.json")
            iid = runtime["manager"]["InvocationID"]
            s.need(runtime["schema"] == "horizon-145-encoded-prefix-live-custody-v1"
                   and s.iid(iid) and build["semantic_submission"] == runtime["submission"],
                   "different encoded-prefix post build")
        else:
            version, iid, build_key, runtime_hash = (
                ("v5q", "cbacb5a17e6347509640846eccb95cb0", "audit_turnover_binding",
                 "a5dc1d9973d950d36f7302b800f0b10421066e135e0912750fd92b98521cadc4") if AUDIT_POST else
                ("v5o", "f3474dfad55f4a05a64431421881db29", "donor_pressure_binding",
                 "d571da98684079bc937a2ddeed52dbcd457eb0a74010519171b851e3e5297137"))
        seal, _ = s.read(PKG / "deployment-seal-receipt.json")
        checker = PKG / "post-inputs"
        member, = (m for m in seal["members"] if m["name"] == checker.name and m["mode"] == "0555")
        label = "encoded-prefix" if ENCODED_POST else "V13j"
        s.need(seal["destination"] == str(PKG) and
               seal["sealer_sha256"] == "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3",
               f"foreign {label} deployment")
        data = checker.read_bytes()
        s.need(hashlib.sha256(data).hexdigest() == member["sha256"], f"unbound {label} inputs")
        selected, _ = s.read(PKG.parent / f"{version}-name-handoff/semantic-completion.json")
        report = json.loads(subprocess.check_output([checker, "inspect-semantic"], timeout=20))
        state = STATE / iid
        s.need(report == selected and selected["invocation_id"] == iid
               and build[build_key]["sha256"] == runtime_hash, f"different captured {version.capitalize()} completion")
        completed = s.bound(selected["completion"], state / "complete.json")
        extracted = s.bound(selected["extraction"], state / "extraction-complete.json")
        s.need(completed["receipt"] == selected["extraction"],
               "different encoded-prefix extraction" if ENCODED_POST else "different V5o extraction")
        return selected["completion"], extracted["extraction"]
    if V5J_SUCCESSOR:
        handoff = PKG.parent / ("v5n-name-handoff" if GUARD_POST else "v5m-name-handoff" if MISSED_POST else "v5k-name-handoff" if LEASE_POST else "v5j-name-handoff-retry1" if V5J_RETRY else "v5j-name-handoff")
        selected, _ = s.read(handoff / "semantic-completion.json")
        result, _ = s.read(handoff / "submission-result.json")
        intent, _ = s.read(handoff / "submission-intent.json")
        if LEASE_POST:
            if GUARD_POST:
                binding = s.bound(build["guard_walk_binding"], PKG.parent/"V5N_RUNTIME_BINDINGS.json")
            old, review, dispatcher = (("dba04d40f1b046b4875d7e27e0ff224a",binding["review"]["sha256"],binding["dispatcher"]["sha256"]) if GUARD_POST else ("ff597d64ad37400ea5c6836336fb6706",
                                       "28540e178ace196165ea892f924001a72b59396708b8269fb3a057a2627b132f",
                                       "2c582f4c5a0d400cadd35e37710aa126b8b2ae8c09bab7bdfcc08f1ecfc5aaea")
                                      if MISSED_POST else
                                      ("f2afc696a63a4e6aa6812451cf3559e5",
                                       "1a7f7bce208d97831963c66c462bbac28b7f9b84e990d09fa5da7e5efa56d150",
                                       "f69f462cecb76fc586799d36f358e61b1880f99d0c024b0c76dd27d3a2f9637e"))
            s.need(intent["original"]["INVOCATION_ID"] == old and intent["review_sha256"] == review
                   and intent["preflight"]["quote_provider"] == build["semantic_dispatch"]
                   and build["semantic_dispatch"]["sha256"] == dispatcher
                   and result["invocation_id"] != old, "foreign lease-ready handoff")
        elif V5J_RETRY:
            s.need(intent["original"]["INVOCATION_ID"] == "48ad7b2234d74e74b0498e7110e0aee3"
                   and intent["review_sha256"] == "38774819c4dbbe1246851585afb57ba65df4919cbf457fb6a04b75ef2e77fc07"
                   and intent["preflight"]["quote_provider"] == build["semantic_dispatch"]
                   and build["semantic_dispatch"]["sha256"] == "1b98fea46cef7beefe2c3f250da7fe524e0e07f78b6ffb61a575a552b2a1b1ee"
                   and result["invocation_id"] != intent["original"]["INVOCATION_ID"], "foreign retry handoff")
        bootstrap = selected["invocation_id"]
        s.need(selected["schema"] == "horizon-145-v5j-semantic-completion-v1" and s.iid(bootstrap)
               and bootstrap == result["invocation_id"] and bootstrap != "afcf6cdd1ec0400ea2757f81472987b3"
               and intent["argv"] == result["argv"] and result["argv"][-1] == build["semantic_image"]["sha256"]
               and result["argv"][-5:-3] == [str(PKG.parent / ("tools-v5n/export145" if GUARD_POST else "tools-v5m/export145" if MISSED_POST else "tools-v5k/export145" if LEASE_POST else "tools-v5j/export145")), "recover-full-output"]
               and selected["start"]["path"] == str(STATE / bootstrap / "recovery-started.json")
               and selected["completion"]["path"] == str(STATE / bootstrap / "complete.json"),
               "different bound v5j publication generation")
        s.bound(selected["completion"], STATE / bootstrap / "complete.json")
        advancing = {"invocation_id": bootstrap, "start": selected["start"]}
    elif FIXTURE_SUCCESSOR:
        bootstrap, advancing = fixture_semantic(s, build)
    elif TIMER_SUCCESSOR:
        # The price observer authenticates the build receipt against the sealed
        # deployment before passing its ID-bound original worker reference.
        advancing = s.bound(build["prior_phase"], PKG.parent / ADVANCING_NAME)
        bootstrap = advancing["invocation_id"]
        manager = s.bound(advancing["manager"], PKG.parent / "V5E_ACTUAL_MANAGER.json")
        intent = s.bound(manager["intent"], PKG.parent / "V5E_START_INTENT.json")
        s.need(s.iid(bootstrap) and manager["new"]["InvocationID"] == bootstrap and
               intent["schema"] == "horizon-145-retry-after-timer-inspection-intent-v1" and
               intent["old"] == "e6551a0bb8a14b989902e15c9ecc0751" and
               intent["failure"] == build["old_failure"] and intent["recovery"] == build["old_start"] and
               intent["failure"]["sha256"] == "9ef9c938290ea2b43d3b2ce4aa617f08b33f4c893961e63f53ba3f48768e215f",
               "different original timer recovery")
    else:
        bootstrap = BOOTSTRAP
        advancing, _ = s.read(PKG.parent / ADVANCING_NAME, ADVANCING)
    if FOCUSED_SUCCESSOR and (PKG.parent / "V5D_START_INTENT.json").exists():
        intent, original = s.read(PKG.parent / "V5D_START_INTENT.json")
        advancing, _ = s.read(PKG.parent / "V5D_ACTUAL_ADVANCING_WORKER.json")
        bootstrap = advancing["invocation_id"]
        s.need(s.iid(bootstrap) and bootstrap != BOOTSTRAP and intent["old"] == BOOTSTRAP and
               intent["schema"] == "horizon-145-focused-census-recovery-intent-v1" and
               not (STATE / BOOTSTRAP / "complete.json").exists(), "ambiguous semantic predecessor")
        manager = s.bound(advancing["manager"], PKG.parent / "V5D_ACTUAL_MANAGER.json")
        s.need(manager["intent"] == original and manager["new"]["InvocationID"] == bootstrap,
               "different paid semantic recovery")
    old = STATE / bootstrap
    start, start_ref = s.read(old / "recovery-started.json", advancing["start"]["sha256"])
    if MISSED_POST:
        native = start["fresh_fit"]
        window = native["phase145"]["window"]
        if GUARD_POST:
            s.need(binding["reader"] == build["semantic_image"] and binding["worker"] == window["continuity_seal"]
                   and window["guard_walk_failure"]["sha256"] == "8a8ef5d04d44a1bb97771cef2a7e15958d721e0defc35f1e2aee0b3f55b85010"
                   and window["registered_guard_clock"]["sha256"] == "119fdd9c0246b71fa188007daad510adc377bc002a110dda3e1074bb06d0819d"
                   and window["rejected_guard"]["sha256"] == "6800d34a8bb71f468d2f06daf6a29cf9016d972f4cc1ef60d915600e8085ad1f", "unbound guard walk recovery")
        s.need(start["image"] == build["semantic_image"]["sha256"] == (binding["reader"]["sha256"] if GUARD_POST else "9068d5ac9ccd4d35481cbf2882faf67a97b0926133663a2e4885917e714bdc21")
               and native["phase145"]["invocation_id"] == bootstrap and native["phase145"]["stage"] == "controller"
               and native["fits"] and native["fleet"] == intent["fleet"]
               and window["continuity_seal"]["sha256"] == (binding["worker"]["sha256"] if GUARD_POST else "db422be5b246aa3aef2457fd9325f6b8cca739e3e4c63d2e4794ae30c527f6c4")
               and window["missed_clock_failure"]["sha256"] == "04eeb879aa90c3f3170e738c781f10eaf17ef44b2d8835d6f9f8f7ee29ee5fb6"
               and native["epoch159_donor_cover"]["fleet"] == intent["fleet"]
               and native["epoch159_donor_cover"]["credited_retirement_bytes"] == 0, "unbound missed-clock recovery")
    verified, vr = s.read(old / "verified-frozen.json")
    done, dr = s.read(old / "complete.json")
    extracted, er = s.read(old / "extraction-complete.json")
    e = extracted["extraction"]
    s.need(advancing["invocation_id"] == start["iid"] == verified["iid"] == done["iid"]
           == extracted["actor_iid"] == bootstrap and done["receipt"] == er
           and done["recovered_from"] == extracted["original_export"] == "de6780b860b3467bae21fbd19176ca14"
           and extracted["verified_frozen"] == vr and extracted["recovery_evidence"] == start_ref
           and verified["r2_mutations"] is False and start["r2_mutations"] is False
           and done["r2_mutations"] is False and extracted["archive_publication_authorized"] is False
           and e["epoch"] == 145 and e["archive"] == str(ARCHIVE) and e["archive_bytes"] == 105610995833
           and e["output_slot_count"] == 432000 and e["independent_output_reread_passed"] is True
           and not (old / "failed.json").exists() and not (OUTPUT / ".tmp36MvkN").exists(),
           "unverified original paid archive promotion")
    return dr, e


def ordinary_full(s, parent, children, gen, extraction):
    if not children:
        return []
    s.need(len(children) == 1, "extra full verifier")
    child = children[0]
    args = argv(child)
    report = PUBLICATION / ("full-" + gen)
    permitted = [
        ["/usr/bin/sha256sum", "--", str(ARCHIVE)],
        [str(VERIFIER), str(ARCHIVE), "--full", "--threads", "1", "--anchor", "62639999",
         "Fnoa95TKZ1U419CubZrxYDtFnqadRmvM554FFi2xSizB", "--expected-terminal", "63071999",
         "4zqmYpqcustpx2BQ2gB6y7v1HsvZpPGeyaRKFEsbThum", "--expected-provenance-sha256",
         extraction["expected_output_provenance_sha256"]],
        [str(PIPE), "145", str(OUTPUT), "--verify-only", "--threads", "1",
         "--verification-report", str(report / "plugin-report.json")],
    ]
    pp, ticks, cg = s.process(child)
    s.need(args in permitted and s.same_file(Path(f"/proc/{child}/exe"), Path(args[0]))
           and (pp, cg) == (parent, "0::" + CGROUP), "foreign full verification child")
    return [[child, ticks, args[0]]]


def network_members(s, parent, leaf, gen, full_iid):
    if not leaf.exists():
        return []
    s.need(not any(x.is_dir() for x in leaf.iterdir()), "nested delegated publication group")
    group = "0::" + CGROUP + "/publication"
    who = procids(leaf)
    actors = {p: s.process(p) for p in who}
    roots = [p for p, (pp, _, _) in actors.items() if pp == parent]
    s.need(all(cg == group and (pp == parent or pp in actors) for pp, _, cg in actors.values())
           and len(roots) == int(bool(who)), "unowned publication subtree")
    if not who:
        return []
    root = roots[0]
    args = argv(root)
    exe = Path(f"/proc/{root}/exe")
    repo = "/home/sol/workspace/jetstreamer"
    name = "refs/heads/account-updates"
    target = name + ":refs/remotes/origin/account-updates"
    local = PUBLICATION / ("full-" + full_iid)
    receipts = PUBLICATION / ("network-" + gen) / "receipts"
    plan = local / "delivery-plan.json"
    _, pr = s.read(plan)
    allowed = [[str(UPLOADER), "inventory", str(OUTPUT), "--epochs", "145-145"],
               [str(UPLOADER), "sync", str(OUTPUT), "--epochs", "145-145", "--receipt-directory", str(receipts),
                "--current-reader-plan", str(plan), "--current-reader-plan-sha256", pr["sha256"],
                "--concurrency", "1", "--part-size-mib", "64"], ["/usr/bin/ssh-add", "-l"]]
    allowed += [["/usr/bin/git", "-C", repo, *a] for a in (["remote", "get-url", "origin"],
                ["ls-remote", "--exit-code", "origin", name], ["fetch", "origin", target])]
    s.need(args in allowed and s.same_file(exe, Path(args[0])), "foreign publication root")
    # The sealed uploader starts its current-reader validators in this leaf. Git
    # and SSH may also create descendants. Every PID must be rooted at the one
    # exact allowed command and be charged to the same capped service.
    for child in actors:
        seen = set()
        while child != root:
            s.need(child in actors and child not in seen, "unrooted publication payload")
            seen.add(child)
            child = actors[child][0]
    rows = [[p, actors[p][1], str(Path(f"/proc/{p}/exe").readlink())] for p in who]
    s.need(procids(leaf) == who and all(s.process(p) == actors[p] for p in who), "publication child changed")
    return rows


def inspect(s, leased, m, members, epoch, provider, profile):
    parent = int(m["MainPID"])
    if parent < 2 or not IMAGE.exists() or not s.same_file(Path(f"/proc/{parent}/exe"), IMAGE):
        return None
    args = argv(parent)
    s.need(len(args) in (5, 6) and args[1] in ("post-full", "publish"), "unknown paid publication phase")
    mode, gen = args[1], m["InvocationID"]
    sr, br = generation(s, parent, mode, args, Path(args[2]), m, profile)
    ticks = s.process(parent)[1]
    seen = set(members)
    if os.getpid() in seen:
        probe = argv(os.getpid())
        s.need(epoch == 145 and os.getppid() == parent and sys.flags.isolated and __debug__
               and probe[1:4] == ["-IB", str(provider), "145"] and len(probe) == 6
               and s.same_file(Path("/proc/self/exe"), Path("/usr/bin/python3")), "foreign 145 capacity probe")
        seen.remove(os.getpid())
    s.need(parent in seen, "holding controller absent")
    seen.remove(parent)
    done, e = completion(s, s.bound(br, PKG / "build-proof.json") if TIMER_SUCCESSOR else None)
    meta = ARCHIVE.lstat()
    s.need((meta.st_dev, meta.st_ino, meta.st_size, meta.st_nlink, meta.st_uid, meta.st_gid,
            stat.S_IMODE(meta.st_mode)) == (64512, 103237059, 105610995833, 1, 0, 0, 0o400)
           and ARCHIVE.resolve(strict=True) == ARCHIVE and stat.S_ISREG(meta.st_mode), "different canonical archive")
    locks = {(meta.st_dev, meta.st_ino): str(ARCHIVE)}
    cgroup = Path("/sys/fs/cgroup" + CGROUP)
    dirs = {x.name for x in cgroup.iterdir() if x.is_dir()}
    if mode == "post-full":
        s.need(not dirs, "extra verification group")
        workers = ordinary_full(s, parent, sorted(seen), gen, e)
    else:
        s.need(not seen and dirs <= {"publication"} and s.iid(args[4]) and args[4] != gen,
               "extra publication group or member")
        label = (e["archive_sha256"] + "  epoch-145.jet\n").encode()
        sm = SIDECAR.lstat()
        s.need(SIDECAR.resolve(strict=True) == SIDECAR and stat.S_ISREG(sm.st_mode)
               and (sm.st_dev, sm.st_uid, sm.st_gid, sm.st_nlink, stat.S_IMODE(sm.st_mode), sm.st_size)
               == (64512, 0, 0, 1, 0o400, len(label)) and SIDECAR.read_bytes() == label,
               "foreign local checksum")
        locks[(sm.st_dev, sm.st_ino)] = str(SIDECAR)
        workers = network_members(s, parent, cgroup / "publication", gen, args[4])
    window = {"mode": mode, "native_parent": {"pid": parent, "start_ticks": ticks}, "workers": workers,
              "completion": done, "leases_parent": leased(parent, locks), "seal": sr, "build": br}
    s.need(s.process(parent)[1:] == (ticks, "0::" + CGROUP) and procids(cgroup) == tuple(sorted(members))
           and argv(parent) == args, "145 generation crossed observation")
    return {"invocation_id": gen, "stage": mode, "window": window}
