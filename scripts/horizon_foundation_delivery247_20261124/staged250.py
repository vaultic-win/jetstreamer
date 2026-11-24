"""Bind the epoch 250 staged publisher to its predecessor and the existing cadence."""

from dataclasses import dataclass
import re
from pathlib import Path

from ordinary249.delivery248 import D, V, bound, props
from staged211 import sealed

EPOCH = 250
UNIT = "horizon-upload-250-staged-public-v257.service"
PREDECESSOR = "horizon-upload-250-ordinary-v221.service"
ROOT = D / UNIT.removesuffix(".service")
REGISTRATION = ROOT / "cadence-registration.json"
PACKAGE = V / "horizon250-staged-published-v257"
PLAN = PACKAGE / "epoch-250-plan.json"
PLAN_SHA = "e96999d456f560fcdc1e1c2c29d11bb4fac9adde7d127542112fe77451c49aa0"
STATE = Path("/home/ubuntu/.jetstreamer-private/current-reader-delivery-250-staged-published-v257")
IMAGE = V / "horizon211-staged-recovery-v1/jetstreamer-r2"
IMAGE_SHA = "7271de0e309c83f8fa2f35cf9091280a8b04f66c51d3175ad1d6ff02faa4c59d"
ETAG = "d152967aadd357c1ce79cea4df147e82-2766"
SIZE = 185599540324
MEMORY_CAP = 10 << 30
OLD_STATUS = {
    "path": "/home/ubuntu/.jetstreamer-private/foundation-publication-status-repair.aIkorzZ0/250/completion.json",
    "sha256": "d9647ae8fe9105eb9886f8a6e8360a6fe9dd2758c00bca77ad64575b24b276cf",
}



@dataclass(frozen=True)
class Profile:
    epoch: int
    unit: str
    predecessor: str
    package: Path
    plan: Path
    plan_sha: str
    state: Path
    image: Path
    image_sha: str
    etag: str
    size: int
    memory_cap: int
    old_status: dict[str, str]
    cpus: str

    @property
    def root(self):
        return D / self.unit.removesuffix(".service")

    @property
    def registration(self):
        return self.root / "cadence-registration.json"

    @property
    def key(self):
        return f"epoch-{self.epoch}.epoch-status.json"


PROFILE = Profile(
    epoch=EPOCH, unit=UNIT, predecessor=PREDECESSOR, package=PACKAGE, plan=PLAN, plan_sha=PLAN_SHA,
    state=STATE, image=IMAGE, image_sha=IMAGE_SHA, etag=ETAG, size=SIZE, memory_cap=MEMORY_CAP,
    old_status=OLD_STATUS, cpus="48-55",
)


def expected_argv(spec, profile=PROFILE):
    return [
        str(profile.image), "sync", spec["archive_directory"], "--epochs", f"{profile.epoch}-{profile.epoch}",
        "--receipt-directory", str(profile.state / "receipts"), "--current-reader-plan", str(profile.plan),
        "--current-reader-plan-sha256", profile.plan_sha, "--concurrency", "2",
        "--staged-archive-etag", profile.etag, "--staged-archive-bytes", str(profile.size),
    ]


def load(original, profile=PROFILE):
    if not profile.registration.exists():
        assert not profile.registration.is_symlink()
        return None
    pointer = sealed(profile.registration)
    registration = bound(pointer)
    assert set(registration) == {
        "schema", "epoch", "predecessor", "predecessor_status", "claim", "spec", "initial_status",
    }
    assert registration["schema"] == f"foundation-staged-{profile.epoch}-cadence-registration-v1"
    assert registration["epoch"] == profile.epoch and registration["predecessor"] == original["claim"]
    assert registration["predecessor_status"] == profile.old_status
    prior = bound(original["claim"])
    assert prior["unit"] == profile.predecessor and prior["epoch"] == profile.epoch
    terminal = props(profile.predecessor, ["InvocationID", "ActiveState", "MainPID", "ControlPID",
                                   "ControlGroup", "Job", "NRestarts"])
    assert terminal["InvocationID"] == prior["invocation_id"] and terminal["ActiveState"] == "failed"
    assert terminal["MainPID"] == terminal["ControlPID"] == terminal["NRestarts"] == "0"
    assert not terminal["ControlGroup"] and not terminal["Job"]

    assert registration["claim"] == sealed(profile.root / "pipeline-claim.json")
    assert registration["spec"] == sealed(profile.root / "publication-spec.json")
    claim = bound(registration["claim"])
    iid = claim["invocation_id"]
    assert claim["epoch"] == profile.epoch and claim["unit"] == profile.unit and claim["phase"] == "upload-readback"
    assert re.fullmatch(r"[0-9a-f]{32}", iid) and iid != prior["invocation_id"]
    assert claim["evidence"] == [sealed(profile.root / "booking.json"), sealed(profile.root / "launch.json")]
    booking, launch = map(bound, claim["evidence"])
    assert booking["handoff"] == original["handoff"] and launch["booking"] == claim["evidence"][0]

    proof = bound(sealed(profile.package / "acceptance.json"))
    assert proof["schema"] == f"foundation-staged-{profile.epoch}-publisher-release-v1"
    observer = sealed(profile.package / "jetstreamer-horizon-observe")
    fleet = sealed(profile.package / "jetstreamer-r2")
    plan = sealed(profile.plan)
    assert proof["observer"] == observer and proof["fleet"] == fleet
    assert proof["plan"] == plan and plan["sha256"] == profile.plan_sha
    assert sealed(profile.image)["sha256"] == profile.image_sha
    previous_spec = bound(original["spec"])
    args = expected_argv(previous_spec, profile)
    assert booking["argv"] == args and previous_spec["archive_bytes"] == profile.size
    assert claim["expected_exec_start"].startswith(
        f"{{ path={args[0]} ; argv[]={' '.join(args)} ; ignore_errors=no ; start_time="
    )
    started = launch["unit"]
    assert started["Id"] == profile.unit and started["InvocationID"] == iid
    assert started["ExecStart"] == claim["expected_exec_start"] and started["ActiveState"] == "active"
    pid = int(started["MainPID"])
    assert pid > 1 and int(started["MemoryMax"]) == profile.memory_cap
    assert bound(registration["spec"]) == dict(
        previous_spec, uploader_pid=pid, reader_plan=plan, receipt_directory=str(profile.state / "receipts"),
    )

    assert registration["initial_status"] == sealed(profile.root / "initial-status/completion.json")
    initial = bound(registration["initial_status"])
    intent = bound(initial["intent"])
    status = bound(initial["readback"])
    assert initial["key"] == profile.key and initial["authenticated_exact_byte_readback"]
    assert intent["previous"] == profile.old_status and intent["key"] == initial["key"]
    assert intent["payload"] == status
    assert status["epoch"] == profile.epoch and status["phase"] == "verification" and status["jet_size_bytes"] == profile.size
    assert status["estimated_remaining_millis"] > 0
    assert status["sampled_at_utc"] > bound(bound(profile.old_status)["readback"])["sampled_at_utc"]
    assert intent["owner"] == dict(claim=registration["claim"], unit=profile.unit, invocation_id=iid)
    return dict(registration, registration=pointer, observer=observer, fleet=fleet, configuration={
        "pid": pid, "invocation_id": iid, "claim_sha256": registration["claim"]["sha256"], "retry_unit": profile.unit,
    })


def adopt_status(current, successor, profile=PROFILE):
    if current == profile.old_status:
        return successor["initial_status"]
    if current is not None:
        owner = bound(bound(current)["intent"])["owner"]
        assert owner == dict(
            claim=successor["claim"], unit=profile.unit, invocation_id=successor["configuration"]["invocation_id"],
        )
    return current
