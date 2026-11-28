"""Price the 40 GiB noswap workspace inside a 56 GiB producer and cap ordinary HOME growth at 8 GiB."""
import os
from pathlib import Path
import stat

G = 1 << 30
RT = Path("/var/lib/jetstreamer/horizon_runtime_data")
OLD = RT / "epoch170-from-73760367-20261128-v1"
ROOT = RT / "epoch170-from-73760367-ram-20261128-v1"
UNIT = "horizon-qualify-170-from-73760367-ram-20261128-v1.service"
OLD_UNIT = "horizon-qualify-170-from-73760367-20261128-v1.service"
OLD_IID = "d8ea1fcfbd6646839b9593752f4afdef"
RAM = 56 * G
TMPFS = 40 * G
HOME_GROWTH = 8 * G


def stopped_gap(core, fleet, prior):
    scope, sr = core.read(OLD/"GAP170_WRITER_INTERFACE.json","3f375caf9273b81cb84c5908695c27c0e4dbc6406f5ab53ebc1e1611ddf2a69f")
    grant, gr = core.read(OLD/"SUCCESSOR_RELEASE.json","44b41b89424986469020d592e8d1d87d831be596cc7b62f1bdfe500093718d04")
    intent, ir = core.read(OLD/"guard-receipts/stop-intent.json","d273dad0851b24ecfad432cb7c41460ccbd75af980075c0017935f928163f60a")
    stop, er = core.read(OLD/"guard-receipts/stop-completion.json","f172a50e67d53e91798e2ee6c723ad4e699e03ac36ce7c2a7bf67b6bc6a08c69")
    first, fr = core.read(OLD/"FIRST_PROTECTED_PROGRESS.json","2f31a88b4f179262386db0c291821c8dde6ae3a82ea46e76479815fa84482d9f")
    custody, cr = core.read(ROOT/"PREDECESSOR_FLOOR_STOP.json","2eb844de0deb0717268b07b9cc0bdd746a92880075fbb14ca515638305f2721c")
    sample = intent["sample"]
    actor = core.bound(grant["actor"])
    row = fleet["current_private170_checkpoint_gap"]
    core.need(row["interface"]==sr and row["actor_ref"]==grant["actor"] and row["release"]==gr
        and row["phase"]=="terminal" and row["native_terminal"]["INVOCATION_ID"]==OLD_IID
        and row["native_terminal"]["UNIT"]==OLD_UNIT and not row["archive_publication_authorized"]
        and grant["interface"]==sr and first["release"]==gr and first["actor"]==grant["actor"]
        and actor["unit"]==OLD_UNIT and actor["producer_invocation_id"]==OLD_IID
        and intent["producer_invocation_id"]==stop["producer_invocation_id"]==OLD_IID
        and intent["reason"]==sample["trip_reason"]=="filesystem-floor"
        and sample["available_bytes"]==9638111191040 < 9639135481492==sample["minimum_free_bytes"]
        and sample["plan_sha256"]==stop["plan_sha256"]==grant["guard_plan"]["sha256"]
        and stop["terminal"]["pid"]==0 and not stop["scratch_deleted"] and stop["intent"]==ir["path"],
        "unconfirmed prior private gap floor stop")
    partial = Path(custody["partial"]["path"])
    stored = custody["partial"]["identity"]
    meta = partial.lstat()
    core.need(partial == Path(scope["run"])/"ledger/epoch-170.diagnostic.jet" and partial.resolve(strict=True) == partial
        and stat.S_ISREG(meta.st_mode) and meta.st_uid == 1001 and meta.st_gid == 1003 and meta.st_nlink == 1
        and [meta.st_dev,meta.st_ino,meta.st_size,meta.st_mtime_ns,meta.st_ctime_ns] ==
            [*stored[:3],stored[3]*1_000_000_000+stored[4],stored[5]*1_000_000_000+stored[6]]
        and custody["partial"]["sha256"] == "2debfbd96615d63ebb04ca7b806ff46d4d359d2f7e1428cf65121b7ecbe3fdee"
        and not os.path.lexists(partial.with_suffix(".jet.segment.json"))
        and custody["release"] == gr and custody["stop_intent"] == ir and custody["stop_completion"] == er
        and not custody["closed_segment"] and custody["last_logged_progress"]["slot"] == 73761053
        and custody["bootstrap_checkpoint"]["slot"] == 73760367, "stopped partial custody changed")
    core.need(prior["owner"](core,fleet) is None, "original gap is still executing")
    return dict(scope=sr,release=gr,intent=ir,completion=er,first=fr,actor=grant["actor"],iid=OLD_IID,custody=cr)


def before_issue(core, fleet):
    """The prestart roster funds future 170 even when 169 is already held or released."""
    core.inactive(UNIT)
    core.inactive(UNIT.replace("-qualify-", "-guard-"))
    timer = core.state(UNIT.replace("-qualify-", "-guard-").replace(".service", ".timer"), "Id,ActiveState,Job")
    core.need(timer["ActiveState"] == "inactive" and not timer["Job"], "occupied proposed 170 guard")
    for name in ("SUCCESSOR_ACTOR.json", "SUCCESSOR_START_INTENT.json", "SUCCESSOR_RELEASE.json", "barrier/allow"):
        core.need(not os.path.lexists(ROOT/name), "170 already issued: " + name)
    core.need(not any(row["epoch"] == 170 for row in fleet["actual_active_private_diagnostics"]),
              "different private 170 owner on prestart roster")
    return None


def charge(core, native, stopped):
    raw=native["raw"]
    legacy=raw["reserved_following_170_growth_bytes"]
    core.need(legacy==raw["joint"]["candidate_growth"]==36*G and raw["joint"]["producer_allowance"]==48*G
              and raw["required_home"]==raw["guard_floor"]+legacy and native["independent_gap_funding"]["new_guard_cpu_micros"]==1_000_000,
              "cannot isolate the existing 170 disk and RAM allotments")
    low, high = raw["terminal_tree_bounds"]
    core.need(0 < low <= high and high + HOME_GROWTH <= 384*G, "retained 170 tree cannot fit its new HOME budget")
    shift=legacy-HOME_GROWTH
    extra=RAM-raw["joint"]["producer_allowance"]
    native["required_home"]-=shift
    native["historical_home_margin"]+=shift
    native["home_margin"]=min(native["historical_home_margin"], native["available_home"]-native["required_home"])
    native["required_ram"]+=extra
    native["ram_margin"]=native["available_ram"]-native["required_ram"]
    native["ram_retry_cost"]=dict(original_home_growth=legacy,home_growth=HOME_GROWTH,scratch_tmpfs=TMPFS,
                                  producer_memory_max=RAM,extra_ram=extra,previous_stop=stopped,
                                  original_guard_still_budgeted=True,resident_ram_credit=0)


def reserve_169(core, native):
    """Keep the second 169 interval's additional tree and RAM charged through 170 admission."""
    control = RT / "epoch169-hourly-retry-20261128-v1"
    prepared, ref = core.read(control/"PREPARE_QUOTE_1795834677791799396.json",
        "7bb806756c04a08ce1a476d01528b736c9b01ba6a3629b5f015a72634f8f6ef6")
    home = prepared["new_home_output"] + prepared["new_home_control"]
    ram = prepared["incremental_ram_bytes"]
    scope = native["stopped_169_compute_handoff"]
    core.need(home == (4*G + (64 << 20)) and ram == 8*G
              and prepared["producer_memory_max"] == 56*G and prepared["guard_memory_max"] == G
              and prepared["returned_159_loan"]["scope"] == native["independent_gap_funding"]["cpu_donor"]
              and scope["retained_159_ram"] == 48*G and scope["retained_guard_ram"] == G
              and prepared["producer_cpu_micros"] == 2_000_000 and prepared["guard_cpu_micros"] == 1_000_000
              and prepared["stage"] == "prepare-only" and not prepared["admission"],"changed 169 reservation")
    native["required_home"] += home
    native["historical_home_margin"] -= home
    native["home_margin"] -= home
    native["required_ram"] += ram
    native["ram_margin"] -= ram
    native["planned_169_retry"] = dict(prepare=ref, additional_home=home, additional_ram=ram,
                                        original_169_guard_retained=True, original_170_guard_cpu_retained=True)
