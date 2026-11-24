//! Exact live delivery owner, measured inside the coordinated observer cadence.
//! Reuses native process-image checks and ordinary unit/cgroup/RSS sampling.
use super::*;
#[path = "../../tools/horizon247_recovery_delivery.rs"]
mod fourth;
use jetstreamer_horizon_observe::staged247_rss as staged;
use jetstreamer_horizon_observe::successor247 as next;
use serde_json::json;
const UNIT: &str = "horizon-upload-247-singleton-20261119-v1.service";
const IID: &str = "69218e2e0924497ea595a1227a6c31db";
const PID: u32 = 1439838;
const IMAGE: &str =
    "/var/lib/jetstreamer/horizon-full265-fast-consumers-20261119-v1/jetstreamer-r2";
const IMAGE_SHA: &str = "4f70b21bd930a6e2890088eb236858ca1952a2dfa4c6404bfb9d9e68d07ba0ba";
#[derive(Clone, Copy)]
struct Owner<'a> {
    unit: &'static str,
    iid: &'a str,
    pid: u32,
    image: &'static str,
    sha: &'static str,
    cap: u64,
}
impl Owner<'_> {
    fn range(&self) -> &'static str {
        match self.unit {
            UNIT211 | STAGED211 | STAGED211_RETRY => "211-211",
            UNIT248 => "248-248",
            UNIT249 => "249-249",
            UNIT250 | STAGED250 => "250-250",
            UNIT251 => "251-251",
            UNIT265 | RETRY265 => "265-265",
            _ => "247-247",
        }
    }
}
const ORIGINAL: Owner<'static> = Owner {
    unit: UNIT,
    iid: IID,
    pid: PID,
    image: IMAGE,
    sha: IMAGE_SHA,
    cap: 7_000_000_000,
};
const STAGED: Owner<'static> = Owner {
    unit: staged::UNIT,
    iid: staged::IID,
    pid: staged::PID,
    image: staged::IMAGE,
    sha: staged::IMAGE_SHA,
    cap: staged::CAP,
};

// systemd can clear the command's display PID and timestamps on daemon-reload.
fn staged_exec_matches(recorded: &str, current: &str) -> bool {
    if recorded == current {
        return true;
    }
    let Some((command, _)) = recorded.split_once(" ; start_time=") else {
        return false;
    };
    const RELOADED: &str =
        " ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }";
    current.strip_suffix(RELOADED) == Some(command)
}

fn staged_inputs() -> Result<Value> {
    let mut proof = json!({});
    let mut docs = json!({});
    for (name, (path, digest)) in [
        ("booking", staged::BOOKING),
        ("launch", staged::LAUNCH),
        ("claim", staged::CLAIM),
        ("plan", staged::PLAN),
    ] {
        let path = Path::new(path);
        let m = fs::symlink_metadata(path)?;
        ensure!(
            path.canonicalize()? == path && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o022 == 0,
            "staged 247 provenance custody"
        );
        let bytes = read_bounded(path, 1 << 20, "staged 247 provenance")?;
        ensure!(
            sha256(&bytes) == digest,
            "staged 247 provenance digest differs"
        );
        docs[name] = serde_json::from_slice(&bytes)?;
        proof[name] = json!({"path":path,"sha256":digest});
    }
    let b = &docs["booking"];
    let l = &docs["launch"];
    let c = &docs["claim"];
    ensure!(
        l["booking"] == proof["booking"]
            && b["approved_plan"] == proof["plan"]
            && b["unit"] == staged::UNIT
            && c["unit"] == staged::UNIT
            && c["invocation_id"] == staged::IID
            && c["expected_exec_start"] == l["unit"]["ExecStart"]
            && l["unit"]["MainPID"]
                .as_str()
                .and_then(|pid| pid.parse::<u32>().ok())
                == Some(staged::PID),
        "staged 247 resource provenance graph"
    );
    let cmd = fs::read(format!("/proc/{}/cmdline", staged::PID))?;
    let args: Vec<_> = cmd
        .strip_suffix(&[0])
        .context("staged 247 argv terminator")?
        .split(|b| *b == 0)
        .map(std::str::from_utf8)
        .collect::<std::result::Result<_, _>>()?;
    ensure!(json!(args) == b["argv"], "staged 247 argv differs");
    let manager = Command::new("/usr/bin/systemctl")
        .args(["show", staged::UNIT, "--property=ExecStart", "--value"])
        .output()?;
    ensure!(
        manager.status.success()
            && staged_exec_matches(
                c["expected_exec_start"]
                    .as_str()
                    .context("missing staged command")?,
                std::str::from_utf8(&manager.stdout)?.trim(),
            ),
        "staged 247 manager execution differs"
    );
    Ok(proof)
}
pub(super) fn validate(c: &Config) -> Result<()> {
    let mut pids = std::collections::HashSet::new();
    let mut invocations = std::collections::HashSet::new();
    let mut digests = std::collections::HashSet::new();
    use OrdinaryEpoch::*;
    for (epoch, claim) in [
        (Epoch211, &c.delivery211_claim),
        (Pinned247, &c.delivery247_pinned_claim),
        (Epoch248, &c.delivery248_claim),
        (Epoch249, &c.delivery249_claim),
        (Epoch250, &c.delivery250_claim),
        (Epoch251, &c.delivery251_claim),
        (Epoch265, &c.delivery265_claim),
    ] {
        let Some(claim) = claim else { continue };
        let unit = epoch.select(claim)?.unit();
        ensure!(
            pids.insert(claim.pid)
                && invocations.insert(&claim.invocation_id)
                && digests.insert(&claim.claim_sha256),
            "ordinary delivery claims alias each other"
        );
        claim.validate()?;
        for replay in c.replays.iter().chain(&c.diagnostic_replays) {
            ensure!(
                replay.producer_unit != unit
                    && replay.controller_unit != unit
                    && replay.expected_controller_invocation_id != claim.invocation_id
                    && replay.expected_producer_invocation_id != claim.invocation_id,
                "ordinary delivery aliases replay telemetry"
            );
        }
    }
    ensure!(
        !(c.delivery247_resource_only && c.staged247_resource_only),
        "choose one 247 delivery observation"
    );
    ensure!(
        c.delivery247_pinned_claim.is_none()
            || (!c.delivery247_resource_only
                && !c.staged247_resource_only
                && c.successor247_claim.is_none()),
        "pinned epoch 247 conflicts with a historical delivery owner"
    );
    let registered;
    let owner = if let Some(reference) = &c.successor247_claim {
        ensure!(
            c.staged247_resource_only,
            "successor needs exclusive staged delivery RSS selection"
        );
        registered = fourth::load(reference)?;
        successor_owner(&registered)
    } else if c.staged247_resource_only {
        STAGED
    } else {
        ORIGINAL
    };
    if !c.delivery247_resource_only && !c.staged247_resource_only {
        return Ok(());
    }
    ensure!(
        !pids.contains(&owner.pid) && !invocations.iter().any(|id| id.as_str() == owner.iid),
        "247 aliases another delivery"
    );
    for r in c.replays.iter().chain(&c.diagnostic_replays) {
        ensure!(
            r.producer_unit != owner.unit
                && r.controller_unit != owner.unit
                && r.expected_producer_invocation_id != owner.iid
                && r.expected_controller_invocation_id != owner.iid,
            "delivery247 cannot alias replay telemetry"
        );
    }
    ensure!(
        c.epoch203_ram_auxiliary.is_none(),
        "delivery247 is not an auxiliary replay"
    );
    Ok(())
}
fn main_ticks(rss: &Value, pid: u32) -> Result<u64> {
    ensure!(
        rss["census_stable"] == true && rss["error"].is_null(),
        "delivery247 RSS unavailable"
    );
    let rows: Vec<_> = rss["processes"]
        .as_array()
        .context("delivery247 RSS processes")?
        .iter()
        .filter(|p| p["pid"] == pid)
        .collect();
    ensure!(
        rows.len() == 1,
        "delivery247 main missing/duplicated in RSS census"
    );
    rows[0]["start_ticks"]
        .as_u64()
        .context("delivery247 main start ticks")
}
fn process_starts(u: &UnitObservation) -> Result<BTreeMap<u64, u64>> {
    let rss = serde_json::to_value(&u.rss)?;
    let mut found = BTreeMap::new();
    for p in rss["processes"]
        .as_array()
        .context("delivery247 complete cgroup RSS census")?
    {
        let pid = p["pid"].as_u64().context("delivery child PID")?;
        let start = p["start_ticks"].as_u64().context("delivery child start")?;
        ensure!(
            found.insert(pid, start).is_none(),
            "duplicate delivery process"
        );
    }
    Ok(found)
}
fn endpoint(u: &UnitObservation, owner: Owner<'_>) -> Result<u64> {
    ensure!(
        u.unit == owner.unit
            && u.invocation_id == owner.iid
            && u.main_pid == u64::from(owner.pid)
            && u.load_state == "loaded"
            && u.active_state == "active"
            && u.sub_state == "running"
            && u.restarts == 0
            && u.control_group == Path::new(&format!("/system.slice/{}", owner.unit)),
        "delivery247 resource owner changed"
    );
    let raw = serde_json::to_value(u)?;
    // Kernel hard cap is page-aligned; retain actual measured gauges and full RSS.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    ensure!(page > 0, "delivery247 page size");
    let cap = owner.cap / (page as u64) * (page as u64);
    ensure!(
        raw["cgroup"]["gauges"]["memory.max"] == cap
            && raw["cgroup"]["gauges"]["memory.swap.max"] == 0,
        "delivery247 original kernel cap changed"
    );
    main_ticks(&raw["rss"], owner.pid)
}
fn successor_owner(info: &next::Owner) -> Owner<'_> {
    Owner {
        unit: fourth::unit(info),
        iid: &info.iid,
        pid: info.pid,
        image: if fourth::is_fourth(info) {
            fourth::IMAGE
        } else {
            next::IMAGE
        },
        sha: if fourth::is_fourth(info) {
            fourth::IMAGE_SHA
        } else {
            next::IMAGE_SHA
        },
        cap: next::HARD,
    }
}
fn successor_input(reference: &Value, info: &next::Owner) -> Result<()> {
    let additional = (fourth::unit(info) == fourth::V221_UNIT).then_some((next::UNIT, fourth::OLD));
    next::verify_registered_drains(additional)?;
    if fourth::is_fourth(info) {
        ensure!(
            fs::read_to_string("/proc/sys/kernel/random/boot_id")?
                .trim()
                .replace('-', "")
                == "3b17d0055c3a4a0e8841da097e0957b5",
            "fourth 247 boot changed"
        );
        ensure!(
            !Path::new("/sys/fs/cgroup/system.slice")
                .join(next::UNIT)
                .try_exists()?,
            "e434 cgroup returned"
        );
        let m = Command::new("/usr/bin/systemctl")
            .args([
                "show",
                next::UNIT,
                "-p",
                "Id,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,Job,Result,ExecMainStatus,NRestarts,Restart",
            ])
            .output()?;
        let mut state = json!({});
        for line in std::str::from_utf8(&m.stdout)?.lines() {
            let (key, value) = line
                .split_once('=')
                .context("invalid e434 systemd property")?;
            state[key] = json!(value);
        }
        ensure!(
            matches!(m.status.code(), Some(0 | 4))
                && state["Id"] == next::UNIT
                && state["ControlPID"] == "0"
                && state["Job"] == ""
                && (state["LoadState"] != "loaded" || state["Restart"] == "no")
                && fourth::predecessor_spent(&state, fourth::unit(info)),
            "e434 reactivated"
        );
    }
    let again = fourth::load(reference)?;
    ensure!(
        again.proof == info.proof && again.iid == info.iid && again.pid == info.pid,
        "changed successor evidence"
    );
    let argv = fs::read(format!("/proc/{}/cmdline", info.pid))?;
    let args = argv
        .strip_suffix(&[0])
        .context("successor argv terminator")?
        .split(|b| *b == 0)
        .map(std::str::from_utf8)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(json!(args) == info.argv, "successor argv differs");
    let manager = Command::new("/usr/bin/systemctl")
        .args([
            "show",
            fourth::unit(info),
            "--property=ExecStart",
            "--value",
        ])
        .output()?;
    ensure!(
        manager.status.success()
            && staged_exec_matches(&info.command, std::str::from_utf8(&manager.stdout)?.trim()),
        "successor PID1 command differs"
    );
    Ok(())
}
fn observe(
    clock: u64,
    owner: Owner<'_>,
    successor: Option<(&Value, &next::Owner)>,
) -> Result<Value> {
    if let Some((reference, info)) = successor {
        successor_input(reference, info)?;
    }
    let provenance = if owner.iid == staged::IID {
        Some(staged_inputs()?)
    } else {
        None
    };
    let before = observe_unit(owner.unit, owner.iid)?;
    let first_ticks = endpoint(&before, owner)?;
    let image_before = native_input_diagnostic::mapped_image_at(
        Path::new(owner.image),
        owner.sha,
        owner.pid,
        Path::new("/proc"),
        0,
    )?;
    let after = observe_unit(owner.unit, owner.iid)?;
    let last_ticks = endpoint(&after, owner)?;
    let image_after = native_input_diagnostic::mapped_image_at(
        Path::new(owner.image),
        owner.sha,
        owner.pid,
        Path::new("/proc"),
        0,
    )?;
    ensure!(
        stable_unit(&before, &after)
            && first_ticks == last_ticks
            && process_starts(&before)? == process_starts(&after)?
            && image_before["mapped_inode"] == image_after["mapped_inode"]
            && image_before["mapped_device"] == image_after["mapped_device"],
        "delivery247 identity changed during same-cadence sample"
    );
    let mut sample = json!({"range":owner.range(),"sampled_unix_seconds":clock,"resource_only":true,
        "delivery_resource_only":true,"phase":"upload-readback",
        "controller_before":before,"producer_before":before,"controller_after":after,"producer_after":after,
        "mapped_image_before":image_before,"mapped_image_after":image_after,
        "invocation_binding_stable":true,"useful_work":{"sufficient_for_rates":false,"entry_progress_observed":false},
        "entry_replay":false,"ordinary_replay_claim":false,"terminal_completion_proven":false,
        "resource_release_authorized":false,"publication_authorized":false,"r2_mutations":false});
    if let Some(proof) = provenance {
        ensure!(proof == staged_inputs()?, "staged 247 evidence changed");
        sample["staged_owner"] = proof;
        staged::validate(&sample)?;
    }
    if let Some((reference, info)) = successor {
        successor_input(reference, info)?;
        sample["successor_owner"] = info.proof.clone();
        fourth::validate_sample(&sample, info)?;
    }
    Ok(sample)
}
fn row(result: Result<Value>, owner: Owner<'_>) -> Value {
    let (status, observation, error) = match result {
        Ok(v) => ("observed", Some(v), None),
        Err(e) => ("unavailable", None, Some(format!("{e:#}"))),
    };
    json!({"range":owner.range(),"producer_unit":owner.unit,"expected_producer_invocation_id":owner.iid,
        "delivery_resource_only":true,"status":status,"observation":observation,"error":error,
        "entry_replay":false,"ordinary_replay_claim":false,"terminal_completion_proven":false,
        "resource_release_authorized":false,"publication_authorized":false,"r2_mutations":false})
}
pub(super) fn sample(
    enabled: bool,
    staged: bool,
    reference: Option<&Value>,
    clock: u64,
) -> Vec<Value> {
    if let Some(r) = reference {
        return match fourth::load(r) {
            Ok(info) => {
                let owner = successor_owner(&info);
                vec![row(observe(clock, owner, Some((r, &info))), owner)]
            }
            Err(e) => vec![row(
                Err(e),
                Owner {
                    unit: fourth::selected_unit(r).unwrap_or(next::UNIT),
                    iid: "",
                    pid: 0,
                    image: next::IMAGE,
                    sha: next::IMAGE_SHA,
                    cap: next::HARD,
                },
            )],
        };
    }
    if enabled || staged {
        let owner = if staged { STAGED } else { ORIGINAL };
        vec![row(observe(clock, owner, None), owner)]
    } else {
        Vec::new()
    }
}
const UNIT250: &str = "horizon-upload-250-ordinary-v221.service";
const STAGED250: &str = "horizon-upload-250-staged-public-v257.service";
const STAGED250_ETAG: &str = "d152967aadd357c1ce79cea4df147e82-2766";
const STAGED250_BYTES: &str = "185599540324";
const UNIT251: &str = "horizon-upload-251-ordinary-v221.service";
const UNIT265: &str = "horizon-upload-265-ordinary-v215.service";
const RETRY265: &str = "horizon-upload-265-ordinary-retry-v216.service";
const UNIT249: &str = "horizon-upload-249-ordinary-v214.service";
const UNIT211: &str = "horizon-upload-211-ordinary-v221.service";
const STAGED211: &str = "horizon-upload-211-staged-recovery-v1.service";
const STAGED211_RETRY: &str = "horizon-upload-211-staged-recovery-v2.service";
const STAGED211_IMAGE: &str = "/var/lib/jetstreamer/horizon211-staged-recovery-v1/jetstreamer-r2";
const STAGED211_IMAGE_SHA: &str =
    "7271de0e309c83f8fa2f35cf9091280a8b04f66c51d3175ad1d6ff02faa4c59d";
const STAGED211_ETAG: &str = "7ee07c0c0517ba9265a8c43c01903e95-1760";
const STAGED211_BYTES: &str = "118062008962";
const PUBLISHED211_PLAN: &str =
    "/var/lib/jetstreamer/horizon211-staged-published-v256/epoch-211-plan.json";
const PUBLISHED211_PLAN_SHA: &str =
    "fc0b4882fa46ec57ef612a9e811f7aed14b3b748333563fc4a42546aab9980e0";
const PINNED247: &str = "horizon-upload-247-pinned-public-v254.service";
const PINNED247_ETAG: &str = "c1be2474b6c9ba8d0ac11405a97ebee3-2688";
const PINNED247_BYTES: &str = "180370916960";
const UNIT248: &str = "horizon-upload-248-ordinary-v213.service";
const IMAGE248: &str = "/var/lib/jetstreamer/horizon247-public-images-58709604-v1/jetstreamer-r2";
const SHA248: &str = "c1e99ad4b2e7f3fe56235f42a722bbe93e3f13af2003d0eb5a150553ae0a660e";
#[derive(Clone, Copy)]
pub(super) enum OrdinaryEpoch {
    Epoch211,
    Staged211,
    Staged211Retry,
    Pinned247,
    Epoch248,
    Epoch249,
    Epoch250,
    Staged250,
    Epoch251,
    Epoch265,
    Retry265,
}
impl OrdinaryEpoch {
    fn number(self) -> u64 {
        match self {
            Self::Epoch211 | Self::Staged211 | Self::Staged211Retry => 211,
            Self::Pinned247 => 247,
            Self::Epoch248 => 248,
            Self::Epoch249 => 249,
            Self::Epoch250 | Self::Staged250 => 250,
            Self::Epoch251 => 251,
            Self::Epoch265 | Self::Retry265 => 265,
        }
    }
    fn unit(self) -> &'static str {
        match self {
            Self::Epoch211 => UNIT211,
            Self::Staged211 => STAGED211,
            Self::Staged211Retry => STAGED211_RETRY,
            Self::Pinned247 => PINNED247,
            Self::Epoch248 => UNIT248,
            Self::Epoch249 => UNIT249,
            Self::Epoch250 => UNIT250,
            Self::Staged250 => STAGED250,
            Self::Epoch251 => UNIT251,
            Self::Epoch265 => UNIT265,
            Self::Retry265 => RETRY265,
        }
    }
    fn image(self) -> (&'static str, &'static str) {
        match self {
            Self::Staged211 | Self::Staged211Retry | Self::Pinned247 | Self::Staged250 => {
                (STAGED211_IMAGE, STAGED211_IMAGE_SHA)
            }
            _ => (IMAGE248, SHA248),
        }
    }
    fn digest(self) -> &'static str {
        match self {
            Self::Epoch211 => "ce03172902f1108c996e0ac9e9ac90df9180ef8ba49440a3c428d177a7945da2",
            Self::Staged211 => "d8217282aa7e280568082309a6881fb0a22040156f17524637e2737cf0e9245c",
            Self::Staged211Retry => PUBLISHED211_PLAN_SHA,
            Self::Pinned247 => "6c6f7a3880a5c5e511575e7f51d9feb8ff26a52fe922d088bdecdc3c00c72a8e",
            Self::Epoch248 => "3053ed2ca2b2881f2d83855c0fa1cff6e63618387dfb630c76a3db7a2dc7d1fd",
            Self::Epoch250 => "12e68ddf9b6d2505b6090688b5a3cfa4e720242b264cf2a6e7993b9b02f910c2",
            Self::Staged250 => "e96999d456f560fcdc1e1c2c29d11bb4fac9adde7d127542112fe77451c49aa0",
            Self::Epoch251 => "1c815780661e8b502634caff4a2b0d783e831fccc27c612d6a94c3480d00e318",
            Self::Epoch265 | Self::Retry265 => {
                "801acbb79784fb29fda64a572b6b0a1ed1396cdad4216b6d39b36b1dad86a544"
            }
            Self::Epoch249 => "03e16ae1dada49958ff00a7dda1c3ef31c2f37c7503b02b7e0a677bb40863e07",
        }
    }
    pub(super) fn select(self, claim: &DeliveryClaim) -> Result<Self> {
        match (self, claim.retry_unit.as_deref()) {
            (_, None) => Ok(self),
            (Self::Epoch211, Some(STAGED211)) => Ok(Self::Staged211),
            (Self::Epoch211, Some(STAGED211_RETRY)) => Ok(Self::Staged211Retry),
            (Self::Epoch250, Some(STAGED250)) => Ok(Self::Staged250),
            (Self::Epoch265, Some(RETRY265)) => Ok(Self::Retry265),
            _ => anyhow::bail!("unknown retry unit for ordinary epoch {}", self.number()),
        }
    }
    fn claim_path(self) -> PathBuf {
        Path::new("/home/ubuntu/.codex/diagnostics")
            .join(self.unit().trim_end_matches(".service"))
            .join("pipeline-claim.json")
    }
    fn argv(self) -> Vec<String> {
        let epoch = self.number();
        let (source, receipts, plan) = match self {
            Self::Epoch265 | Self::Retry265 => (
                "/home/ubuntu/.jetstreamer-private/qualification-265-replacement-20261119-v3/output".to_owned(),
                "/home/ubuntu/.jetstreamer-private/current-reader-delivery-265-v215/receipts".to_owned(),
                "/var/lib/jetstreamer/horizon265-ordinary-reader-v215/epoch-265-plan.json".to_owned(),
            ),
            Self::Epoch211 => (
                "/home/ubuntu/.jetstreamer-private/qualification-211-singleton-capped-v1/output".to_owned(),
                "/home/ubuntu/.jetstreamer-private/current-reader-delivery-211-v221/receipts".to_owned(),
                "/var/lib/jetstreamer/horizon211-ordinary-reader-v221/epoch-211-plan.json".to_owned(),
            ),
            Self::Staged211 | Self::Staged211Retry => (
                "/home/ubuntu/.jetstreamer-private/qualification-211-singleton-capped-v1/output".to_owned(),
                "/home/ubuntu/.jetstreamer-private/current-reader-delivery-211-staged-recovery-v1/receipts".to_owned(),
                if matches!(self, Self::Staged211Retry) {
                    PUBLISHED211_PLAN
                } else {
                    "/var/lib/jetstreamer/horizon211-staged-recovery-v1/epoch-211-plan.json"
                }.to_owned(),
            ),
            Self::Pinned247 => (
                "/home/ubuntu/.jetstreamer-private/qualification-247-reboot-20261117-v2/output".to_owned(),
                "/home/ubuntu/.jetstreamer-private/current-reader-delivery-247-pinned-public-v254/receipts".to_owned(),
                "/home/ubuntu/.jetstreamer-private/current-reader-delivery-247-pinned-public-v254/epoch-247-plan.json".to_owned(),
            ),
            Self::Epoch251 => (
                "/home/ubuntu/.jetstreamer-private/qualification-251-replacement-20261118-v1/output".to_owned(),
                "/home/ubuntu/.jetstreamer-private/current-reader-delivery-251-20261119-v2/receipts".to_owned(),
                "/var/lib/jetstreamer/horizon247-public-reader-58709604-v1/epoch-251-plan.json".to_owned(),
            ),
            Self::Staged250 => (
                "/home/ubuntu/.jetstreamer-private/qualification-250-reboot-20261117-v1/output".to_owned(),
                "/home/ubuntu/.jetstreamer-private/current-reader-delivery-250-staged-published-v257/receipts".to_owned(),
                "/var/lib/jetstreamer/horizon250-staged-published-v257/epoch-250-plan.json".to_owned(),
            ),
            Self::Epoch248 | Self::Epoch249 | Self::Epoch250 => (
                format!("/home/ubuntu/.jetstreamer-private/qualification-{epoch}-reboot-20261117-v1/output"),
                format!("/home/ubuntu/.jetstreamer-private/current-reader-delivery-{epoch}-20261119-v2/receipts"),
                format!("/var/lib/jetstreamer/horizon247-public-reader-58709604-v1/epoch-{epoch}-plan.json"),
            ),
        };
        let mut args = vec![
            self.image().0.into(),
            "sync".into(),
            source,
            "--epochs".into(),
            format!("{epoch}-{epoch}"),
            "--receipt-directory".into(),
            receipts,
            "--current-reader-plan".into(),
            plan,
            "--current-reader-plan-sha256".into(),
            self.digest().into(),
            "--concurrency".into(),
            "2".into(),
        ];
        let staged_pin = match self {
            Self::Staged211 | Self::Staged211Retry => Some((STAGED211_ETAG, STAGED211_BYTES)),
            Self::Pinned247 => Some((PINNED247_ETAG, PINNED247_BYTES)),
            Self::Staged250 => Some((STAGED250_ETAG, STAGED250_BYTES)),
            _ => None,
        };
        if let Some((etag, bytes)) = staged_pin {
            args.extend([
                "--staged-archive-etag".into(),
                etag.into(),
                "--staged-archive-bytes".into(),
                bytes.into(),
            ]);
        }
        args
    }
}
#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DeliveryClaim {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retry_unit: Option<String>,
    invocation_id: String,
    pid: u32,
    claim_sha256: String,
}

impl DeliveryClaim {
    fn validate(&self) -> Result<()> {
        let digest = |s: &str, n| {
            s.len() == n
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        ensure!(
            self.pid > 1 && digest(&self.invocation_id, 32) && digest(&self.claim_sha256, 64),
            "invalid ordinary delivery binding"
        );
        Ok(())
    }

    fn claim_command<'a>(
        &self,
        epoch: OrdinaryEpoch,
        args: &[String],
        claim: &'a Value,
    ) -> Result<&'a str> {
        ensure!(
            claim["epoch"] == epoch.number()
                && claim["phase"] == "upload-readback"
                && claim["unit"] == epoch.unit()
                && claim["invocation_id"] == self.invocation_id
                && claim["evidence"].as_array().is_some_and(|v| !v.is_empty()),
            "ordinary delivery pipeline claim mismatch"
        );
        let command = claim["expected_exec_start"]
            .as_str()
            .context("ordinary delivery expected command")?;
        let prefix = format!(
            "{{ path={} ; argv[]={} ; ignore_errors=no ; start_time=",
            epoch.image().0,
            args.join(" ")
        );
        ensure!(
            command.starts_with(&prefix)
                && (!matches!(
                    epoch,
                    OrdinaryEpoch::Staged211
                        | OrdinaryEpoch::Staged211Retry
                        | OrdinaryEpoch::Pinned247
                        | OrdinaryEpoch::Staged250
                ) || (command.ends_with(" }") && command.matches("{ path=").count() == 1)),
            "ordinary delivery unexpected uploader command"
        );
        Ok(command)
    }

    fn checked_command(&self, epoch: OrdinaryEpoch) -> Result<()> {
        self.validate()?;
        let path = epoch.claim_path();
        ensure!(path.canonicalize()? == path, "ordinary delivery claim path");
        let file = fs::File::open(&path)?;
        let m = file.metadata()?;
        ensure!(
            m.is_file()
                && m.uid() == 0
                && m.gid() == 0
                && m.nlink() == 1
                && m.mode() & 0o222 == 0
                && m.len() <= 1 << 20,
            "ordinary delivery claim custody"
        );
        let mut bytes = Vec::new();
        std::io::Read::take(file, (1 << 20) + 1).read_to_end(&mut bytes)?;
        ensure!(
            sha256(&bytes) == self.claim_sha256,
            "ordinary delivery claim changed"
        );
        let claim: Value = serde_json::from_slice(&bytes)?;
        let actual = fs::read(format!("/proc/{}/cmdline", self.pid))?;
        let command = self.checked_process_command(epoch, &claim, &actual)?;
        let current = Command::new("/usr/bin/systemctl")
            .args(["show", epoch.unit(), "--property=ExecStart", "--value"])
            .output()?;
        ensure!(
            current.status.success()
                && staged_exec_matches(command, std::str::from_utf8(&current.stdout)?.trim()),
            "ordinary delivery manager command changed"
        );
        Ok(())
    }

    fn checked_process_command<'a>(
        &self,
        epoch: OrdinaryEpoch,
        claim: &'a Value,
        actual: &[u8],
    ) -> Result<&'a str> {
        let mut args = epoch.argv();
        if matches!(epoch, OrdinaryEpoch::Staged211)
            && actual != (args.join("\0") + "\0").as_bytes()
        {
            args[8] = PUBLISHED211_PLAN.into();
            args[10] = PUBLISHED211_PLAN_SHA.into();
        }
        ensure!(
            actual == (args.join("\0") + "\0").as_bytes(),
            "ordinary delivery process command mismatch"
        );
        self.claim_command(epoch, &args, claim)
    }
}

pub(super) fn sample_ordinary(epoch: OrdinaryEpoch, claim: &DeliveryClaim, clock: u64) -> Value {
    let (image, sha) = epoch.image();
    let owner = Owner {
        unit: epoch.unit(),
        iid: &claim.invocation_id,
        pid: claim.pid,
        image,
        sha,
        cap: if matches!(epoch, OrdinaryEpoch::Pinned247) {
            24 << 30
        } else {
            10 << 30
        },
    };
    let result = (|| {
        claim.checked_command(epoch)?;
        let mut sample = observe(clock, owner, None)?;
        claim.checked_command(epoch)?;
        sample["delivery_claim"] = json!({"path":epoch.claim_path(),"sha256":claim.claim_sha256});
        Ok(sample)
    })();
    row(result, owner)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "reads only the registered manager, PID and historical drains on the original host"]
    fn v221_registered_commands_match_all_native_identities() -> Result<()> {
        let path = std::path::PathBuf::from(std::env::var("HORIZON_V221_STATIC_CONFIG")?);
        let (config, _) = load_config(&path)?;
        let reference = config
            .successor247_claim
            .as_ref()
            .context("v221 staged claim")?;
        let staged = fourth::load(reference)?;
        ensure!(
            fourth::unit(&staged) == fourth::V221_UNIT,
            "different staged owner"
        );
        successor_input(reference, &staged)?;
        use OrdinaryEpoch::*;
        for (epoch, claim) in [
            (Epoch211, config.delivery211_claim),
            (Epoch248, config.delivery248_claim),
            (Epoch249, config.delivery249_claim),
            (Epoch250, config.delivery250_claim),
            (Epoch251, config.delivery251_claim),
            (Epoch265, config.delivery265_claim),
        ] {
            let claim = claim.context("missing ordinary delivery")?;
            claim.checked_command(epoch.select(&claim)?)?;
        }
        Ok(())
    }

    #[test]
    fn each_v221_delivery_uses_its_own_epoch_and_claim_directory() {
        use OrdinaryEpoch::*;
        for epoch in [
            Epoch211, Pinned247, Epoch248, Epoch249, Epoch250, Staged250, Epoch251, Retry265,
        ] {
            let unit = epoch.unit();
            let owner = Owner { unit, ..ORIGINAL };
            let args = epoch.argv();
            assert_eq!(owner.range(), format!("{0}-{0}", epoch.number()));
            assert_eq!(args[4], owner.range());
            assert_eq!(args[10], epoch.digest());
            assert!(epoch.claim_path().ends_with(format!(
                "{}/pipeline-claim.json",
                unit.trim_end_matches(".service")
            )));
        }
    }
    #[test]
    fn pinned_247_uses_streaming_staged_publication_with_exact_identity() {
        let args = OrdinaryEpoch::Pinned247.argv();
        assert_eq!(args[4], "247-247");
        assert_eq!(
            args[13..],
            [
                "--staged-archive-etag",
                PINNED247_ETAG,
                "--staged-archive-bytes",
                PINNED247_BYTES,
            ]
        );
        assert!(!args.iter().any(|arg| arg == "--recover-staged-247"));
    }
    #[test]
    fn ordinary_delivery_binds_each_epoch_to_its_distinct_plan_and_process() {
        for epoch in [OrdinaryEpoch::Epoch248, OrdinaryEpoch::Epoch249] {
            let n = epoch.number();
            let args = epoch.argv();
            assert_eq!(args[4], format!("{n}-{n}"));
            assert_eq!(
                args[8],
                format!(
                    "/var/lib/jetstreamer/horizon247-public-reader-58709604-v1/epoch-{n}-plan.json"
                )
            );
            assert_eq!(args[10], epoch.digest());
            assert!(epoch.claim_path().ends_with(format!(
                "{}/pipeline-claim.json",
                epoch.unit().trim_end_matches(".service")
            )));
        }
        let archive = OrdinaryEpoch::Epoch265.argv();
        assert_eq!(archive[4], "265-265");
        assert_eq!(
            archive[8],
            "/var/lib/jetstreamer/horizon265-ordinary-reader-v215/epoch-265-plan.json"
        );
        assert_eq!(archive[10], OrdinaryEpoch::Epoch265.digest());
        assert_ne!(archive[10], OrdinaryEpoch::Epoch249.digest());
        assert_ne!(
            OrdinaryEpoch::Epoch248.digest(),
            OrdinaryEpoch::Epoch249.digest()
        );
    }
    #[test]
    fn staged_250_selects_only_its_pinned_retry() {
        let claim = DeliveryClaim {
            retry_unit: Some(STAGED250.into()),
            invocation_id: "a".repeat(32),
            pid: 1234,
            claim_sha256: "b".repeat(64),
        };
        let staged = OrdinaryEpoch::Epoch250.select(&claim).unwrap();
        assert!(OrdinaryEpoch::Epoch249.select(&claim).is_err());
        assert_ne!(staged.claim_path(), OrdinaryEpoch::Epoch250.claim_path());
        let args = staged.argv();
        assert_eq!(args[2], OrdinaryEpoch::Epoch250.argv()[2]);
        assert_eq!(
            args[13..],
            [
                "--staged-archive-etag",
                STAGED250_ETAG,
                "--staged-archive-bytes",
                STAGED250_BYTES,
            ]
        );
    }
    #[test]
    fn custody_retry_211_pins_the_published_reader_without_reusing_the_old_claim() {
        let mut claim = DeliveryClaim {
            retry_unit: Some(STAGED211_RETRY.into()),
            invocation_id: "a".repeat(32),
            pid: 1234,
            claim_sha256: "b".repeat(64),
        };
        let retry = OrdinaryEpoch::Epoch211.select(&claim).unwrap();
        assert!(OrdinaryEpoch::Epoch250.select(&claim).is_err());
        assert_ne!(retry.claim_path(), OrdinaryEpoch::Staged211.claim_path());
        assert_eq!(retry.argv()[8], PUBLISHED211_PLAN);
        assert_eq!(retry.argv()[10], PUBLISHED211_PLAN_SHA);
        assert_eq!(retry.argv()[13..], OrdinaryEpoch::Staged211.argv()[13..]);
        claim.retry_unit = Some(STAGED211.into());
        assert_eq!(
            OrdinaryEpoch::Epoch211.select(&claim).unwrap().unit(),
            STAGED211
        );
    }
    #[test]
    fn retry_265_uses_its_own_receipt_and_the_original_archive_command() {
        let original = OrdinaryEpoch::Epoch265;
        let mut claim: DeliveryClaim = serde_json::from_value(json!({
            "invocation_id":"a".repeat(32), "pid":1234, "claim_sha256":"b".repeat(64)
        }))
        .unwrap();
        assert_eq!(original.select(&claim).unwrap().unit(), UNIT265);
        claim.retry_unit = Some(RETRY265.into());
        let retry = original.select(&claim).unwrap();
        assert_eq!(retry.unit(), RETRY265);
        assert_ne!(retry.claim_path(), original.claim_path());
        assert_eq!(retry.argv(), original.argv());
        assert!(OrdinaryEpoch::Epoch249.select(&claim).is_err());
        claim.retry_unit = Some(UNIT248.into());
        assert!(original.select(&claim).is_err());
    }
    #[test]
    fn staged_211_uses_its_own_exact_uploader_plan_and_archive_pin() {
        let original = OrdinaryEpoch::Epoch211;
        let claim = DeliveryClaim {
            retry_unit: Some(STAGED211.into()),
            invocation_id: "a".repeat(32),
            pid: 1234,
            claim_sha256: "b".repeat(64),
        };
        let staged = original.select(&claim).unwrap();
        assert_eq!(staged.unit(), STAGED211);
        assert_eq!(
            Owner {
                unit: STAGED211,
                ..ORIGINAL
            }
            .range(),
            "211-211"
        );
        assert_ne!(staged.claim_path(), original.claim_path());
        assert_eq!(staged.image(), (STAGED211_IMAGE, STAGED211_IMAGE_SHA));
        assert!(OrdinaryEpoch::Epoch265.select(&claim).is_err());
        let args = staged.argv();
        assert_eq!(args[2], original.argv()[2]);
        assert_eq!(args[10], staged.digest());
        assert_eq!(
            &args[13..],
            [
                "--staged-archive-etag",
                STAGED211_ETAG,
                "--staged-archive-bytes",
                STAGED211_BYTES,
            ]
        );
        let cmd = format!(
            "{{ path={} ; argv[]={} ; ignore_errors=no ; start_time=[n/a] }}",
            STAGED211_IMAGE,
            args.join(" ")
        );
        let mut payload = json!({
            "epoch": 211,
            "phase": "upload-readback",
            "unit": STAGED211,
            "invocation_id": claim.invocation_id,
            "evidence": [{"path":"/sealed/launch.json","sha256":"1".repeat(64)}],
            "expected_exec_start": cmd,
        });
        assert!(claim.claim_command(staged, &args, &payload).is_ok());
        let original_process = args.join("\0") + "\0";
        assert!(
            claim
                .checked_process_command(staged, &payload, original_process.as_bytes())
                .is_ok()
        );
        let published_command = cmd
            .replace(&args[8], PUBLISHED211_PLAN)
            .replace(staged.digest(), PUBLISHED211_PLAN_SHA);
        let published_process = original_process
            .replace(&args[8], PUBLISHED211_PLAN)
            .replace(staged.digest(), PUBLISHED211_PLAN_SHA);
        payload["expected_exec_start"] = json!(published_command);
        assert!(
            claim
                .checked_process_command(staged, &payload, published_process.as_bytes())
                .is_ok()
        );
        assert!(
            claim
                .checked_process_command(staged, &payload, original_process.as_bytes())
                .is_err()
        );
        payload["expected_exec_start"] = json!(cmd.replace(STAGED211_ETAG, "incorrect"));
        assert!(claim.claim_command(staged, &args, &payload).is_err());
        payload["expected_exec_start"] = json!(cmd.replace(staged.digest(), original.digest()));
        assert!(claim.claim_command(staged, &args, &payload).is_err());
    }
    #[test]
    fn ordinary_delivery_requires_a_bound_claim_and_pid() {
        let mut claim = DeliveryClaim {
            retry_unit: None,
            invocation_id: "a".repeat(32),
            claim_sha256: "1".repeat(64),
            pid: 42,
        };
        assert!(claim.validate().is_ok());
        claim.pid = 0;
        assert!(claim.validate().is_err());
        claim.pid = 42;
        claim.invocation_id.replace_range(0..1, "Z");
        assert!(claim.validate().is_err());
    }
    #[test]
    fn bounded_owner_requires_the_exact_new_plan_and_both_original_invocations() -> Result<()> {
        let f: Value = serde_json::from_str(include_str!("fixtures/successor247-history.json"))?;
        let old = &f["recovery"];
        let tier: Value =
            serde_json::from_str(include_str!("fixtures/successor247-fadfe2d4.json"))?;
        let recovery = &tier["recovery"];
        let plan = &tier["plan"];
        let acceptance = &tier["main_acceptance"];
        let source = &tier["source_acceptance"];
        next::reader_source(plan, acceptance, source)?;
        let previous: Value =
            serde_json::from_str(include_str!("fixtures/successor247-cf4d.json"))?;
        assert!(next::reader_source(plan, acceptance, &previous["source_acceptance"]).is_err());
        let mut foreign = source.clone();
        foreign["published_head"] = json!("0".repeat(40));
        assert!(next::reader_source(plan, acceptance, &foreign).is_err());
        for (field, altered) in [
            ("reader_commit", "99f306410aa59a41394e9c4bf379143fb2a4ada1"),
            (
                "uploader_commit",
                "f72cefd577617c6b8332ca6713f71a01e3d03b12",
            ),
        ] {
            let mut invalid = source.clone();
            invalid[field] = json!(altered);
            assert!(next::reader_source(plan, acceptance, &invalid).is_err());
        }
        assert_eq!(
            tier["recovery_ref"],
            next::binding(next::RECOVERY, next::RECOVERY_SHA)
        );
        assert_eq!(
            tier["recovery"]["prior_staged_owner"],
            next::binding(next::PRIOR, next::PRIOR_SHA)
        );
        let args = recovery["recovery_argv"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect::<Vec<_>>()
            .join(" ");
        let cmd = format!(
            "{{ path={} ; argv[]={args} ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }}",
            next::IMAGE
        );
        let id = "1234567890abcdef1234567890abcdef";
        let claim = json!({"epoch":247,"phase":"upload-readback","unit":next::UNIT,"invocation_id":id,"expected_exec_start":cmd});
        let booking = json!({"unit":next::UNIT,"argv":recovery["recovery_argv"],"approved_plan":next::binding(next::PLAN,next::PLAN_SHA),"capacity_credit":0,"local_reclamation_credit":0,"additional_memory_reserve":next::BOOKED,"disk_reserve":next::DISK});
        let launch = json!({"unit":{"Id":next::UNIT,"InvocationID":id,"NRestarts":"0","MemoryMax":next::HARD.to_string(),"MemorySwapMax":"0","ExecStart":cmd}});
        next::graph(&claim, &booking, &launch, recovery, &f["previous"])?;
        assert!(next::graph(&claim, &booking, &launch, old, &f["previous"]).is_err());
        // Model the coordinated resource row; an actual process is checked only in the observer.
        let modeled = next::Owner {
            iid: id.into(),
            pid: 12345,
            argv: recovery["recovery_argv"].clone(),
            command: cmd.clone(),
            proof: json!({"recovery":tier["recovery_ref"]}),
        };
        let endpoint = json!({"unit":next::UNIT, "invocation_id":id, "main_pid":modeled.pid,
            "control_group":format!("/system.slice/{}",next::UNIT),
            "active_state":"active","sub_state":"running","restarts":0,
            "cgroup":{"gauges":{"memory.max":next::HARD,"memory.swap.max":0}},
            "rss":{"census_stable":true,"error":null,"aggregate_rss_bytes":8192,
                "processes":[{"pid":modeled.pid,"start_ticks":7100}]}});
        let mapped = json!({"executable":next::IMAGE,"sha256":next::IMAGE_SHA,"pid":modeled.pid,"mapped_inode":31,"mapped_device":8});
        let mut sample = json!({"range":"247-247","phase":"upload-readback","resource_only":true,"delivery_resource_only":true,
            "entry_replay":false,"ordinary_replay_claim":false,"invocation_binding_stable":true,"useful_work":{"sufficient_for_rates":false},
            "successor_owner":modeled.proof,"controller_before":endpoint,"producer_before":endpoint,
            "controller_after":endpoint,"producer_after":endpoint,"mapped_image_before":mapped,"mapped_image_after":mapped});
        staged::validate_sample(&sample, &modeled)?;
        sample["mapped_image_after"]["sha256"] = old["uploader"]["sha256"].clone();
        assert!(staged::validate_sample(&sample, &modeled).is_err());
        sample["mapped_image_after"] = mapped;
        let mut reused = endpoint;
        reused["rss"]["processes"][0]["start_ticks"] = json!(7101);
        sample["controller_after"] = reused.clone();
        sample["producer_after"] = reused;
        assert!(staged::validate_sample(&sample, &modeled).is_err());
        let mut stale_booking = booking.clone();
        stale_booking["approved_plan"] = old["current_reader_plan"].clone();
        assert!(next::graph(&claim, &stale_booking, &launch, recovery, &f["previous"]).is_err());
        for key in [
            "prior_staged_owner",
            "historical_terminal",
            "current_reader_plan",
            "uploader",
        ] {
            let mut other = recovery.clone();
            other[key]["sha256"] = json!("0".repeat(64));
            assert!(next::graph(&claim, &booking, &launch, &other, &f["previous"]).is_err());
        }
        for key in [
            "capacity_credit",
            "local_reclamation_credit",
            "additional_memory_reserve",
            "disk_reserve",
        ] {
            let mut other = booking.clone();
            other[key] = json!(1);
            assert!(next::graph(&claim, &other, &launch, recovery, &f["previous"]).is_err());
        }
        assert!(
            next::graph(
                &f["prior_claim"],
                &booking,
                &launch,
                recovery,
                &f["previous"]
            )
            .is_err()
        );
        Ok(())
    }
    #[test]
    #[ignore = "reads only the exact live staged uploader; no global observation or state change"]
    fn native_staged_owner_kernel_rss() {
        let row = row(observe(now_unix().unwrap(), STAGED, None), STAGED);
        assert_eq!(row["status"], "observed", "{row}");
        println!("STAGED247_RSS={row}");
    }
    #[test]
    fn reloaded_manager_retains_the_exact_staged_command() {
        let command =
            "{ path=/sealed/tool ; argv[]=/sealed/tool sync --epochs 247-247 ; ignore_errors=no";
        let original = format!(
            "{command} ; start_time=[Fri 2026-11-20 18:58:29 UTC] ; stop_time=[n/a] ; pid=2149076 ; code=(null) ; status=0/0 }}"
        );
        let reloaded = format!(
            "{command} ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }}"
        );
        assert!(staged_exec_matches(&original, &original));
        assert!(staged_exec_matches(&original, &reloaded));
        for altered in [
            reloaded.replace("247-247", "247-248"),
            reloaded.replace("ignore_errors=no", "ignore_errors=yes"),
            reloaded.replace("pid=0", "pid=42"),
            reloaded.replace("code=(null)", "code=exited"),
        ] {
            assert!(!staged_exec_matches(&original, &altered));
        }
    }

    #[test]
    fn unavailable_staged_owner_never_substitutes_original_or_zero() {
        let data = row(Err(anyhow!("changed")), STAGED);
        assert_eq!(data["producer_unit"], staged::UNIT);
        assert_eq!(data["expected_producer_invocation_id"], staged::IID);
        assert_eq!(data["status"], "unavailable");
        assert!(data["observation"].is_null());
    }
    #[test]
    fn missing_delivery_is_unavailable_not_zero_rss_or_replay() {
        let v = row(Err(anyhow!("original uploader finished")), ORIGINAL);
        assert_eq!(v["status"], "unavailable");
        assert!(v["observation"].is_null());
        for k in [
            "entry_replay",
            "ordinary_replay_claim",
            "terminal_completion_proven",
            "resource_release_authorized",
            "publication_authorized",
            "r2_mutations",
        ] {
            assert_eq!(v[k], false);
        }
    }
    #[test]
    fn actual_pid_required_once_in_stable_rss_census() {
        let good =
            json!({"census_stable":true,"error":null,"processes":[{"pid":PID,"start_ticks":123}]});
        assert_eq!(main_ticks(&good, PID).unwrap(), 123);
        for value in [
            json!({"census_stable":false,"error":null,"processes":[{"pid":PID,"start_ticks":123}]}),
            json!({"census_stable":true,"error":null,"processes":[]}),
            json!({"census_stable":true,"error":null,"processes":[{"pid":42,"start_ticks":123}]}),
            json!({"census_stable":true,"error":null,"processes":[{"pid":PID,"start_ticks":123},{"pid":PID,"start_ticks":123}]}),
        ] {
            assert!(main_ticks(&value, PID).is_err());
        }
    }
}
