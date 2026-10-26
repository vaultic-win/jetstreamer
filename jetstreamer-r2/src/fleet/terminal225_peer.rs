//! Truthful epoch 225 ownership during the completed-producer/extractor handoff.
//!
//! The original producer is durable artifact custody, not a live process.  A
//! later extractor is a different generation and is accepted only through its
//! own admission, launch and current owner.  Both phases retain the complete
//! source/output disk envelope without reclamation credit.
use super::*;

pub(super) const ORIGINAL_UNIT: &str =
    "horizon-qualify-225-natural-root-resource-shrink-budget-2f856bd-v1.service";
pub(super) const ORIGINAL_IID: &str = "4cd76ae1353a4411885b997f04306402";
const ORIGINAL_LAUNCH: &str =
    "/var/lib/jetstreamer/horizon-225-shrink-natural-root-launch-222936-v1/launch.json";
const ORIGINAL_LAUNCH_SHA: &str =
    "491baf3214515c8ad324d0d0de43a3fa680bb35892bfae32fd027b8ce6c6b071";
const SOURCE_ARCHIVE: &str = "/home/ubuntu/.jetstreamer-private/qualification-225-v1625-natural-root-shrink-budget-2f856bd-v1/output/epoch-225.jet";
const SOURCE_ARCHIVE_BYTES: u64 = 265_610_094_371;
const SOURCE_ARCHIVE_SHA: &str = "77c0f95a020ceb6c45e323f4ce1bb48066fd0b379615bd5c9dbcb67f9082d6f9";
const SOURCE_MANIFEST: &str = "/home/ubuntu/.jetstreamer-private/qualification-225-v1625-natural-root-shrink-budget-2f856bd-v1/output/epoch-225.jet.segment.json";
const SOURCE_MANIFEST_SHA: &str =
    "53a69d801e70866b0bc048e1b3a75d9c16c1fb93995503157fc206742f3cdcf6";
const WORKER_SHA: &str = "2dcc9b84a6ce27edba3d3b053c6e6170f66a2337f12a5aae54900c3ad9e2eedd";
pub(super) const RETAINED_DISK_BYTES: u64 = 640u64 << 30;
pub(super) const OUTPUT_BYTES: u64 = 320u64 << 30;
pub(super) const OUTPUT_METADATA_BYTES: u64 = 256u64 << 20;
pub(super) const EXTRACTOR_MEMORY_BYTES: u64 = 96u64 << 30;
pub(super) const GUARD_MEMORY_BYTES: u64 = 1u64 << 30;
pub(super) const METADATA_ISSUER_MEMORY_BYTES: u64 = 1u64 << 30;
pub(super) const EXTRACTION_ADMISSION_MEMORY_BYTES: u64 =
    EXTRACTOR_MEMORY_BYTES + GUARD_MEMORY_BYTES + METADATA_ISSUER_MEMORY_BYTES;
const PINNED_MANIFEST: &[u8] =
    include_bytes!("../../../jetstreamer-node/src/epoch225_extract/source-manifest.json");

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Extractor {
    pub unit: String,
    pub invocation_id: String,
    pub plan: BoundFile,
    pub admission: BoundFile,
    pub launch: BoundFile,
    pub guard_unit: String,
    pub guard_receipt_directory: PathBuf,
    pub guard_plan: BoundFile,
    pub guard_sha256: String,
    pub maximum_output_bytes: u64,
    pub memory_max_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Profile {
    schema: String,
    original_launch: BoundFile,
    source_manifest: BoundFile,
    terminal_properties: BoundFile,
    manager_journal: BoundFile,
    source_archive: PathBuf,
    source_archive_bytes: u64,
    source_archive_sha256: String,
    retained_disk_reservation_bytes: u64,
    reclamation_credit_bytes: u64,
    phase: String,
    extractor: Option<Extractor>,
}

fn exact_original(p: &Profile) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-epoch225-terminal-handoff-profile-v1"
            && p.original_launch.path == Path::new(ORIGINAL_LAUNCH)
            && p.original_launch.sha256 == ORIGINAL_LAUNCH_SHA
            && p.source_manifest.path == Path::new(SOURCE_MANIFEST)
            && p.source_manifest.sha256 == SOURCE_MANIFEST_SHA
            && p.source_archive == Path::new(SOURCE_ARCHIVE)
            && p.source_archive_bytes == SOURCE_ARCHIVE_BYTES
            && p.source_archive_sha256 == SOURCE_ARCHIVE_SHA
            && p.retained_disk_reservation_bytes == RETAINED_DISK_BYTES
            && p.reclamation_credit_bytes == 0,
        "epoch 225 handoff changed its original source or retained reservation"
    );
    Ok(())
}

fn manifest_shape(m: &Value) -> Result<()> {
    let pinned: Value = serde_json::from_slice(PINNED_MANIFEST)?;
    ensure!(
        *m == pinned
            && m["schema_version"] == 1
            && m["epoch"] == 225
            && m["output_slot_start"] == 97_200_000u64
            && m["output_slot_count"] == 863_465u64
            && m["worker_executable_sha256"] == WORKER_SHA
            && m["archive_sha256"] == SOURCE_ARCHIVE_SHA
            && m["runtime"]["runtime_profile"] == "solana-v1.6.25"
            && m["runtime"]["runtime_admission"] == "candidate"
            && m["terminal"]["slot"] == 98_063_464u64
            && m["terminal"]["slot_complete"] == true
            && m["terminal"]["accounts_hash"] == "4TaJaC5esCEWtHp5Fay2aMS9XjA1o9bwQthcvBeSyYbR",
        "epoch 225 retained manifest, terminal checkpoint, runtime or archive differs"
    );
    Ok(())
}

fn original_launch_shape(l: &Value) -> Result<()> {
    let claim = DiagnosticClaim {
        epoch: 225,
        unit: ORIGINAL_UNIT.into(),
        invocation_id: ORIGINAL_IID.into(),
        scratch_path: "/home/ubuntu/.jetstreamer-private/qualification-225-v1625-natural-root-shrink-budget-2f856bd-v1".into(),
        launch_receipt: BoundFile {
            path: ORIGINAL_LAUNCH.into(),
            sha256: ORIGINAL_LAUNCH_SHA.into(),
        },
    };
    validate_diagnostic_launch(l, &claim)?;
    ensure!(
        l["schema"] == "jetstreamer-private-epoch225-shrink-natural-root-resource-launch-v1"
            && l["evidence"]["units"]
                .as_array()
                .is_some_and(|u| u.len() == 1)
            && l["evidence"]["units"][0]["unit"] == ORIGINAL_UNIT
            && l["evidence"]["units"][0]["invocation_id"] == ORIGINAL_IID
            && l["worker_sha256"] == WORKER_SHA,
        "epoch 225 original launch does not bind the completed producer generation"
    );
    Ok(())
}

fn active225(f: &Value) -> Result<Vec<&Value>> {
    Ok(f["active"]
        .as_array()
        .context("epoch 225 handoff accepted roster absent")?
        .iter()
        .filter(|row| row["epoch"] == 225)
        .collect())
}

fn original_history(f: &Value) -> Result<&Value> {
    let rows = f["diagnostics"]
        .as_array()
        .context("epoch 225 retained diagnostic history absent")?
        .iter()
        .filter(|row| {
            row["epoch"] == 225
                && row["launch_invocation_id"] == ORIGINAL_IID
                && row["launch_receipt"] == ORIGINAL_LAUNCH
                && row["launch_receipt_sha256"] == ORIGINAL_LAUNCH_SHA
        })
        .collect::<Vec<_>>();
    ensure!(
        rows.len() == 1,
        "epoch 225 completed original history omitted or duplicated"
    );
    Ok(rows[0])
}

fn active_extractor_row(f: &Value) -> Result<&Value> {
    let rows = f["active"]
        .as_array()
        .context("epoch 225 handoff accepted roster absent")?
        .iter()
        .filter(|row| row["epoch"] == 225)
        .collect::<Vec<_>>();
    ensure!(
        rows.len() == 1,
        "epoch 225 extractor owner omitted or duplicated"
    );
    Ok(rows[0])
}

fn accepted_original(f: &Value) -> Result<()> {
    let history = original_history(f)?;
    let owner = &history["unit"];
    ensure!(
        owner["Id"] == ORIGINAL_UNIT
            && history["live"] == false
            && history["scope_first_epoch"] == 225
            && history["scope_last_epoch"] == 226
            && history["terminal_outcome_requires_canary_receipt"] == true
            && owner["NRestarts"] == "0"
            && active225(f)?.is_empty()
            && f["unit_census"][ORIGINAL_UNIT] == *owner,
        "epoch 225 handoff is not rooted in the exact terminal original producer"
    );
    Ok(())
}

fn terminal_evidence(properties: &Value, journal: &Value) -> Result<()> {
    terminal_state(properties)?;
    let rows = journal
        .as_array()
        .context("epoch 225 PID 1 terminal journal is not an array")?;
    ensure!(
        !rows.is_empty() && rows.len() <= 4096,
        "epoch 225 PID 1 terminal journal is empty or unbounded"
    );
    let mut success = false;
    let mut deactivated = false;
    for row in rows {
        ensure!(
            row["_PID"] == "1"
                && row["_UID"] == "0"
                && row["UNIT"] == ORIGINAL_UNIT
                && row["INVOCATION_ID"] == ORIGINAL_IID,
            "epoch 225 PID 1 terminal journal contains another owner or generation"
        );
        let message = row["MESSAGE"]
            .as_str()
            .context("epoch 225 PID 1 terminal journal message absent")?;
        success |= message.contains("Succeeded") || message.contains("successfully");
        deactivated |= message.contains("Deactivated successfully");
    }
    ensure!(
        success && deactivated,
        "epoch 225 PID 1 journal lacks successful terminal deactivation"
    );
    Ok(())
}

fn terminal_state(current: &Value) -> Result<()> {
    ensure!(
        current["Id"] == ORIGINAL_UNIT
            && current["LoadState"] == "loaded"
            && current["MainPID"] == "0"
            && current["NRestarts"] == "0"
            && current["ActiveState"] == "inactive"
            && current["SubState"] == "dead"
            && current["Result"] == "success"
            && current["ExecMainStatus"] == "0"
            && current["InvocationID"]
                .as_str()
                .is_some_and(|iid| iid.is_empty() || iid == ORIGINAL_IID)
            && current["ControlGroup"].as_str().is_some_and(str::is_empty),
        "epoch 225 original producer is live, failed, restarted, replaced or ambiguous"
    );
    Ok(())
}

fn terminal_owner(current: &Value, accepted: &Value) -> Result<()> {
    terminal_state(current)?;
    ensure!(
        pipeline_status::same_exec_start(
            accepted["ExecStart"]
                .as_str()
                .context("epoch 225 accepted original command absent")?,
            current["ExecStart"]
                .as_str()
                .context("epoch 225 terminal original command absent")?
        ),
        "epoch 225 terminal original command changed"
    );
    Ok(())
}

fn extractor_scope(x: &Extractor, f: &Value, admission: &Value, launch: &Value) -> Result<()> {
    let suffix = x
        .unit
        .strip_prefix("horizon-qualify-225-prefix-extract-")
        .and_then(|s| s.strip_suffix(".service"));
    ensure!(
        suffix.is_some_and(|s| {
            !s.is_empty()
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        }) && is_lower_hex(&x.invocation_id, 32)
            && x.guard_unit
                == x.unit
                    .strip_suffix(".service")
                    .map(|s| format!("{s}-guard.service"))
                    .unwrap_or_default()
            && x.guard_receipt_directory
                .starts_with("/var/lib/jetstreamer")
            && x.maximum_output_bytes == OUTPUT_BYTES
            && x.memory_max_bytes == EXTRACTOR_MEMORY_BYTES,
        "epoch 225 extractor namespace, guard, output or memory envelope differs"
    );
    ensure!(
        admission["schema"] == "jetstreamer-epoch225-prefix-extraction-admission-v1"
            && admission["epoch"] == 225
            && admission["unit"] == x.unit
            && admission["plan"] == private157::binding(&x.plan)
            && admission["retained_disk_reservation_bytes"] == RETAINED_DISK_BYTES
            && admission["maximum_output_bytes"] == x.maximum_output_bytes
            && admission["memory_max_bytes"] == x.memory_max_bytes
            && admission["reclamation_credit_bytes"] == 0
            && admission["authority"]["publication_authorized"] == false
            && admission["authority"]["retirement_authorized"] == false
            && admission["authority"]["runtime_promotion_authorized"] == false
            && admission["authority"]["r2_mutations"] == false,
        "epoch 225 extractor admission does not retain the exact source/envelope"
    );
    ensure!(
        launch["schema"] == "jetstreamer-epoch225-prefix-extraction-launch-v1"
            && launch["epoch"] == 225
            && launch["unit"] == x.unit
            && launch["invocation_id"] == x.invocation_id
            && launch["plan"] == private157::binding(&x.plan)
            && launch["admission"] == private157::binding(&x.admission)
            && launch["guard_unit"] == x.guard_unit
            && launch["guard_receipt_directory"]
                == serde_json::to_value(&x.guard_receipt_directory)?
            && launch["guard_plan"] == private157::binding(&x.guard_plan)
            && launch["guard_sha256"] == x.guard_sha256
            && launch["authority"]["publication_authorized"] == false
            && launch["authority"]["retirement_authorized"] == false
            && launch["authority"]["runtime_promotion_authorized"] == false
            && launch["authority"]["r2_mutations"] == false,
        "epoch 225 extractor launch differs from its admitted generation"
    );
    original_history(f)?;
    let row = active_extractor_row(f)?;
    let owner = singleton227_admission::active_owner(row)?;
    let rows226 = f["active"]
        .as_array()
        .context("epoch 225 extractor active roster absent")?
        .iter()
        .filter(|row| row["epoch"] == 226)
        .collect::<Vec<_>>();
    ensure!(
        owner["Id"] == x.unit
            && owner["InvocationID"] == x.invocation_id
            && owner["NRestarts"] == "0"
            && owner["ActiveState"] == "active"
            && owner["SubState"] == "running"
            && owner["MainPID"]
                .as_str()
                .and_then(|s| s.parse::<u32>().ok())
                .is_some_and(|n| n > 1)
            && f["unit_census"][&x.unit] == *owner
            && row["phase"] == "private-prefix-extraction"
            && row["wire_phase"] == "verification"
            && row["ordinary_replay_claim"] == false
            && row["source_must_be_retained"] == true
            && row["retained226_private_slots"] == 431_465u64
            && row["missing226_suffix_slots"] == 535
            && rows226.len() == 1
            && rows226[0]["phase"] == "private-prefix-extraction"
            && rows226[0]["wire_phase"] == "verification"
            && rows226[0]["ordinary_replay_claim"] == false
            && rows226[0]["source_must_be_retained"] == true
            && rows226[0]["retained226_private_slots"] == 431_465u64
            && rows226[0]["missing226_suffix_slots"] == 535
            && singleton227_admission::active_owner(rows226[0])? == owner,
        "epoch 225 extractor is omitted, inactive, restarted, replaced or lost its epoch 226 tail"
    );
    Ok(())
}

fn source_anchor(
    source: &Profile,
    profile: &Profile,
    launch: &Value,
    anchor: &BoundFile,
) -> Result<()> {
    ensure!(
        source.phase == "terminal-retained"
            && source.extractor.is_none()
            && source.original_launch == profile.original_launch
            && source.source_manifest == profile.source_manifest
            && source.terminal_properties == profile.terminal_properties
            && source.manager_journal == profile.manager_journal
            && launch["terminal_handoff"] == private157::binding(anchor),
        "epoch 225 extractor borrowed a different terminal handoff"
    );
    Ok(())
}
impl Profile {
    fn source_manifest_placeholder() -> BoundFile {
        BoundFile {
            path: SOURCE_MANIFEST.into(),
            sha256: SOURCE_MANIFEST_SHA.into(),
        }
    }

    fn load_evidence(binding: &BoundFile) -> Result<Self> {
        let value = native210::immutable_json(binding)?;
        let profile: Self = serde_json::from_value(value)?;
        exact_original(&profile)?;
        // The retained manifest remains owned by its original producer. Freeze
        // its bytes without changing that uid merely to read terminal evidence.
        let m = fs::symlink_metadata(&profile.source_manifest.path)?;
        ensure!(
            m.is_file()
                && m.uid() == 1000
                && m.nlink() == 1
                && m.mode() & 0o222 == 0
                && profile.source_manifest.path.canonicalize()? == profile.source_manifest.path,
            "epoch 225 retained manifest custody differs"
        );
        let manifest = bound_json(&profile.source_manifest)?;
        let launch = native210::immutable_json(&profile.original_launch)?;
        manifest_shape(&manifest)?;
        original_launch_shape(&launch)?;
        let properties = native210::immutable_json(&profile.terminal_properties)?;
        let journal = native210::immutable_json(&profile.manager_journal)?;
        terminal_evidence(&properties, &journal)?;
        Ok(profile)
    }

    pub(super) fn load(binding: &BoundFile, f: &Value) -> Result<Self> {
        let profile = Self::load_evidence(binding)?;
        ensure!(
            native210::immutable_json(&profile.terminal_properties)?
                == original_history(f)?["unit"],
            "epoch 225 terminal properties differ from the accepted historical row"
        );
        if let Some(x) = &profile.extractor {
            let admission = native210::immutable_json(&x.admission)?;
            let launch = native210::immutable_json(&x.launch)?;
            // The live profile is prepared after launch. Its source anchor was
            // frozen before admission; requiring the live profile's own digest
            // here would create an impossible admission/launch hash cycle.
            let anchor: BoundFile = serde_json::from_value(admission["terminal_handoff"].clone())?;
            let source = Self::load_evidence(&anchor)?;
            source_anchor(&source, &profile, &launch, &anchor)?;
        }
        profile.validate_fleet(f)?;
        Ok(profile)
    }

    fn validate_fleet(&self, f: &Value) -> Result<()> {
        match (&*self.phase, &self.extractor) {
            ("terminal-retained", None) => accepted_original(f),
            ("extractor-live", Some(x)) => {
                let admission = native210::immutable_json(&x.admission)?;
                let launch = native210::immutable_json(&x.launch)?;
                extractor_scope(x, f, &admission, &launch)
            }
            _ => bail!("epoch 225 handoff phase/extractor shape differs"),
        }
    }

    pub(super) fn extractor(&self) -> Option<&Extractor> {
        self.extractor.as_ref()
    }

    pub(super) fn phase(&self) -> &str {
        &self.phase
    }

    pub(super) fn census_names(&self) -> BTreeSet<String> {
        let mut names = BTreeSet::from([ORIGINAL_UNIT.to_owned()]);
        if let Some(x) = &self.extractor {
            names.insert(x.unit.clone());
        }
        names
    }

    pub(super) fn without_guards(
        &self,
        guards: &BTreeMap<String, BoundFile>,
    ) -> Result<BTreeMap<String, BoundFile>> {
        let mut view = guards.clone();
        ensure!(
            view.remove(ORIGINAL_UNIT).is_none(),
            "epoch 225 obsolete producer guard must not be selected"
        );
        match &self.extractor {
            Some(x) => ensure!(
                view.remove(&x.unit).is_some(),
                "epoch 225 live extractor guard omitted"
            ),
            None => ensure!(
                !guards
                    .keys()
                    .any(|name| name.starts_with("horizon-qualify-225-prefix-extract-")),
                "epoch 225 terminal handoff imported an unadmitted extractor guard"
            ),
        }
        Ok(view)
    }

    pub(super) fn guard(
        &self,
        guards: &BTreeMap<String, BoundFile>,
        census: &BTreeMap<String, Value>,
        sample: u64,
        now: u64,
    ) -> Result<Value> {
        let Some(x) = &self.extractor else {
            self.without_guards(guards)?;
            return Ok(json!({"phase":"terminal-retained","guard":null,
                "obsolete_producer_guard_selected":false}));
        };
        let current = census
            .get(&x.unit)
            .context("epoch 225 extractor current row missing")?;
        ensure!(
            current["InvocationID"] == x.invocation_id && diagnostic_stage_running(current),
            "epoch 225 extractor is no longer its admitted live generation"
        );
        let binding = guards
            .get(&x.unit)
            .context("epoch 225 extractor protective guard omitted")?;
        self.without_guards(guards)?;
        let g = bound_json(binding)?;
        let p = native210::immutable_json(&x.guard_plan)?;
        let recorded = g["recorded_unix_seconds"]
            .as_u64()
            .context("epoch 225 extractor guard clock absent")?;
        ensure!(
            p["schema"] == "jetstreamer-horizon-standalone-guard-plan-v1"
                && p["unit"] == x.unit
                && p["invocation_id"] == x.invocation_id
                && p["maximum_root_physical_bytes"] == OUTPUT_BYTES + OUTPUT_METADATA_BYTES
                && p["maximum_worker_vmas"] == 3_500_000u64
                && g["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
                && g["guard_sha256"] == x.guard_sha256
                && g["plan_sha256"] == x.guard_plan.sha256
                && g["plan"] == serde_json::to_value(&x.guard_plan.path)?
                && g["producer_invocation_id"] == x.invocation_id
                && g["producer"]["invocation_id"] == x.invocation_id
                && g["producer"]["active"] == "active"
                && g["producer"]["sub"] == "running"
                && g["producer"]["restarts"] == 0
                && g["trip_reason"].is_null()
                && g["worker_observation_error"].is_null()
                && g["root_physical_observation_error"].is_null()
                && recorded >= sample
                && recorded <= now
                && now - recorded <= 1800,
            "epoch 225 extractor guard is stale, foreign, tripped or belongs to another generation"
        );
        let completed = warmup223::completed_guard_binding(
            &x.guard_unit,
            &x.guard_receipt_directory,
            sample,
            now,
        )?;
        ensure!(
            completed["binding"] == private157::binding(binding),
            "epoch 225 extractor selected guard is not its latest successful fire"
        );
        Ok(
            json!({"phase":"extractor-live","owner":x.unit,"invocation_id":x.invocation_id,
            "guard":private157::binding(binding),"completed":completed}),
        )
    }

    pub(super) fn resources(&self) -> (u64, Value, u64, Value) {
        let memory = self
            .extractor
            .as_ref()
            .map_or(0, |_| EXTRACTION_ADMISSION_MEMORY_BYTES);
        let output = self
            .extractor
            .as_ref()
            .map_or(0, |_| OUTPUT_BYTES + OUTPUT_METADATA_BYTES);
        (
            RETAINED_DISK_BYTES + output,
            json!({"epoch":225,"phase":self.phase,"retained_source_archive_bytes":SOURCE_ARCHIVE_BYTES,
                "retained_disk_reservation_bytes":RETAINED_DISK_BYTES,"reclamation_credit_bytes":0,
                "additional_extractor_output_and_metadata_bytes":output,
                "total_protected_disk_bytes":RETAINED_DISK_BYTES+output,
                "extractor_output_cap_bytes":self.extractor.as_ref().map(|_|OUTPUT_BYTES),
                "source_and_private_epoch_226_tail_retained":true}),
            memory,
            json!({"epoch":225,"phase":self.phase,"extractor_hard_memory_bytes":self.extractor.as_ref().map_or(0, |_|EXTRACTOR_MEMORY_BYTES),
                "independent_guard_hard_memory_bytes":self.extractor.as_ref().map_or(0, |_|GUARD_MEMORY_BYTES),
                "metadata_issuer_hard_memory_bytes":self.extractor.as_ref().map_or(0, |_|METADATA_ISSUER_MEMORY_BYTES),
                "total_hard_memory_bytes":memory,"old_worker_rss_credit_bytes":0}),
        )
    }

    pub(super) fn selected_owner<'a>(&self, f: &'a Value) -> Result<Option<&'a Value>> {
        self.validate_fleet(f)?;
        match &self.extractor {
            Some(_) => Ok(Some(singleton227_admission::active_owner(
                active_extractor_row(f)?,
            )?)),
            None => Ok(None),
        }
    }

    pub(super) fn current(&self, f: &Value, census: &BTreeMap<String, Value>) -> Result<()> {
        let accepted = self.selected_owner(f)?;
        let original = census
            .get(ORIGINAL_UNIT)
            .context("epoch 225 terminal original omitted from current census")?;
        terminal_owner(original, &original_history(f)?["unit"])?;
        if let Some(x) = &self.extractor {
            let accepted =
                accepted.context("epoch 225 admitted extractor has no accepted owner")?;
            let current = census
                .get(&x.unit)
                .context("epoch 225 admitted extractor omitted from current census")?;
            for key in [
                "Id",
                "InvocationID",
                "MainPID",
                "NRestarts",
                "ActiveState",
                "SubState",
                "ControlGroup",
            ] {
                ensure!(
                    current[key] == accepted[key],
                    "epoch 225 extractor changed:{key}"
                );
            }
            ensure!(
                pipeline_status::same_exec_start(
                    accepted["ExecStart"]
                        .as_str()
                        .context("epoch 225 accepted extractor command")?,
                    current["ExecStart"]
                        .as_str()
                        .context("epoch 225 current extractor command")?
                ) && diagnostic_stage_running(current),
                "epoch 225 extractor command changed or is no longer live"
            );
        }
        Ok(())
    }

    pub(super) fn without(&self, f: &Value) -> Result<Value> {
        self.validate_fleet(f)?;
        let mut view = f.clone();
        view["active"]
            .as_array_mut()
            .context("epoch 225 handoff active roster absent")?
            .retain(|row| !matches!(row["epoch"].as_u64(), Some(225) | Some(226)));
        Ok(view)
    }

    pub(super) fn without_current(
        &self,
        f: &Value,
        census: &BTreeMap<String, Value>,
    ) -> Result<BTreeMap<String, Value>> {
        self.current(f, census)?;
        let mut view = census.clone();
        view.remove(ORIGINAL_UNIT);
        if let Some(x) = &self.extractor {
            view.remove(&x.unit);
        }
        Ok(view)
    }

    pub(super) fn without_observer(&self, o: &Value, f: &Value) -> Result<Value> {
        let mut view = o.clone();
        let Some(owner) = self.selected_owner(f)? else {
            return Ok(view);
        };
        let name = owner["Id"]
            .as_str()
            .context("epoch 225 selected owner name")?;
        for key in ["replays", "diagnostic_replays"] {
            view[key]
                .as_array_mut()
                .with_context(|| format!("epoch 225 observer {key} absent"))?
                .retain(|row| {
                    row["producer_unit"] != name
                        && row["producer_after"]["unit"] != name
                        && row["observation"]["producer_after"]["unit"] != name
                });
        }
        Ok(view)
    }
}

pub(in crate::fleet) fn validate_profile(binding: &BoundFile) -> Result<Value> {
    let profile = Profile::load_evidence(binding)?;
    Ok(
        json!({"schema":"jetstreamer-epoch225-terminal-handoff-validation-v1",
        "profile":private157::binding(binding),"phase":profile.phase,
        "retained_disk_reservation_bytes":RETAINED_DISK_BYTES,
        "reclamation_credit_bytes":0,"source_archive_sha256":SOURCE_ARCHIVE_SHA,
        "source_manifest_sha256":SOURCE_MANIFEST_SHA,"terminal_slot":98_063_464u64,
        "original_live_owner_claimed":false,"authority":{"launch":false,"publication":false,
        "retirement":false,"remote_mutations":false,"r2_mutations":false}}),
    )
}

pub(in crate::fleet) fn current(
    binding: &BoundFile,
    previous_fleet: &Value,
    census: &BTreeMap<String, Value>,
) -> Result<()> {
    Profile::load(binding, previous_fleet)?.current(previous_fleet, census)
}

#[cfg(test)]
pub(super) fn fixture_terminal_profile() -> Profile {
    Profile {
        schema: "jetstreamer-epoch225-terminal-handoff-profile-v1".into(),
        original_launch: BoundFile {
            path: ORIGINAL_LAUNCH.into(),
            sha256: ORIGINAL_LAUNCH_SHA.into(),
        },
        source_manifest: Profile::source_manifest_placeholder(),
        terminal_properties: BoundFile {
            path: "/sealed/terminal-properties.json".into(),
            sha256: "a".repeat(64),
        },
        manager_journal: BoundFile {
            path: "/sealed/manager-journal.json".into(),
            sha256: "b".repeat(64),
        },
        source_archive: SOURCE_ARCHIVE.into(),
        source_archive_bytes: SOURCE_ARCHIVE_BYTES,
        source_archive_sha256: SOURCE_ARCHIVE_SHA.into(),
        retained_disk_reservation_bytes: RETAINED_DISK_BYTES,
        reclamation_credit_bytes: 0,
        phase: "terminal-retained".into(),
        extractor: None,
    }
}

#[cfg(test)]
pub(super) fn fixture_terminal_fleet(active: Vec<Value>) -> Value {
    let owner = json!({"Id":ORIGINAL_UNIT,"LoadState":"loaded","InvocationID":"","MainPID":"0",
        "NRestarts":"0","ActiveState":"inactive","SubState":"dead","Result":"success",
        "ExecMainStatus":"0","ControlGroup":"","Type":"exec",
        "ExecStart":"{ path=/sealed/owner ; argv[]=/sealed/owner ; ignore_errors=no }"});
    json!({"active":active,"diagnostics":[{"epoch":225,"launch_invocation_id":ORIGINAL_IID,
        "launch_receipt":ORIGINAL_LAUNCH,"launch_receipt_sha256":ORIGINAL_LAUNCH_SHA,"live":false,
        "scope_first_epoch":225,"scope_last_epoch":226,"terminal_outcome_requires_canary_receipt":true,
        "unit":owner}],"unit_census":{(ORIGINAL_UNIT):owner}})
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(phase: &str, extractor: Option<Extractor>) -> Profile {
        Profile {
            schema: "jetstreamer-epoch225-terminal-handoff-profile-v1".into(),
            original_launch: BoundFile {
                path: ORIGINAL_LAUNCH.into(),
                sha256: ORIGINAL_LAUNCH_SHA.into(),
            },
            source_manifest: Profile::source_manifest_placeholder(),
            terminal_properties: BoundFile {
                path: "/sealed/terminal-properties.json".into(),
                sha256: "a".repeat(64),
            },
            manager_journal: BoundFile {
                path: "/sealed/manager-journal.json".into(),
                sha256: "b".repeat(64),
            },
            source_archive: SOURCE_ARCHIVE.into(),
            source_archive_bytes: SOURCE_ARCHIVE_BYTES,
            source_archive_sha256: SOURCE_ARCHIVE_SHA.into(),
            retained_disk_reservation_bytes: RETAINED_DISK_BYTES,
            reclamation_credit_bytes: 0,
            phase: phase.into(),
            extractor,
        }
    }
    fn live(name: &str, iid: &str) -> Value {
        json!({"Id":name,"LoadState":"loaded","InvocationID":iid,"MainPID":"42","NRestarts":"0",
            "ActiveState":"active","SubState":"running","Result":"success","ExecMainStatus":"0",
            "ControlGroup":format!("/system.slice/{name}"),"ExecStart":"{ path=/sealed/owner ; argv[]=/sealed/owner ; ignore_errors=no }"})
    }
    fn terminal() -> Value {
        json!({"Id":ORIGINAL_UNIT,"LoadState":"loaded","InvocationID":"","MainPID":"0","NRestarts":"0",
            "ActiveState":"inactive","SubState":"dead","Result":"success","ExecMainStatus":"0","ControlGroup":"",
            "ExecStart":"{ path=/sealed/owner ; argv[]=/sealed/owner ; ignore_errors=no }"})
    }
    fn fleet(owner: Value) -> Value {
        json!({"active":[],"diagnostics":[{"epoch":225,"launch_invocation_id":ORIGINAL_IID,
            "launch_receipt":ORIGINAL_LAUNCH,"launch_receipt_sha256":ORIGINAL_LAUNCH_SHA,"live":false,
            "scope_first_epoch":225,"scope_last_epoch":226,"terminal_outcome_requires_canary_receipt":true,
            "unit":owner}],"unit_census":{(ORIGINAL_UNIT):owner}})
    }

    #[test]
    fn e225_terminal_live_profile_uses_immutable_prior_anchor_without_hash_cycle() {
        let original = profile("terminal-retained", None);
        let mut live = original.clone();
        live.phase = "extractor-live".into();
        let anchor = BoundFile {
            path: "/sealed/terminal-anchor.json".into(),
            sha256: "a".repeat(64),
        };
        let launch = json!({"terminal_handoff":private157::binding(&anchor)});
        source_anchor(&original, &live, &launch, &anchor).unwrap();
        live.terminal_properties.sha256 = "b".repeat(64);
        assert!(source_anchor(&original, &live, &launch, &anchor).is_err());
        let mut live = original.clone();
        live.phase = "extractor-live".into();
        let foreign = json!({"terminal_handoff":{"path":"/sealed/foreign-profile.json","sha256":"b".repeat(64)}});
        assert!(source_anchor(&original, &live, &foreign, &anchor).is_err());
        assert!(source_anchor(&live, &live, &launch, &anchor).is_err());
    }
    #[test]
    fn terminal225_retains_reservation_without_fabricating_a_live_iid_or_guard() {
        let p = profile("terminal-retained", None);
        exact_original(&p).unwrap();
        let f = fleet(terminal());
        accepted_original(&f).unwrap();
        let current = BTreeMap::from([(ORIGINAL_UNIT.into(), terminal())]);
        p.current(&f, &current).unwrap();
        assert!(p.extractor().is_none());
        assert_eq!(p.without(&f)["active"], json!([]));
        assert_eq!(p.without_current(&f, &current).unwrap().len(), 0);
        assert_eq!(p.retained_disk_reservation_bytes, 640u64 << 30);
        assert_eq!(p.reclamation_credit_bytes, 0);
        p.without_guards(&BTreeMap::new()).unwrap();
        let obsolete = BTreeMap::from([(
            ORIGINAL_UNIT.into(),
            BoundFile {
                path: "/sealed/obsolete-guard.json".into(),
                sha256: "9".repeat(64),
            },
        )]);
        assert!(p.without_guards(&obsolete).is_err());

        let mut falsely_live = current;
        falsely_live.insert(ORIGINAL_UNIT.into(), live(ORIGINAL_UNIT, ORIGINAL_IID));
        assert!(p.current(&f, &falsely_live).is_err());
    }

    #[test]
    fn terminal225_rejects_changed_manifest_reservation_omission_and_duplicate_owner() {
        manifest_shape(&serde_json::from_slice(PINNED_MANIFEST).unwrap()).unwrap();
        let mut changed: Value = serde_json::from_slice(PINNED_MANIFEST).unwrap();
        changed["terminal"]["slot"] = json!(98_063_463u64);
        assert!(manifest_shape(&changed).is_err());
        let mut p = profile("terminal-retained", None);
        p.retained_disk_reservation_bytes = 0;
        assert!(exact_original(&p).is_err());
        let mut f = fleet(terminal());
        let duplicate = f["diagnostics"][0].clone();
        f["diagnostics"].as_array_mut().unwrap().push(duplicate);
        assert!(accepted_original(&f).is_err());
    }

    #[test]
    fn extractor225_requires_its_own_admitted_generation_and_retains_the_same_reservation() {
        let unit = "horizon-qualify-225-prefix-extract-attempt1.service";
        let iid = "c".repeat(32);
        let authority = json!({"publication_authorized":false,"retirement_authorized":false,
            "runtime_promotion_authorized":false,"r2_mutations":false});
        let x = Extractor {
            unit: unit.into(),
            invocation_id: iid.clone(),
            plan: BoundFile {
                path: "/sealed/extractor-plan.json".into(),
                sha256: "3".repeat(64),
            },
            admission: BoundFile {
                path: "/sealed/extractor-admission.json".into(),
                sha256: "d".repeat(64),
            },
            launch: BoundFile {
                path: "/sealed/extractor-launch.json".into(),
                sha256: "e".repeat(64),
            },
            guard_unit: "horizon-qualify-225-prefix-extract-attempt1-guard.service".into(),
            guard_receipt_directory: "/var/lib/jetstreamer/extractor-guard-receipts".into(),
            guard_plan: BoundFile {
                path: "/sealed/extractor-guard-plan.json".into(),
                sha256: "f".repeat(64),
            },
            guard_sha256: "1".repeat(64),
            maximum_output_bytes: OUTPUT_BYTES,
            memory_max_bytes: EXTRACTOR_MEMORY_BYTES,
        };
        let admission = json!({"schema":"jetstreamer-epoch225-prefix-extraction-admission-v1",
            "epoch":225,"unit":unit,"plan":private157::binding(&x.plan),
            "retained_disk_reservation_bytes":RETAINED_DISK_BYTES,"maximum_output_bytes":OUTPUT_BYTES,
            "memory_max_bytes":EXTRACTOR_MEMORY_BYTES,"reclamation_credit_bytes":0,"authority":authority});
        let launch = json!({"schema":"jetstreamer-epoch225-prefix-extraction-launch-v1","epoch":225,
            "unit":unit,"invocation_id":iid,"plan":private157::binding(&x.plan),
            "admission":private157::binding(&x.admission),"guard_unit":x.guard_unit,
            "guard_receipt_directory":x.guard_receipt_directory,"guard_plan":private157::binding(&x.guard_plan),
            "guard_sha256":x.guard_sha256,"authority":authority});
        let owner = live(unit, &iid);
        let row = |epoch| {
            json!({"epoch":epoch,"phase":"private-prefix-extraction",
            "wire_phase":"verification","ordinary_replay_claim":false,"source_must_be_retained":true,
            "retained226_private_slots":431_465u64,"missing226_suffix_slots":535,"producer":owner.clone()})
        };
        let mut f = fleet(terminal());
        f["active"] = json!([row(225), row(226)]);
        f["unit_census"][unit] = owner;
        extractor_scope(&x, &f, &admission, &launch).unwrap();
        let p = profile("extractor-live", Some(x.clone()));
        assert_eq!(
            p.resources().0,
            RETAINED_DISK_BYTES + OUTPUT_BYTES + OUTPUT_METADATA_BYTES
        );
        assert_eq!(p.resources().2, EXTRACTION_ADMISSION_MEMORY_BYTES);
        assert_eq!(
            p.resources().0 - profile("terminal-retained", None).resources().0,
            OUTPUT_BYTES + OUTPUT_METADATA_BYTES
        );
        let mut fabricated = f;
        fabricated["active"][0]["producer"]["InvocationID"] = json!("2".repeat(32));
        assert!(extractor_scope(&x, &fabricated, &admission, &launch).is_err());
    }
}
