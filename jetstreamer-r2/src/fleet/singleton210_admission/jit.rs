//! Same-process Full 210 JIT issuer. All expensive independent input checks
//! precede intrinsic guard selection; ordinary complete admission is unchanged.
use super::*;
mod issuer;
mod qualification;
const IID207: &str = "74eb420ca4574a50a35913d1417124f1";
pub(super) fn issuer_scope(name: &str) -> bool {
    issuer::scope(name)
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    observer: BoundFile,
    fleet: BoundFile,
    epoch225_handoff: BoundFile,
    resource_plan: BoundFile,
    capability: BoundFile,
    native_input: BoundFile,
    issuer: issuer::Role,
    output_directory: PathBuf,
}
fn private(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        path.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-210-singleton-admission-"))
            && path.canonicalize()? == path
            && m.is_dir()
            && m.uid() == 0
            && m.gid() == 0
            && m.mode() & 0o777 == 0o700,
        "210 JIT attempt must be a canonical direct root-private output directory"
    );
    Ok(())
}
fn scope(r: &Request) -> Result<()> {
    ensure!(
        r.schema == "jetstreamer-full210-jit-admission-spec-v1" && issuer::scope(&r.issuer.unit),
        "210 JIT request is foreign"
    );
    private(&r.output_directory)?;
    ensure!(
        fs::read_dir(&r.output_directory)?.next().is_none(),
        "210 JIT attempt is not fresh; preserve previous evidence"
    );
    Ok(())
}
#[derive(Clone, PartialEq, Eq, Serialize)]
struct GuardProfile {
    owner: String,
    owner_invocation_id: String,
    epoch: u64,
    guard_unit: String,
    receipt_directory: PathBuf,
    registered_completed: Option<completed_archive_phase::GuardSelectionProfile>,
    registered_extractor: Option<terminal225_peer::Extractor>,
    registered_first_root233: Option<prefix223_live_peer::FirstRoot233GuardProfile>,
}
fn legacy_profile(owner: &str, epoch: u64, iid: &str) -> Result<GuardProfile> {
    let (unit, directory) = prefix223_native20_admission::guard_selector(owner)?;
    Ok(GuardProfile {
        owner: owner.into(),
        owner_invocation_id: iid.into(),
        epoch,
        guard_unit: unit.into(),
        receipt_directory: directory.into(),
        registered_completed: None,
        registered_extractor: None,
        registered_first_root233: None,
    })
}
fn roster_with_closed(
    f: &Value,
    handoff: &terminal225_peer::Profile,
    mut completed: BTreeMap<String, completed_archive_phase::GuardSelectionProfile>,
    mut first_root233: BTreeMap<String, prefix223_live_peer::FirstRoot233GuardProfile>,
) -> Result<BTreeMap<String, GuardProfile>> {
    let mut found = BTreeMap::new();
    let selected225 = handoff.selected_owner(f)?;
    for row in f["active"]
        .as_array()
        .context("210 JIT complete accepted roster absent")?
    {
        let owner = singleton227_admission::active_owner(row)?;
        let name = owner["Id"]
            .as_str()
            .context("210 JIT accepted owner name absent")?;
        if matches!(row["epoch"].as_u64(), Some(225 | 226)) {
            let extractor = handoff
                .extractor()
                .context("210 JIT active epoch 225/226 row lacks an admitted extractor")?;
            ensure!(
                selected225 == Some(owner)
                    && name == extractor.unit
                    && owner["InvocationID"] == extractor.invocation_id,
                "210 JIT epoch 225/226 extractor row changed generation"
            );
            if row["epoch"] == 226 {
                continue;
            }
            ensure!(
                found
                    .insert(
                        name.to_owned(),
                        GuardProfile {
                            owner: name.into(),
                            owner_invocation_id: extractor.invocation_id.clone(),
                            epoch: 225,
                            guard_unit: extractor.guard_unit.clone(),
                            receipt_directory: extractor.guard_receipt_directory.clone(),
                            registered_completed: None,
                            registered_extractor: Some(extractor.clone()),
                            registered_first_root233: None,
                        },
                    )
                    .is_none(),
                "210 JIT duplicate epoch 225 extractor profile"
            );
            continue;
        }
        let profile = match name {
            singleton207::UNIT => legacy_profile(name, 207, IID207)?,
            first_root233::UNIT => {
                let p = first_root233
                    .remove(name)
                    .context("210 JIT first root 233 lacks an authenticated accepted launch")?;
                ensure!(
                    p.owner == name
                        && row["phase"] == "private-known-root-prefix"
                        && row["ordinary_replay_claim"] == false
                        && row["launch_receipt"].as_str() == p.authenticated_launch.path.to_str()
                        && row["launch_receipt_sha256"] == p.authenticated_launch.sha256,
                    "210 JIT first root 233 source or qualification scope changed"
                );
                let mut profile = legacy_profile(name, 233, &p.owner_invocation_id)?;
                profile.registered_first_root233 = Some(p);
                profile
            }
            _ => {
                let p = completed.remove(name).with_context(|| {
                    format!("210 JIT has an unsupported or unregistered accepted owner: {name}")
                })?;
                ensure!(
                    p.owner == name && p.epoch == 209,
                    "210 JIT registered completed peer scope differs"
                );
                GuardProfile {
                    owner: p.owner.clone(),
                    owner_invocation_id: p.owner_invocation_id.clone(),
                    epoch: p.epoch,
                    guard_unit: p.guard_unit.clone(),
                    receipt_directory: p.receipt_directory.clone(),
                    registered_completed: Some(p),
                    registered_extractor: None,
                    registered_first_root233: None,
                }
            }
        };
        ensure!(
            row["epoch"] == profile.epoch
                && owner["InvocationID"] == profile.owner_invocation_id
                && owner["NRestarts"] == "0"
                && owner["ActiveState"] == "active"
                && owner["SubState"] == "running"
                && owner["MainPID"]
                    .as_str()
                    .and_then(|s| s.parse::<u32>().ok())
                    .is_some_and(|p| p > 1)
                && f["unit_census"][name] == *owner
                && found.insert(name.to_owned(), profile).is_none(),
            "210 JIT changed, inactive, omitted or duplicate accepted owner"
        );
    }
    ensure!(
        completed.is_empty() && first_root233.is_empty(),
        "210 JIT peer selection omitted an authenticated owner"
    );
    // Keep positively live raw owners visible even if a malformed active roster
    // omits them. All remaining global live-competitor checks run in the core.
    for (name, owner) in f["unit_census"]
        .as_object()
        .context("210 JIT raw accepted census missing")?
    {
        if (name == singleton207::UNIT
            || name.starts_with("horizon-qualify-233-first-root-")
            || name.starts_with("horizon-qualify-225-prefix-extract-")
            || name.starts_with("horizon-qualify-209-generic-"))
            && diagnostic_stage_running(owner)
        {
            ensure!(
                found.contains_key(name),
                "210 JIT complete roster omits a live supported owner"
            );
        }
    }
    Ok(found)
}
fn roster(
    f: &Value,
    handoff: &terminal225_peer::Profile,
) -> Result<BTreeMap<String, GuardProfile>> {
    roster_with_closed(
        f,
        handoff,
        completed_archive_phase::peer_guard_selection_profiles(f)?,
        prefix223_live_peer::first_root233_guard_selection_profiles(f)?,
    )
}
#[cfg(test)]
fn roster_with(
    f: &Value,
    handoff: &terminal225_peer::Profile,
    completed: BTreeMap<String, completed_archive_phase::GuardSelectionProfile>,
) -> Result<BTreeMap<String, GuardProfile>> {
    roster_with_closed(f, handoff, completed, BTreeMap::new())
}
fn ordinary_spec(r: &Request, guards: BTreeMap<String, BoundFile>) -> Spec {
    Spec {
        schema: "jetstreamer-private-epoch210-singleton-admission-spec-v1".into(),
        resource_basis: json!({"observer":r.observer,"fleet":r.fleet,"protected_guards":guards,
            "epoch225_handoff":r.epoch225_handoff}),
        resource_plan: r.resource_plan.clone(),
        capability: r.capability.clone(),
        native_input: r.native_input.clone(),
        output: r.output_directory.join("admission.json"),
    }
}
fn selected_shape(
    profile: &GuardProfile,
    selected: &Value,
    receipt: &Value,
    minimum: u64,
    at: u64,
) -> Result<()> {
    let owner = profile.owner.as_str();
    let guard = profile.guard_unit.as_str();
    let directory = profile.receipt_directory.as_path();
    let binding: BoundFile = serde_json::from_value(selected["binding"].clone())?;
    let iid = receipt["guard_invocation_id"]
        .as_str()
        .context("210 JIT guard IID missing")?;
    ensure!(
        is_lower_hex(iid, 32)
            && receipt["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && binding.path == Path::new(directory).join(format!("sample-{iid}.json"))
            && selected["history"]["unit"] == guard
            && selected["history"]["guard_invocation_id"] == iid
            && receipt["producer"]["cgroup"] == format!("/system.slice/{owner}")
            && receipt["producer"]["restarts"] == 0
            && receipt["producer"]["active"] == "active"
            && receipt["producer"]["sub"] == "running"
            && receipt.get("trip_reason").is_some_and(Value::is_null)
            && receipt
                .get("worker_observation_error")
                .is_some_and(Value::is_null)
            && receipt["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|n| n >= minimum && n <= at && at - n <= 1800),
        "210 JIT selected guard is foreign, failed, stale or replaced"
    );
    let expected_iid = profile.owner_invocation_id.as_str();
    ensure!(
        receipt["producer_invocation_id"] == expected_iid
            && receipt["producer"]["invocation_id"] == expected_iid,
        "210 JIT guard belongs to a replaced producer"
    );
    if let Some(p) = &profile.registered_completed {
        ensure!(
            receipt["plan"] == serde_json::to_value(&p.guard_plan.path)?
                && receipt["plan_sha256"] == p.guard_plan.sha256
                && receipt["guard_sha256"] == p.guard_sha256,
            "210 JIT completed guard changed its authenticated plan or executable"
        );
    }
    if let Some(x) = &profile.registered_extractor {
        ensure!(
            receipt["plan"] == serde_json::to_value(&x.guard_plan.path)?
                && receipt["plan_sha256"] == x.guard_plan.sha256
                && receipt["guard_sha256"] == x.guard_sha256,
            "210 JIT extractor guard changed its admitted plan or executable"
        );
    }
    if let Some(p) = &profile.registered_first_root233 {
        ensure!(
            profile.owner == first_root233::UNIT
                && profile.epoch == 233
                && profile.guard_unit == first_root233::PROTECTIVE
                && profile.receipt_directory == Path::new(first_root233::GUARD_RECEIPTS)
                && receipt["plan"] == serde_json::to_value(&p.guard_plan.path)?
                && receipt["plan_sha256"] == p.guard_plan.sha256
                && receipt["guard_sha256"] == first_root233::GUARD_SHA,
            "210 JIT first root 233 guard changed its exact authenticated plan or executable"
        );
    }
    // Preserve the exact existing per-generation validators in ordinary capacity;
    // the historical epoch 225 guard must not be forced into a newer payload schema.
    Ok(())
}
fn selected_scope(
    profile: &GuardProfile,
    selected: &Value,
    receipt: &Value,
    minimum: u64,
    at: u64,
) -> Result<()> {
    selected_shape(profile, selected, receipt, minimum, at)?;
    warmup223::validate_completed_guard_history(&selected["history"], receipt)
}
fn denied() -> Value {
    json!({"replay_launch_authorized":false,"runtime_promotion_authorized":false,"full_epoch_qualified":false,
        "canonical_sidecar_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false})
}
pub(super) struct Attempt {
    request: BoundFile,
    effective: BoundFile,
    selections: BoundFile,
    initial: Value,
    role: issuer::Role,
    observer: BoundFile,
    fleet: BoundFile,
    epoch225_handoff: BoundFile,
    output_directory: PathBuf,
}
impl Attempt {
    pub(super) fn before_commit(
        &self,
        s: &Spec,
        effective: &BoundFile,
        self_sha: &str,
    ) -> Result<Value> {
        ensure!(
            *effective == self.effective
                && s.output == self.output_directory.join("admission.json")
                && s.resource_basis["observer"] == private157::binding(&self.observer)
                && s.resource_basis["fleet"] == private157::binding(&self.fleet),
            "210 JIT proof borrowed by another admission context"
        );
        native210::immutable_json(&self.request)?;
        let saved: Spec = serde_json::from_value(native210::immutable_json(&self.effective)?)?;
        ensure!(
            serde_json::to_value(&saved)? == serde_json::to_value(s)?,
            "210 JIT effective ordinary spec changed"
        );
        let selections = native210::immutable_json(&self.selections)?;
        ensure!(
            selections["protected_guards"] == s.resource_basis["protected_guards"],
            "210 JIT selections changed effective guard roster"
        );
        let o = bound_json(&self.observer)?;
        let minimum = utc_seconds(
            o["recorded_at_utc"]
                .as_str()
                .context("210 JIT observer time missing at commit")?,
        )?;
        let accepted = assembly204_recovery::accepted_context(&self.fleet, &self.observer)?;
        let handoff = terminal225_peer::Profile::load(&self.epoch225_handoff, &accepted)?;
        let profiles = roster(&accepted, &handoff)?;
        ensure!(
            selections["profiles"] == serde_json::to_value(&profiles)?,
            "210 JIT selected profile roster changed"
        );
        for row in selections["proofs"]
            .as_array()
            .context("210 JIT complete chosen proofs missing")?
        {
            let evidence: BoundFile = serde_json::from_value(row["evidence"].clone())?;
            let proof = native210::immutable_json(&evidence)?;
            let owner = row["owner"]
                .as_str()
                .context("210 JIT chosen owner missing")?;
            ensure!(
                proof["owner"] == owner
                    && proof["selected"]["binding"] == row["binding"]
                    && row["binding"] == selections["protected_guards"][owner],
                "210 JIT complete selected proof changed"
            );
            let profile = profiles
                .get(owner)
                .context("210 JIT selected profile was omitted")?;
            ensure!(
                proof["profile"] == serde_json::to_value(profile)?,
                "210 JIT selected profile provenance changed"
            );
            selected_scope(
                profile,
                &proof["selected"],
                &proof["receipt"],
                minimum,
                now()?,
            )?;
        }
        let f = assembly204_recovery::accepted_context(&self.fleet, &self.observer)?;
        let handoff = terminal225_peer::Profile::load(&self.epoch225_handoff, &f)?;
        roster(&f, &handoff)?;
        let current =
            issuer::snapshot(&self.role, &self.request, self_sha, &self.output_directory)?;
        issuer::same(&self.initial, &current)?;
        Ok(
            json!({"schema":"jetstreamer-full210-jit-admission-provenance-v1","request":self.request,
            "effective_spec":self.effective,"selected_guard_evidence":self.selections,"issuer_before":self.initial,
            "issuer_before_commit":current,"same_process":true,"independent_source_validation_skipped":false,"authority":denied()}),
        )
    }
}
fn bind_written(path: &Path, v: &Value) -> Result<BoundFile> {
    private157::immutable_receipt(path, v)?;
    Ok(serde_json::from_value(private157::file_binding(path)?)?)
}
pub(super) fn run() -> Result<()> {
    let (binding, self_sha) = publication203::parsed_args("admit-singleton210-jit")?;
    let r: Request = serde_json::from_value(native210::immutable_json(&binding)?)?;
    scope(&r)?;
    let mut progress = crate::operation_progress::ProgressLog::new(
        "full210-jit-admission",
        210,
        "issuer-validation",
    );
    let mut phase = "issuer-validation";
    let outcome = (|| -> Result<()> {
        let initial = issuer::snapshot(&r.issuer, &binding, &self_sha, &r.output_directory)?;
        bind_written(
            &r.output_directory.join("issuer-initial.json"),
            &json!({"request":binding,"issuer":initial,"authority":denied()}),
        )?;
        let f = assembly204_recovery::accepted_context(&r.fleet, &r.observer)?;
        let handoff = terminal225_peer::Profile::load(&r.epoch225_handoff, &f)?;
        let initial_profiles = roster(&f, &handoff)?;
        let o = bound_json(&r.observer)?;
        memory(&o)?;
        let minimum = utc_seconds(
            o["recorded_at_utc"]
                .as_str()
                .context("210 JIT coordinated sample time absent")?,
        )?;
        phase = "independent-input-validation";
        progress.phase(phase);
        let mut s = ordinary_spec(&r, BTreeMap::new());
        // This is the same original capability, native, snapshot, node, worker,
        // preflight, genesis and resource-plan validation used by ordinary run.
        // The returned token has no deserializer or caller-controlled success.
        let inputs = validate_inputs(&s)?;
        phase = "preselection-native-custody";
        progress.phase(phase);
        inputs.revalidate(&s)?;
        let current = issuer::snapshot(&r.issuer, &binding, &self_sha, &r.output_directory)?;
        issuer::same(&initial, &current)?;
        ensure!(
            assembly204_recovery::accepted_context(&r.fleet, &r.observer)? == f,
            "210 JIT accepted context changed before selection"
        );
        let profiles = roster(&f, &handoff)?;
        ensure!(
            profiles == initial_profiles,
            "210 JIT supported peer profiles changed before intrinsic selection"
        );
        phase = "intrinsic-guard-selection";
        progress.phase(phase);
        let mut guards = BTreeMap::new();
        let mut chosen = Vec::new();
        for (owner, profile) in &profiles {
            let at = now()?;
            let selected = warmup223::completed_guard_binding(
                &profile.guard_unit,
                &profile.receipt_directory,
                minimum,
                at,
            )?;
            let b: BoundFile = serde_json::from_value(selected["binding"].clone())?;
            let receipt = bound_json(&b)?;
            selected_scope(profile, &selected, &receipt, minimum, at)?;
            let proof = json!({"owner":owner,"profile":profile,"selected":selected,"receipt":receipt,"authority":denied()});
            let saved = bind_written(
                &r.output_directory
                    .join(format!("selected-{}.json", profile.epoch)),
                &proof,
            )?;
            chosen.push(json!({"evidence":saved,"owner":owner,"binding":b}));
            ensure!(
                guards.insert(owner.clone(), b).is_none(),
                "210 JIT duplicate intrinsic guard selection"
            );
        }
        s.resource_basis["protected_guards"] = serde_json::to_value(&guards)?;
        inputs.revalidate(&s)?;
        let selections = bind_written(
            &r.output_directory.join("selected-guards.json"),
            &json!({"schema":"jetstreamer-full210-jit-selected-guards-v1",
            "request":binding,"protected_guards":guards,"profiles":profiles,"proofs":chosen,"authority":denied()}),
        )?;
        let effective = bind_written(
            &r.output_directory.join("effective-spec.json"),
            &serde_json::to_value(&s)?,
        )?;
        let attempt = Attempt {
            request: binding.clone(),
            effective: effective.clone(),
            selections,
            initial,
            role: r.issuer.clone(),
            observer: r.observer.clone(),
            fleet: r.fleet.clone(),
            epoch225_handoff: r.epoch225_handoff.clone(),
            output_directory: r.output_directory.clone(),
        };
        phase = "complete-ordinary-admission";
        progress.phase(phase);
        // Direct invocation in this exact root process. No exec, external seal,
        // message, source-body rehash or timer operation intervenes here.
        admit_validated(&s, &effective, &self_sha, &inputs, Some(&attempt))
    })();
    let result = json!({"schema":"jetstreamer-full210-jit-attempt-result-v1","request":binding,"helper_sha256":self_sha,
        "admission_passed":outcome.is_ok(),"last_phase":phase,"error":outcome.as_ref().err().map(|e|format!("{e:#}")),
        "same_process_pid":std::process::id(),"recorded_unix_seconds":now()?,"no_automatic_retry":true,"authority":denied()});
    let persisted = bind_written(&r.output_directory.join("attempt-result.json"), &result);
    progress.finish(outcome.is_ok() && persisted.is_ok());
    match (outcome,persisted) {
        (Ok(()),Ok(_))=>Ok(()),(Err(error),Ok(_))=>Err(error),
        (Ok(()),Err(error))=>Err(error.context("210 JIT admission passed but result persistence failed; preserve exact admission and attempt")),
        (Err(error),Err(persist))=>Err(error.context(format!("210 JIT failure evidence also failed: {persist:#}"))),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn row(epoch: u64, name: &str, iid: &str) -> Value {
        json!({"epoch":epoch,"producer":{"Id":name,"InvocationID":iid,"NRestarts":"0","ActiveState":"active","SubState":"running","MainPID":"42"}})
    }
    #[test]
    fn full210_jit_accepts_only_authenticated_first_root233_and_retains_the_complete_census() {
        let (row, authenticated) = prefix223_live_peer::first_root233_fixture();
        let handoff = terminal225_peer::fixture_terminal_profile();
        let old = self::row(207, singleton207::UNIT, IID207);
        let mut f = terminal225_peer::fixture_terminal_fleet(vec![old.clone(), row.clone()]);
        f["unit_census"][singleton207::UNIT] = old["producer"].clone();
        f["unit_census"][first_root233::UNIT] = row["producer"].clone();
        let source = BTreeMap::from([(first_root233::UNIT.into(), authenticated.clone())]);
        let before = f.clone();
        let profiles = roster_with_closed(&f, &handoff, BTreeMap::new(), source.clone()).unwrap();
        assert_eq!(profiles.len(), 2);
        assert!(profiles.contains_key(singleton207::UNIT));
        let chosen = &profiles[first_root233::UNIT];
        assert_eq!(chosen.epoch, 233);
        assert_eq!(
            chosen.owner_invocation_id,
            authenticated.owner_invocation_id
        );
        assert_eq!(chosen.guard_unit, first_root233::PROTECTIVE);
        assert_eq!(
            chosen.receipt_directory,
            Path::new(first_root233::GUARD_RECEIPTS)
        );
        assert!(chosen.registered_completed.is_none());
        assert!(chosen.registered_extractor.is_none());
        assert!(chosen.registered_first_root233.is_some());
        assert_eq!(f, before);
        assert!(roster_with_closed(&f, &handoff, BTreeMap::new(), BTreeMap::new()).is_err());
        let mut missing = f.clone();
        missing["active"].as_array_mut().unwrap().pop();
        assert!(roster_with_closed(&missing, &handoff, BTreeMap::new(), source.clone()).is_err());
        // Even an omitted provider must not hide a positively live raw owner.
        assert!(roster_with_closed(&missing, &handoff, BTreeMap::new(), BTreeMap::new()).is_err());
        let mut duplicate = f.clone();
        duplicate["active"]
            .as_array_mut()
            .unwrap()
            .push(row.clone());
        assert!(roster_with_closed(&duplicate, &handoff, BTreeMap::new(), source.clone()).is_err());
        let mut omitted_raw = f.clone();
        omitted_raw["unit_census"]
            .as_object_mut()
            .unwrap()
            .remove(first_root233::UNIT);
        assert!(
            roster_with_closed(&omitted_raw, &handoff, BTreeMap::new(), source.clone()).is_err()
        );
        for pointer in [
            "/producer/InvocationID",
            "/producer/NRestarts",
            "/producer/MainPID",
            "/producer/ActiveState",
            "/launch_receipt_sha256",
            "/launch_receipt",
            "/phase",
            "/ordinary_replay_claim",
            "/epoch",
        ] {
            let mut changed = f.clone();
            *changed["active"][1].pointer_mut(pointer).unwrap() = Value::Null;
            assert!(
                roster_with_closed(&changed, &handoff, BTreeMap::new(), source.clone()).is_err(),
                "{pointer}"
            );
        }
        // Synchronizing the forged roster and raw census still cannot replace
        // the invocation authenticated by the accepted claim and launch.
        let mut replaced = f.clone();
        replaced["active"][1]["producer"]["InvocationID"] = json!("e".repeat(32));
        replaced["unit_census"][first_root233::UNIT] = replaced["active"][1]["producer"].clone();
        assert!(roster_with_closed(&replaced, &handoff, BTreeMap::new(), source.clone()).is_err());
        let mut foreign = source;
        foreign.get_mut(first_root233::UNIT).unwrap().owner = "foreign.service".into();
        assert!(roster_with_closed(&f, &handoff, BTreeMap::new(), foreign).is_err());
    }

    #[test]
    fn full210_jit_first_root233_cannot_hide_unregistered_live_generations() {
        let handoff = terminal225_peer::fixture_terminal_profile();
        let f = terminal225_peer::fixture_terminal_fleet(vec![]);
        for name in [
            first_root233::UNIT,
            "horizon-qualify-233-first-root-foreign.service",
        ] {
            let raw = self::row(233, name, &"e".repeat(32));
            let mut hidden = f.clone();
            hidden["unit_census"][name] = raw["producer"].clone();
            assert!(
                roster_with_closed(&hidden, &handoff, BTreeMap::new(), BTreeMap::new()).is_err()
            );
            hidden["active"].as_array_mut().unwrap().push(raw);
            assert!(
                roster_with_closed(&hidden, &handoff, BTreeMap::new(), BTreeMap::new()).is_err()
            );
        }
    }

    #[test]
    fn full210_jit_first_root233_selection_binds_its_exact_guard_plan_executable_and_owner() {
        let (row, p) = prefix223_live_peer::first_root233_fixture();
        let handoff = terminal225_peer::fixture_terminal_profile();
        let mut f = terminal225_peer::fixture_terminal_fleet(vec![row.clone()]);
        f["unit_census"][first_root233::UNIT] = row["producer"].clone();
        let profiles = roster_with_closed(
            &f,
            &handoff,
            BTreeMap::new(),
            BTreeMap::from([(p.owner.clone(), p.clone())]),
        )
        .unwrap();
        let profile = &profiles[first_root233::UNIT];
        let iid = "a".repeat(32);
        let selected = json!({"binding":{"path":Path::new(first_root233::GUARD_RECEIPTS).join(format!("sample-{iid}.json")),"sha256":"b".repeat(64)},
            "history":{"unit":first_root233::PROTECTIVE,"guard_invocation_id":iid}});
        let receipt = json!({"schema":"jetstreamer-horizon-standalone-guard-sample-v1","guard_invocation_id":iid,
            "producer_invocation_id":p.owner_invocation_id,"producer":{"cgroup":format!("/system.slice/{}",p.owner),
            "invocation_id":p.owner_invocation_id,"restarts":0,"active":"active","sub":"running"},
            "recorded_unix_seconds":1000,"trip_reason":null,"worker_observation_error":null,
            "plan":p.guard_plan.path,"plan_sha256":p.guard_plan.sha256,"guard_sha256":first_root233::GUARD_SHA});
        selected_shape(profile, &selected, &receipt, 900, 1000).unwrap();
        for pointer in [
            "/guard_sha256",
            "/plan",
            "/plan_sha256",
            "/producer_invocation_id",
            "/producer/invocation_id",
        ] {
            let mut bad = receipt.clone();
            *bad.pointer_mut(pointer).unwrap() = Value::Null;
            assert!(
                selected_shape(profile, &selected, &bad, 900, 1000).is_err(),
                "{pointer}"
            );
        }
        let mut wrong = selected.clone();
        wrong["history"]["unit"] = json!(singleton207::PROTECTIVE);
        assert!(selected_shape(profile, &wrong, &receipt, 900, 1000).is_err());
        let mut wrong = selected.clone();
        wrong["binding"]["path"] = json!("/foreign/sample.json");
        assert!(selected_shape(profile, &wrong, &receipt, 900, 1000).is_err());
        assert!(selected_shape(profile, &selected, &receipt, 1001, 1001).is_err());
        assert!(selected_shape(profile, &selected, &receipt, 900, 2801).is_err());
        assert!(
            selected_scope(profile, &selected, &receipt, 900, 1000).is_err(),
            "asserted history still needs genuine completed-fire evidence"
        );
    }
    #[test]
    fn full210_jit_roster_cannot_omit_duplicate_replace_or_add_a_live_owner() {
        let a = row(207, singleton207::UNIT, IID207);
        let handoff = terminal225_peer::fixture_terminal_profile();
        let mut f = terminal225_peer::fixture_terminal_fleet(vec![a.clone()]);
        f["unit_census"][singleton207::UNIT] = a["producer"].clone();
        roster_with(&f, &handoff, BTreeMap::new()).unwrap();
        let mut missing = f.clone();
        missing["active"].as_array_mut().unwrap().pop();
        assert!(roster_with(&missing, &handoff, BTreeMap::new()).is_err());
        let mut duplicate = f.clone();
        duplicate["active"]
            .as_array_mut()
            .unwrap()
            .push(f["active"][0].clone());
        assert!(roster_with(&duplicate, &handoff, BTreeMap::new()).is_err());
        let mut changed = f.clone();
        changed["active"][0]["producer"]["InvocationID"] = json!("a".repeat(32));
        assert!(roster_with(&changed, &handoff, BTreeMap::new()).is_err());
        let mut competitor = f;
        competitor["active"].as_array_mut().unwrap().push(row(
            209,
            "horizon-qualify-209-generic-full-v7.service",
            &"b".repeat(32),
        ));
        assert!(roster_with(&competitor, &handoff, BTreeMap::new()).is_err());
    }
    #[test]
    fn full210_jit_roster_uses_authenticated_completed209_profile_without_omitting_legacy_peers() {
        let name = "horizon-qualify-209-generic-full-v7.service";
        let iid = "b".repeat(32);
        let a = row(207, singleton207::UNIT, IID207);
        let c = row(209, name, &iid);
        let handoff = terminal225_peer::fixture_terminal_profile();
        let mut f = terminal225_peer::fixture_terminal_fleet(vec![a.clone(), c.clone()]);
        f["unit_census"][singleton207::UNIT] = a["producer"].clone();
        f["unit_census"][name] = c["producer"].clone();
        let profile = completed_archive_phase::GuardSelectionProfile {
            owner: name.into(),
            owner_invocation_id: iid,
            epoch: 209,
            guard_unit: "horizon-generic209-full-protective-v7.service".into(),
            receipt_directory: "/var/lib/jetstreamer/horizon-generic209-full-guard-receipts-v7"
                .into(),
            guard_plan: BoundFile {
                path: "/sealed/guard-plan.json".into(),
                sha256: "c".repeat(64),
            },
            guard_sha256: "d".repeat(64),
            authenticated_launch: BoundFile {
                path: "/sealed/launch.json".into(),
                sha256: "e".repeat(64),
            },
        };
        let provider = BTreeMap::from([(name.into(), profile.clone())]);
        let profiles = roster_with(&f, &handoff, provider.clone()).unwrap();
        assert_eq!(profiles.len(), 2);
        assert!(profiles.contains_key(singleton207::UNIT));
        assert_eq!(
            profiles[name]
                .registered_completed
                .as_ref()
                .unwrap()
                .guard_plan,
            profile.guard_plan
        );
        assert!(roster_with(&f, &handoff, BTreeMap::new()).is_err());
        let mut missing = f.clone();
        missing["active"].as_array_mut().unwrap().remove(0);
        assert!(roster_with(&missing, &handoff, provider.clone()).is_err());
        let mut replaced = f.clone();
        replaced["active"][1]["producer"]["InvocationID"] = json!("f".repeat(32));
        assert!(roster_with(&replaced, &handoff, provider.clone()).is_err());
        let mut foreign = provider;
        foreign.get_mut(name).unwrap().owner = "other.service".into();
        assert!(roster_with(&f, &handoff, foreign).is_err());
    }
    #[test]
    fn full210_jit_selection_rejects_foreign_stale_tripped_and_replaced_guard() {
        let profile = legacy_profile(singleton207::UNIT, 207, IID207).unwrap();
        let iid = "a".repeat(32);
        let (guard, dir) =
            prefix223_native20_admission::guard_selector(singleton207::UNIT).unwrap();
        let selected = json!({"binding":{"path":Path::new(dir).join(format!("sample-{iid}.json")),"sha256":"b".repeat(64)},
            "history":{"unit":guard,"guard_invocation_id":iid}});
        let receipt = json!({"schema":"jetstreamer-horizon-standalone-guard-sample-v1","guard_invocation_id":iid,
            "producer_invocation_id":IID207,"producer":{"cgroup":format!("/system.slice/{}",singleton207::UNIT),
            "invocation_id":IID207,"restarts":0,"active":"active","sub":"running"},"recorded_unix_seconds":1000,
            "trip_reason":null,"worker_observation_error":null});
        selected_shape(&profile, &selected, &receipt, 900, 1000).unwrap();
        for (path, value) in [
            ("/guard_invocation_id", json!("c".repeat(32))),
            ("/recorded_unix_seconds", json!(899)),
            ("/producer/invocation_id", json!("d".repeat(32))),
            ("/trip_reason", json!("disk-floor")),
            ("/worker_observation_error", json!("not observed")),
            ("/producer/restarts", json!(1)),
            ("/producer/active", json!("failed")),
        ] {
            let mut changed = receipt.clone();
            *changed.pointer_mut(path).unwrap() = value;
            assert!(
                selected_shape(&profile, &selected, &changed, 900, 1000).is_err(),
                "{path}"
            );
        }
        assert!(selected_shape(&profile, &selected, &receipt, 900, 2801).is_err());
        let mut foreign = selected.clone();
        foreign["binding"]["path"] = json!("/var/lib/jetstreamer/foreign/sample.json");
        assert!(selected_shape(&profile, &foreign, &receipt, 900, 1000).is_err());
        assert!(
            selected_scope(&profile, &selected, &receipt, 900, 1000).is_err(),
            "asserted history without genuine Started/stdout/Finished must never pass"
        );
    }
    #[test]
    fn full210_jit_wire_cannot_import_guard_choices_skip_checks_or_gain_authority() {
        let binding = json!({"path":"/sealed/input","sha256":"a".repeat(64)});
        let mut request = json!({"schema":"jetstreamer-full210-jit-admission-spec-v1","observer":binding,"fleet":binding,
            "epoch225_handoff":binding,"resource_plan":binding,"capability":binding,"native_input":binding,"issuer":{"unit":"horizon-capacity210-jit-test.service",
            "fragment":"/etc/systemd/system/horizon-capacity210-jit-test.service","runner":binding,"deployment_seal":binding,"qualification":binding},"output_directory":"/var/lib/jetstreamer/horizon-210-singleton-admission-test"});
        assert!(serde_json::from_value::<Request>(request.clone()).is_ok());
        for key in [
            "protected_guards",
            "ignore_peer",
            "skip_inputs",
            "native_input_validated",
            "launch",
            "retry",
        ] {
            request[key] = json!(true);
            assert!(serde_json::from_value::<Request>(request.clone()).is_err());
            request.as_object_mut().unwrap().remove(key);
        }
        let authority = denied();
        for key in [
            "replay_launch_authorized",
            "runtime_promotion_authorized",
            "full_epoch_qualified",
            "canonical_sidecar_authorized",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            assert_eq!(authority[key], false);
        }
    }
}
