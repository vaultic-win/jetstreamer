//! Same-process Full 210 JIT issuer. All expensive independent input checks
//! precede intrinsic guard selection; ordinary complete admission is unchanged.
use super::*;
mod issuer;
mod qualification;
const OWNER225: &str = "horizon-qualify-225-natural-root-resource-shrink-budget-2f856bd-v1.service";
const IID207: &str = "74eb420ca4574a50a35913d1417124f1";
const IID225: &str = "4cd76ae1353a4411885b997f04306402";
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
    })
}
fn roster_with(
    f: &Value,
    mut completed: BTreeMap<String, completed_archive_phase::GuardSelectionProfile>,
) -> Result<BTreeMap<String, GuardProfile>> {
    let mut found = BTreeMap::new();
    for row in f["active"]
        .as_array()
        .context("210 JIT complete accepted roster absent")?
    {
        let owner = singleton227_admission::active_owner(row)?;
        let name = owner["Id"]
            .as_str()
            .context("210 JIT accepted owner name absent")?;
        let profile = match name {
            singleton207::UNIT => legacy_profile(name, 207, IID207)?,
            OWNER225 => legacy_profile(name, 225, IID225)?,
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
        completed.is_empty(),
        "210 JIT completed peer selection omitted an authenticated owner"
    );
    // Keep positively live raw owners visible even if a malformed active roster
    // omits them. All remaining global live-competitor checks run in the core.
    for (name, owner) in f["unit_census"]
        .as_object()
        .context("210 JIT raw accepted census missing")?
    {
        if (matches!(name.as_str(), singleton207::UNIT | OWNER225)
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
fn roster(f: &Value) -> Result<BTreeMap<String, GuardProfile>> {
    roster_with(
        f,
        completed_archive_phase::peer_guard_selection_profiles(f)?,
    )
}
fn ordinary_spec(r: &Request, guards: BTreeMap<String, BoundFile>) -> Spec {
    Spec {
        schema: "jetstreamer-private-epoch210-singleton-admission-spec-v1".into(),
        resource_basis: json!({"observer":r.observer,"fleet":r.fleet,"protected_guards":guards}),
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
    // Preserve the exact existing per-generation validators in ordinary capacity;
    // the historical 225 guard must not be forced into a newer payload schema.
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
        let profiles = roster(&assembly204_recovery::accepted_context(
            &self.fleet,
            &self.observer,
        )?)?;
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
        roster(&f)?;
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
    let mut phase = "issuer-validation";
    let outcome = (|| -> Result<()> {
        let initial = issuer::snapshot(&r.issuer, &binding, &self_sha, &r.output_directory)?;
        bind_written(
            &r.output_directory.join("issuer-initial.json"),
            &json!({"request":binding,"issuer":initial,"authority":denied()}),
        )?;
        let f = assembly204_recovery::accepted_context(&r.fleet, &r.observer)?;
        let initial_profiles = roster(&f)?;
        let o = bound_json(&r.observer)?;
        memory(&o)?;
        let minimum = utc_seconds(
            o["recorded_at_utc"]
                .as_str()
                .context("210 JIT coordinated sample time absent")?,
        )?;
        phase = "independent-input-validation";
        let mut s = ordinary_spec(&r, BTreeMap::new());
        // This is the same original capability, native, snapshot, node, worker,
        // preflight, genesis and resource-plan validation used by ordinary run.
        // The returned token has no deserializer or caller-controlled success.
        let inputs = validate_inputs(&s)?;
        phase = "preselection-native-custody";
        inputs.revalidate(&s)?;
        let current = issuer::snapshot(&r.issuer, &binding, &self_sha, &r.output_directory)?;
        issuer::same(&initial, &current)?;
        ensure!(
            assembly204_recovery::accepted_context(&r.fleet, &r.observer)? == f,
            "210 JIT accepted context changed before selection"
        );
        let profiles = roster(&f)?;
        ensure!(
            profiles == initial_profiles,
            "210 JIT supported peer profiles changed before intrinsic selection"
        );
        phase = "intrinsic-guard-selection";
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
            output_directory: r.output_directory.clone(),
        };
        phase = "complete-ordinary-admission";
        // Direct invocation in this exact root process. No exec, external seal,
        // message, source-body rehash or timer operation intervenes here.
        admit_validated(&s, &effective, &self_sha, &inputs, Some(&attempt))
    })();
    let result = json!({"schema":"jetstreamer-full210-jit-attempt-result-v1","request":binding,"helper_sha256":self_sha,
        "admission_passed":outcome.is_ok(),"last_phase":phase,"error":outcome.as_ref().err().map(|e|format!("{e:#}")),
        "same_process_pid":std::process::id(),"recorded_unix_seconds":now()?,"no_automatic_retry":true,"authority":denied()});
    let persisted = bind_written(&r.output_directory.join("attempt-result.json"), &result);
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
    fn full210_jit_roster_cannot_omit_duplicate_replace_or_add_a_live_owner() {
        let a = row(207, singleton207::UNIT, IID207);
        let b = row(225, OWNER225, IID225);
        let f = json!({"active":[a,b],"unit_census":{singleton207::UNIT:a["producer"],OWNER225:b["producer"]}});
        roster_with(&f, BTreeMap::new()).unwrap();
        let mut missing = f.clone();
        missing["active"].as_array_mut().unwrap().pop();
        assert!(roster_with(&missing, BTreeMap::new()).is_err());
        let mut duplicate = f.clone();
        duplicate["active"]
            .as_array_mut()
            .unwrap()
            .push(f["active"][0].clone());
        assert!(roster_with(&duplicate, BTreeMap::new()).is_err());
        let mut changed = f.clone();
        changed["active"][0]["producer"]["InvocationID"] = json!("a".repeat(32));
        assert!(roster_with(&changed, BTreeMap::new()).is_err());
        let mut competitor = f;
        competitor["active"].as_array_mut().unwrap().push(row(
            209,
            "horizon-qualify-209-generic-full-v7.service",
            &"b".repeat(32),
        ));
        assert!(roster_with(&competitor, BTreeMap::new()).is_err());
    }
    #[test]
    fn full210_jit_roster_uses_authenticated_completed209_profile_without_omitting_legacy_peers() {
        let name = "horizon-qualify-209-generic-full-v7.service";
        let iid = "b".repeat(32);
        let a = row(207, singleton207::UNIT, IID207);
        let b = row(225, OWNER225, IID225);
        let c = row(209, name, &iid);
        let f = json!({"active":[a,b,c],"unit_census":{singleton207::UNIT:a["producer"],OWNER225:b["producer"],name:c["producer"]}});
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
        let profiles = roster_with(&f, provider.clone()).unwrap();
        assert_eq!(profiles.len(), 3);
        assert!(profiles.contains_key(singleton207::UNIT) && profiles.contains_key(OWNER225));
        assert_eq!(
            profiles[name]
                .registered_completed
                .as_ref()
                .unwrap()
                .guard_plan,
            profile.guard_plan
        );
        assert!(roster_with(&f, BTreeMap::new()).is_err());
        let mut missing = f.clone();
        missing["active"].as_array_mut().unwrap().remove(0);
        assert!(roster_with(&missing, provider.clone()).is_err());
        let mut replaced = f.clone();
        replaced["active"][2]["producer"]["InvocationID"] = json!("f".repeat(32));
        assert!(roster_with(&replaced, provider.clone()).is_err());
        let mut foreign = provider;
        foreign.get_mut(name).unwrap().owner = "other.service".into();
        assert!(roster_with(&f, foreign).is_err());
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
            "resource_plan":binding,"capability":binding,"native_input":binding,"issuer":{"unit":"horizon-capacity210-jit-test.service",
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
