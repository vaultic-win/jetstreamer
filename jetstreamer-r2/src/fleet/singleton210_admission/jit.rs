//! Same-process Full 210 JIT issuer. All expensive independent input checks
//! precede intrinsic guard selection; ordinary complete admission is unchanged.
use super::*;
mod issuer;
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
fn roster(f: &Value) -> Result<()> {
    let mut found = BTreeMap::new();
    for row in f["active"]
        .as_array()
        .context("210 JIT complete accepted roster absent")?
    {
        let owner = singleton227_admission::active_owner(row)?;
        let name = owner["Id"]
            .as_str()
            .context("210 JIT accepted owner name absent")?;
        let (epoch, iid) = match name {
            singleton207::UNIT => (207, IID207),
            OWNER225 => (225, IID225),
            _ => bail!("210 JIT cannot omit or generalize a newly accepted owner: {name}"),
        };
        ensure!(
            row["epoch"] == epoch
                && owner["InvocationID"] == iid
                && owner["NRestarts"] == "0"
                && owner["ActiveState"] == "active"
                && owner["SubState"] == "running"
                && owner["MainPID"]
                    .as_str()
                    .and_then(|s| s.parse::<u32>().ok())
                    .is_some_and(|p| p > 1)
                && found.insert(name.to_owned(), iid).is_none(),
            "210 JIT changed, inactive or duplicate accepted owner"
        );
    }
    ensure!(
        found.keys().map(String::as_str).collect::<BTreeSet<_>>()
            == BTreeSet::from([singleton207::UNIT, OWNER225]),
        "210 JIT requires the complete exact 207 and 225 owner roster"
    );
    Ok(())
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
    owner: &str,
    selected: &Value,
    receipt: &Value,
    minimum: u64,
    at: u64,
) -> Result<()> {
    let (guard, directory) = prefix223_native20_admission::guard_selector(owner)?;
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
    let expected_iid = if owner == singleton207::UNIT {
        IID207
    } else {
        ensure!(owner == OWNER225, "210 JIT foreign guard owner");
        IID225
    };
    ensure!(
        receipt["producer_invocation_id"] == expected_iid
            && receipt["producer"]["invocation_id"] == expected_iid,
        "210 JIT guard belongs to a replaced producer"
    );
    // Preserve the exact existing per-generation validators in ordinary capacity;
    // the historical 225 guard must not be forced into a newer payload schema.
    Ok(())
}
fn selected_scope(
    owner: &str,
    selected: &Value,
    receipt: &Value,
    minimum: u64,
    at: u64,
) -> Result<()> {
    selected_shape(owner, selected, receipt, minimum, at)?;
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
            selected_scope(
                owner,
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
        roster(&f)?;
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
        roster(&f)?;
        phase = "intrinsic-guard-selection";
        let mut guards = BTreeMap::new();
        let mut chosen = Vec::new();
        for owner in [singleton207::UNIT, OWNER225] {
            let (unit, directory) = prefix223_native20_admission::guard_selector(owner)?;
            let at = now()?;
            let selected =
                warmup223::completed_guard_binding(unit, Path::new(directory), minimum, at)?;
            let b: BoundFile = serde_json::from_value(selected["binding"].clone())?;
            let receipt = bound_json(&b)?;
            selected_scope(owner, &selected, &receipt, minimum, at)?;
            let proof =
                json!({"owner":owner,"selected":selected,"receipt":receipt,"authority":denied()});
            let saved = bind_written(
                &r.output_directory.join(format!(
                    "selected-{}.json",
                    if owner == singleton207::UNIT {
                        207
                    } else {
                        225
                    }
                )),
                &proof,
            )?;
            chosen.push(json!({"evidence":saved,"owner":owner,"binding":b}));
            ensure!(
                guards.insert(owner.into(), b).is_none(),
                "210 JIT duplicate intrinsic guard selection"
            );
        }
        s.resource_basis["protected_guards"] = serde_json::to_value(&guards)?;
        inputs.revalidate(&s)?;
        let selections = bind_written(
            &r.output_directory.join("selected-guards.json"),
            &json!({"schema":"jetstreamer-full210-jit-selected-guards-v1",
            "request":binding,"protected_guards":guards,"proofs":chosen,"authority":denied()}),
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
        let f = json!({"active":[row(207,singleton207::UNIT,IID207),row(225,OWNER225,IID225)]});
        roster(&f).unwrap();
        let mut missing = f.clone();
        missing["active"].as_array_mut().unwrap().pop();
        assert!(roster(&missing).is_err());
        let mut duplicate = f.clone();
        duplicate["active"]
            .as_array_mut()
            .unwrap()
            .push(f["active"][0].clone());
        assert!(roster(&duplicate).is_err());
        let mut changed = f.clone();
        changed["active"][0]["producer"]["InvocationID"] = json!("a".repeat(32));
        assert!(roster(&changed).is_err());
        let mut competitor = f;
        competitor["active"].as_array_mut().unwrap().push(row(
            209,
            "horizon-qualify-209-generic-full-v7.service",
            &"b".repeat(32),
        ));
        assert!(roster(&competitor).is_err());
    }
    #[test]
    fn full210_jit_selection_rejects_foreign_stale_tripped_and_replaced_guard() {
        let iid = "a".repeat(32);
        let (guard, dir) =
            prefix223_native20_admission::guard_selector(singleton207::UNIT).unwrap();
        let selected = json!({"binding":{"path":Path::new(dir).join(format!("sample-{iid}.json")),"sha256":"b".repeat(64)},
            "history":{"unit":guard,"guard_invocation_id":iid}});
        let receipt = json!({"schema":"jetstreamer-horizon-standalone-guard-sample-v1","guard_invocation_id":iid,
            "producer_invocation_id":IID207,"producer":{"cgroup":format!("/system.slice/{}",singleton207::UNIT),
            "invocation_id":IID207,"restarts":0,"active":"active","sub":"running"},"recorded_unix_seconds":1000,
            "trip_reason":null,"worker_observation_error":null});
        selected_shape(singleton207::UNIT, &selected, &receipt, 900, 1000).unwrap();
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
                selected_shape(singleton207::UNIT, &selected, &changed, 900, 1000).is_err(),
                "{path}"
            );
        }
        assert!(selected_shape(singleton207::UNIT, &selected, &receipt, 900, 2801).is_err());
        let mut foreign = selected.clone();
        foreign["binding"]["path"] = json!("/var/lib/jetstreamer/foreign/sample.json");
        assert!(selected_shape(singleton207::UNIT, &foreign, &receipt, 900, 1000).is_err());
        assert!(
            selected_scope(singleton207::UNIT, &selected, &receipt, 900, 1000).is_err(),
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
