//! Distinct 205 policy, sharing only the complete existing host/guard/floor math.
use super::*;
pub(super) fn candidate_with_anchor(
    stage: downstream::Stage,
    bytes: u64,
    anchor_bytes: u64,
) -> Result<maintenance_capacity::Candidate> {
    use downstream::Stage;
    ensure!(
        bytes == BYTES
            && ((stage == Stage::Full && anchor_bytes > 0 && anchor_bytes <= OUTPUT_MAX)
                || (stage != Stage::Full && anchor_bytes == 0)),
        "205 candidate length/anchor scope differs"
    );
    let additional = match stage {
        Stage::Full => bytes
            .checked_add(anchor_bytes)
            .and_then(|n| n.checked_add(128 << 20)),
        Stage::Plugin | Stage::Boundary => Some(128 << 20),
        Stage::Import => bytes.checked_add(128 << 20),
        Stage::Upload => Some(1 << 30),
        Stage::Assembly => {
            bail!("205 private assembly is already complete and is not a delivery candidate")
        }
    }
    .context("205 candidate disk overflow")?;
    Ok(maintenance_capacity::Candidate {
        additional_bytes: additional,
        memory_max_bytes: stage.memory() + (1 << 30),
        minimum_protected_disk_bytes: 0,
    })
}
pub(super) fn stage_capacity(
    basis: &Value,
    stage: downstream::Stage,
    bytes: u64,
    anchor: u64,
) -> Result<Value> {
    let c = candidate_with_anchor(stage, bytes, anchor)?;
    let result = maintenance_capacity::check_continuation205_delivery(basis, c)?;
    validate_capacity(&result, c.memory_max_bytes, c.additional_bytes)?;
    validate_provenance(&result)?;
    Ok(result)
}
pub(super) fn validate_capacity(v: &Value, memory: u64, additional: u64) -> Result<()> {
    assembly204_recovery::validate205_capacity(v, memory, additional)
}
pub(super) fn validate_provenance(v: &Value) -> Result<()> {
    assembly204_recovery::validate_shared_capacity_provenance(v)
}

/// Constructed only by release from its exact immutable stage spec and actual
/// childless waiting process. No JSON candidate exemption is accepted.
pub(in crate::fleet) struct WaitingContext {
    stage: downstream::StageSpec,
    spec: BoundFile,
    waiting: BoundFile,
    expected_process: Value,
}
impl WaitingContext {
    pub(in crate::fleet) fn candidate(&self) -> Result<maintenance_capacity::Candidate> {
        candidate_with_anchor(
            self.stage.stage,
            BYTES,
            downstream::anchor_reserve(&self.stage)?,
        )
    }
    pub(in crate::fleet) fn names(&self) -> Result<BTreeSet<String>> {
        let (guard, _) = startup::capacity_waiter(
            &self.stage,
            &self.spec,
            &self.waiting,
            &self.expected_process,
        )?;
        Ok(BTreeSet::from([self.stage.stage.unit().into(), guard]))
    }
    fn retained_view(
        stage: downstream::Stage,
        guard: &str,
        f: &Value,
        raw: &BTreeMap<String, Value>,
    ) -> Result<BTreeMap<String, Value>> {
        let names = BTreeSet::from([stage.unit().to_owned(), guard.to_owned()]);
        for row in f["active"]
            .as_array()
            .context("205 waiting capacity accepted roster missing")?
        {
            let owner = singleton227_admission::active_owner(row)?;
            ensure!(
                !names.contains(s(owner, "Id")?),
                "205 waiter cannot remove an already accepted owner"
            );
        }
        ensure!(
            f["continuation205_delivery"]
                .as_array()
                .is_none_or(|rows| rows.iter().all(|r| r["live"] != true)),
            "205 waiting release cannot replace an accepted delivery claim"
        );
        let guard_row = raw
            .get(guard)
            .context("205 waiting guard omitted from census")?;
        ensure!(
            guard_row["Id"] == guard
                && guard_row["MainPID"] == "0"
                && guard_row["NRestarts"] == "0"
                && guard_row["ActiveState"] == "inactive"
                && guard_row["SubState"] == "dead"
                && guard_row["Result"] == "success"
                && guard_row["ExecMainStatus"] == "0",
            "205 waiting guard is active/restarted/uncertain"
        );
        let mut view = raw.clone();
        ensure!(
            view.remove(stage.unit()).is_some(),
            "205 waiting candidate omitted from raw census"
        );
        view.remove(guard);
        Ok(view)
    }
    pub(in crate::fleet) fn peer_view(
        &self,
        f: &Value,
        raw: &BTreeMap<String, Value>,
    ) -> Result<(BTreeMap<String, Value>, Value)> {
        let (guard, process) = startup::capacity_waiter(
            &self.stage,
            &self.spec,
            &self.waiting,
            &self.expected_process,
        )?;
        let owner = raw
            .get(self.stage.stage.unit())
            .context("205 waiting owner absent")?;
        let expected_pid = n(&process, "pid")?.to_string();
        ensure!(
            owner["Id"] == self.stage.stage.unit()
                && owner["InvocationID"] == process["invocation_id"]
                && owner["MainPID"].as_str() == Some(expected_pid.as_str())
                && owner["ControlGroup"] == process["cgroup"]
                && owner["NRestarts"] == "0"
                && owner["ActiveState"] == "active"
                && owner["SubState"] == "running",
            "205 waiting raw census disagrees with authenticated native candidate"
        );
        // Prove the raw command against the immutable native argv as well as the
        // native process snapshot, retaining both raw census and process proof.
        let argv = process["argv"]
            .as_array()
            .context("205 waiting native argv absent")?
            .iter()
            .map(|a| a.as_str().context("205 waiting argv is not text"))
            .collect::<Result<Vec<_>>>()?;
        let runner = argv.first().context("205 waiting argv empty")?;
        let display = format!(
            "{{ path={runner} ; argv[]={} ; ignore_errors=no }}",
            argv.join(" ")
        );
        ensure!(
            peer::command_matches(s(owner, "ExecStart")?, &display),
            "205 waiting raw command differs"
        );
        let view = Self::retained_view(self.stage.stage, &guard, f, raw)?;
        let cgroup = capped204205_work::empty_terminal_cgroup(&guard)?;
        let candidate = self.candidate()?;
        Ok((
            view,
            json!({"schema":"jetstreamer-continuation205-childless-waiter-accounting-v1",
            "stage_spec":self.spec,"waiting":self.waiting,"native_process":process,"guard_unit":guard,"guard_cgroup":cgroup,
            "candidate_memory_max_bytes":candidate.memory_max_bytes,"actor_full_hard_cap_bytes":self.stage.stage.memory(),
            "independent_guard_full_hard_cap_bytes":startup::GUARD_MEMORY,"allocation_credit_bytes":0,
            "accepted_owner_removed":false,"raw_fleet_and_census_preserved":true}),
        ))
    }
}
pub(super) fn waiting_stage_capacity(
    basis: &Value,
    stage: &downstream::StageSpec,
    spec: &BoundFile,
    waiting: &BoundFile,
    process: &Value,
) -> Result<Value> {
    let exact = downstream::stage_spec(&read(spec)?)?;
    ensure!(
        serde_json::to_value(&exact)? == serde_json::to_value(stage)?,
        "205 waiting capacity stage spec changed"
    );
    let context = WaitingContext {
        stage: exact,
        spec: spec.clone(),
        waiting: waiting.clone(),
        expected_process: process.clone(),
    };
    let c = context.candidate()?;
    let result = maintenance_capacity::check_continuation205_waiting(basis, &context)?;
    validate_capacity(&result, c.memory_max_bytes, c.additional_bytes)?;
    validate_provenance(&result)?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn waiter_census() -> BTreeMap<String, Value> {
        BTreeMap::from([
            (
                downstream::Stage::Full.unit().into(),
                json!({"Id":downstream::Stage::Full.unit(),"MainPID":"123","InvocationID":"a".repeat(32)}),
            ),
            (
                "horizon-205-delivery-full-protective-v1.service".into(),
                json!({"Id":"horizon-205-delivery-full-protective-v1.service","MainPID":"0","NRestarts":"0","ActiveState":"inactive","SubState":"dead","Result":"success","ExecMainStatus":"0"}),
            ),
            (
                "horizon-qualify-227-peer.service".into(),
                json!({"Id":"horizon-qualify-227-peer.service","MainPID":"456","InvocationID":"b".repeat(32)}),
            ),
        ])
    }
    #[test]
    fn continuation205_waiter_view_keeps_every_peer_and_raw_census_without_memory_credit() {
        let raw = waiter_census();
        let saved = raw.clone();
        let f = json!({"active":[],"failed_history":{"227":"retained"}});
        let saved_f = f.clone();
        let view = WaitingContext::retained_view(
            downstream::Stage::Full,
            "horizon-205-delivery-full-protective-v1.service",
            &f,
            &raw,
        )
        .unwrap();
        assert_eq!(view.len(), 1);
        assert_eq!(
            view.get("horizon-qualify-227-peer.service"),
            raw.get("horizon-qualify-227-peer.service")
        );
        assert_eq!(raw, saved);
        assert_eq!(f, saved_f);
        assert_eq!(
            candidate_with_anchor(downstream::Stage::Full, BYTES, 100)
                .unwrap()
                .memory_max_bytes,
            65u64 << 30
        );
    }
    #[test]
    fn continuation205_waiter_view_rejects_accepted_owner_live_guard_or_missing_candidate() {
        let raw = waiter_census();
        let guard = "horizon-205-delivery-full-protective-v1.service";
        let accepted = json!({"active":[{"unit":raw[downstream::Stage::Full.unit()]}]});
        assert!(
            WaitingContext::retained_view(downstream::Stage::Full, guard, &accepted, &raw).is_err()
        );
        for (key, value) in [
            ("MainPID", "99"),
            ("NRestarts", "1"),
            ("ActiveState", "active"),
            ("Result", "timeout"),
            ("ExecMainStatus", "1"),
        ] {
            let mut changed = raw.clone();
            changed.get_mut(guard).unwrap()[key] = json!(value);
            assert!(
                WaitingContext::retained_view(
                    downstream::Stage::Full,
                    guard,
                    &json!({"active":[]}),
                    &changed
                )
                .is_err()
            );
        }
        let mut missing = raw.clone();
        missing.remove(downstream::Stage::Full.unit());
        assert!(
            WaitingContext::retained_view(
                downstream::Stage::Full,
                guard,
                &json!({"active":[]}),
                &missing
            )
            .is_err()
        );
        assert!(
            WaitingContext::retained_view(
                downstream::Stage::Full,
                guard,
                &json!({"active":[],"continuation205_delivery":[{"live":true}]}),
                &raw
            )
            .is_err()
        );
    }
    #[test]
    fn continuation205_candidate_covers_actual_copy_anchor_and_independent_guard() {
        use downstream::Stage;
        let c = candidate_with_anchor(Stage::Full, BYTES, 114228848867).unwrap();
        assert_eq!(c.additional_bytes, BYTES + 114228848867 + (128 << 20));
        assert_eq!(c.memory_max_bytes, 65u64 << 30);
        assert_eq!(
            candidate_with_anchor(Stage::Upload, BYTES, 0)
                .unwrap()
                .memory_max_bytes,
            17u64 << 30
        );
        assert!(candidate_with_anchor(Stage::Full, BYTES, 0).is_err());
        assert!(candidate_with_anchor(Stage::Assembly, BYTES, 0).is_err());
    }
}
