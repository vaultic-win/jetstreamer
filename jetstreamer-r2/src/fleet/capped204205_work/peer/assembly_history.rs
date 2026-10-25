//! Find a real positive Assembly predecessor through the normal two-step cadence.
//! Negative ledgers remain evidence; none becomes a current accepted owner.
use super::*;
const MAX_LINKS: usize = 16;
const STALE_FRAME: &str = "capped work detached from deployed corrected observer provenance";
fn same_origin(a: &Claim, b: &Claim) -> bool {
    a.epoch == b.epoch
        && a.producer_plan == b.producer_plan
        && a.admission == b.admission
        && a.launch == b.launch
}
fn claims(f: &Value) -> Result<Vec<Claim>> {
    let plan = bound_json(&BoundFile {
        path: string(f, "plan")?.into(),
        sha256: string(f, "plan_sha256")?.into(),
    })?;
    Ok(serde_json::from_value(plan["capped204205_work"].clone())?)
}
fn negative_scope(row: &Value, epoch: u64) -> Result<()> {
    ensure!(
        row["epoch"] == epoch
            && row["phase"] == "capped204205-unresolved"
            && row["ownership_unresolved"] == true
            && row["reason"] == STALE_FRAME
            && row["live"] == true
            && row["ordinary_replay_claim"] == false
            && row["publication_authorized"] == false
            && row["r2_mutations"] == false
            && row["positive_inactivity_confirmed"] == false,
        "Assembly history is not the exact stale-frame cadence handoff"
    );
    Ok(())
}
fn unresolved_handoff(f: &Value, current: &Peer) -> Result<Claim> {
    let rows = f["active"]
        .as_array()
        .context("Assembly history active census absent")?
        .iter()
        .filter(|r| selected(r))
        .collect::<Vec<_>>();
    ensure!(
        rows.len() == 1 && rows[0]["epoch"] == current.claim.epoch,
        "Assembly history unresolved node contains another or ambiguous capped owner"
    );
    let row = rows[0];
    negative_scope(row, current.claim.epoch)?;
    let matching = claims(f)?
        .into_iter()
        .filter(|c| c.epoch == current.claim.epoch)
        .collect::<Vec<_>>();
    ensure!(
        matching.len() == 1,
        "Assembly history lacks one exact original claim"
    );
    let claim = matching.into_iter().next().unwrap();
    ensure!(
        same_origin(&claim, &current.claim),
        "Assembly history changed original admission, plan, or launch"
    );
    let input = read_inputs(&claim)?;
    validate_origin(&claim, &input)?;
    let census: BTreeMap<String, Value> = serde_json::from_value(f["unit_census"].clone())?;
    let observer_bound = BoundFile {
        path: string(f, "observer_receipt")?.into(),
        sha256: string(f, "observer_sha256")?.into(),
    };
    let observer = bound_json(&observer_bound)?;
    ensure!(
        observer["recorded_at_utc"] == f["sampled_at_utc"]
            && input.frame["observer"] != private157::binding(&observer_bound),
        "Assembly cadence handoff did not advance its bound observer"
    );
    let old_observer = evidence::bound(
        &serde_json::from_value(input.frame["observer"].clone())?,
        false,
    )?;
    ensure!(
        utc_seconds(string(&old_observer, "recorded_at_utc")?)?
            < utc_seconds(string(&observer, "recorded_at_utc")?)?,
        "Assembly handoff observer did not advance forward"
    );
    let error = evaluate(
        &claim,
        &input,
        &observer,
        &census,
        number(f, "recorded_unix_seconds")?,
    )
    .err()
    .context("Assembly historical node is not a negative cadence handoff")?;
    ensure!(
        format!("{error:#}") == STALE_FRAME
            && lifecycle::unresolved(&claim, &input.plan, &census, STALE_FRAME) == *row,
        "Assembly negative history does not reproduce the exact stale-observer classification"
    );
    let owner = census
        .get(string(&input.plan, "producer_unit")?)
        .context("Assembly handoff producer absent")?;
    let guard = census
        .get(string(&input.plan, "guard_unit")?)
        .context("Assembly handoff independent guard absent")?;
    ensure!(
        live(owner)
            && live(guard)
            && guard["Id"] == current.input.plan["guard_unit"]
            && owner["Id"] == current.row["unit"]["Id"]
            && owner["InvocationID"] == current.input.launch["invocation_id"]
            && owner["MainPID"]
                == current.input.launch["main_pid"]
                    .as_u64()
                    .map(|p| p.to_string())
                    .unwrap_or_default()
            && owner["NRestarts"] == "0"
            && guard["NRestarts"] == "0"
            && guard["InvocationID"] == current.input.launch["guard_invocation_id"]
            && pipeline_status::same_exec_start(
                string(owner, "ExecStart")?,
                string(&current.input.launch, "expected_exec_start")?
            )
            && evidence::command_matches(
                &evidence::expected_guard_command(
                    &input.plan,
                    &input.admission,
                    &claim.producer_plan,
                    string(&input.launch, "invocation_id")?
                )?,
                string(guard, "ExecStart")?
            ),
        "Assembly negative handoff lost the exact running producer or independent guard"
    );
    Ok(claim)
}
fn ledger_scope(f: &Value, max_clock: u64, max_sample: u64) -> Result<(u64, u64)> {
    let clock = number(f, "recorded_unix_seconds")?;
    let sample = utc_seconds(string(f, "sampled_at_utc")?)?;
    ensure!(
        f["schema"] == SCHEMA
            && f["first_epoch"] == 201
            && f["last_epoch"] == 300
            && f["inventory"]["anomalies"] == 0
            && sample <= clock
            && clock <= max_clock
            && sample <= max_sample,
        "Assembly history ledger is foreign, anomalous, or goes forward in time"
    );
    Ok((clock, sample))
}
pub(super) fn select(current: &Peer, initial: &BoundFile) -> Result<(Peer, Value)> {
    let mut bound = BoundFile {
        path: initial.path.clone(),
        sha256: initial.sha256.clone(),
    };
    let mut seen = BTreeSet::new();
    let mut chain = Vec::new();
    let mut negatives = Vec::new();
    let mut max_clock = number(&current.input.frame, "sampled_unix_millis")? / 1000;
    let mut max_sample = utc_seconds(string(
        &evidence::bound(
            &serde_json::from_value(current.input.frame["observer"].clone())?,
            false,
        )?,
        "recorded_at_utc",
    )?)?;
    for _ in 0..MAX_LINKS {
        ensure!(
            seen.insert((bound.path.clone(), bound.sha256.clone())),
            "Assembly predecessor chain cycles"
        );
        let f = bound_json(&bound)?;
        (max_clock, max_sample) = ledger_scope(&f, max_clock, max_sample)?;
        let rows = f["active"]
            .as_array()
            .context("Assembly ancestor active census absent")?
            .iter()
            .filter(|r| r["epoch"] == current.claim.epoch && selected(r))
            .collect::<Vec<_>>();
        ensure!(
            rows.len() == 1,
            "Assembly history has a missing or ambiguous epoch owner"
        );
        if rows[0]["phase"] == "capped204205-unresolved" {
            let claim = unresolved_handoff(&f, current)?;
            chain.push(json!({"fleet":private157::binding(&bound),"classification":"reproduced-stale-frame-cadence-handoff",
                "negative_row":rows[0],"claim":claim,"history_retained":true,"current_owner_exemption":false}));
            negatives.push(claim);
            bound = serde_json::from_value(f["previous_fleet"].clone())?;
            continue;
        }
        let found = accepted(&f)?
            .into_iter()
            .filter(|p| p.claim.epoch == current.claim.epoch)
            .collect::<Vec<_>>();
        ensure!(
            found.len() == 1,
            "Assembly history lacks a unique positive predecessor"
        );
        let old = found.into_iter().next().unwrap();
        ensure!(
            same_origin(&old.claim, &current.claim) && old.row["current_stage"] == "assembly",
            "Assembly positive predecessor changed origin or phase"
        );
        let old_claim = serde_json::to_value(&old.claim)?;
        for claim in negatives {
            ensure!(
                serde_json::to_value(claim)? == old_claim,
                "Assembly cadence handoff did not preserve the exact eventual positive predecessor claim"
            );
        }
        chain.push(json!({"fleet":private157::binding(&bound),"classification":"independently-accepted-positive-assembly",
            "claim":old_claim,"history_retained":true}));
        return Ok((
            old,
            json!({"selected_positive_fleet":private157::binding(&bound),"links":chain,
            "current_accepted_owner_gate_unchanged":true,"maximum_links":MAX_LINKS}),
        ));
    }
    bail!("Assembly predecessor chain exceeds its bounded historical search")
}

#[cfg(test)]
mod tests {
    use super::*;
    fn claim() -> Claim {
        let b = || BoundFile {
            path: "/sealed/evidence.json".into(),
            sha256: "a".repeat(64),
        };
        Claim {
            epoch: 204,
            producer_plan: b(),
            admission: b(),
            launch: b(),
            frame: b(),
            eta_policy: b(),
        }
    }
    #[test]
    fn only_the_explicit_reproduced_stale_frame_node_can_be_traversed() {
        let row = json!({"epoch":204,"phase":"capped204205-unresolved","ownership_unresolved":true,
            "reason":STALE_FRAME,"live":true,"ordinary_replay_claim":false,"publication_authorized":false,
            "r2_mutations":false,"positive_inactivity_confirmed":false});
        negative_scope(&row, 204).unwrap();
        for (k, v) in [
            ("reason", json!("unknown guard failure")),
            ("epoch", json!(205)),
            ("phase", json!("unsupported")),
            ("live", json!(false)),
            ("ordinary_replay_claim", json!(true)),
            ("publication_authorized", json!(true)),
            ("ownership_unresolved", json!(false)),
        ] {
            let mut bad = row.clone();
            bad[k] = v;
            assert!(negative_scope(&bad, 204).is_err(), "{k}");
        }
    }
    #[test]
    fn predecessor_scope_preserves_original_claim_and_never_goes_forward_or_foreign() {
        let c = claim();
        let mut bad = claim();
        bad.admission.sha256 = "b".repeat(64);
        assert!(!same_origin(&c, &bad));
        let mut bad = claim();
        bad.launch.sha256 = "b".repeat(64);
        assert!(!same_origin(&c, &bad));
        let mut bad = claim();
        bad.producer_plan.path = "/foreign/plan".into();
        assert!(!same_origin(&c, &bad));
        let f = json!({"schema":SCHEMA,"first_epoch":201,"last_epoch":300,"inventory":{"anomalies":0},
            "sampled_at_utc":"2026-10-25T04:20:00Z","recorded_unix_seconds":1792903382u64});
        ledger_scope(&f, 1792903382, 1792902000).unwrap();
        for (k, v) in [
            ("schema", json!("foreign")),
            ("first_epoch", json!(200)),
            ("last_epoch", json!(301)),
            ("recorded_unix_seconds", json!(1792903383u64)),
            ("sampled_at_utc", json!("2026-10-25T04:21:00Z")),
        ] {
            let mut bad = f.clone();
            bad[k] = v;
            assert!(ledger_scope(&bad, 1792903382, 1792902000).is_err(), "{k}");
        }
        let mut bad = f;
        bad["inventory"]["anomalies"] = json!(1);
        assert!(ledger_scope(&bad, 1792903382, 1792902000).is_err());
    }
    #[test]
    #[ignore = "root-only saved cycle391 metadata reproduction; no resource/service/cloud/R2 observation or mutation"]
    fn real391_assembly_history_retains_the_negative_cadence_node_and_selects_real390_positive() {
        let f = bound_json(&BoundFile {
            path: "/var/lib/jetstreamer/horizon-capped204-fleet-cb0bd6d9-cycle391-v1/fleet.json"
                .into(),
            sha256: "b58a27028b71626f6c30a23dc9f6ef7078c9c65376461322b67cf33205dfb8c3".into(),
        })
        .unwrap();
        accepted(&f).unwrap();
        let o = bound_json(&BoundFile {
            path: string(&f, "observer_receipt").unwrap().into(),
            sha256: string(&f, "observer_sha256").unwrap().into(),
        })
        .unwrap();
        let owners = peer_assembly_memory_owners(&f, &o).unwrap();
        assert_eq!(owners.len(), 1);
        let p = owners.values().next().unwrap();
        let links = p["predecessor_history"]["links"].as_array().unwrap();
        assert_eq!(links.len(), 2);
        assert_eq!(
            links[0]["classification"],
            "reproduced-stale-frame-cadence-handoff"
        );
        assert_eq!(
            links[1]["classification"],
            "independently-accepted-positive-assembly"
        );
        assert_eq!(links[0]["negative_row"]["ownership_unresolved"], true);
        assert_eq!(p["disk_or_hard_memory_growth_exempted"], false);
        let n = peer_clean_assembly_window(&f, &o).unwrap();
        assert_eq!(n.len(), 1);
    }
}
