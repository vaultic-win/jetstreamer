//! Exact terminal223v2 carry-forward; original fleet and census remain evidence.
use super::*;
pub(super) const UNIT: &str = "horizon-qualify-223-v1620-warmup-resource-8457f800-v2.service";
const IID: &str = "58ab3d9221a6452685b8eab3ceabdb49";
const ROOT: &str =
    "/home/ubuntu/.jetstreamer-private/qualification-223-v1620-prefix-warmup-8457f800-v2";
const ORIGIN: &str = "/var/lib/jetstreamer/horizon-warmup223-native20-admission-v2/launch.json";
pub(super) struct Peer {
    pub binding: BoundFile,
    proof: Value,
}
fn scope(p: &Value) -> Result<()> {
    ensure!(
        p["schema"] == warmup223::TERMINAL_SCHEMA_V2
            && p["epoch"] == 223
            && p["unit"] == UNIT
            && p["invocation_id"] == IID
            && p["running_origin"]["path"] == ORIGIN,
        "209 carry-forward requires the actual exact223v2 terminal proof"
    );
    Ok(())
}
pub(super) fn prepare(
    binding: Option<&BoundFile>,
    f: &Value,
    o: &Value,
    observer: &BoundFile,
    fleet: &BoundFile,
) -> Result<Option<Peer>> {
    let Some(b) = binding else { return Ok(None) };
    let proof = native209::immutable_json(b)?;
    scope(&proof)?;
    let (unit, iid) = warmup223::terminal_identity(&proof)?;
    ensure!(
        unit == UNIT && iid == IID,
        "209 terminal223 identity differs"
    );
    ensure!(
        proof["observer"] == private157::binding(observer)
            && proof["fleet"] == private157::binding(fleet),
        "209 terminal223 proof must bind the same accepted observer and complete predecessor fleet"
    );
    let rows = f["active"]
        .as_array()
        .context("209 terminal223 active census")?;
    let matching = rows
        .iter()
        .filter(|r| r["epoch"] == 223)
        .collect::<Vec<_>>();
    ensure!(
        matching.len() == 1,
        "209 terminal223 predecessor needs exactly its registered live owner"
    );
    let row = matching[0];
    let owner = singleton227_admission::active_owner(row)?;
    let origin: BoundFile = serde_json::from_value(proof["running_origin"].clone())?;
    let p: Plan = serde_json::from_value(bound_json(&BoundFile {
        path: f["plan"]
            .as_str()
            .context("209 terminal223 fleet plan")?
            .into(),
        sha256: f["plan_sha256"]
            .as_str()
            .context("209 terminal223 plan digest")?
            .into(),
    })?)?;
    let claims = p
        .pipeline_claims
        .iter()
        .filter(|c| c.unit == UNIT)
        .collect::<Vec<_>>();
    ensure!(
        claims.len() == 1
            && claims[0].epoch == 223
            && claims[0].phase == "private-warmup-reproduction"
            && claims[0].invocation_id == IID
            && claims[0].evidence == vec![origin]
            && row["phase"] == "private-warmup-reproduction"
            && row["ordinary_replay_claim"] == false
            && owner["Id"] == UNIT
            && owner["InvocationID"] == IID
            && owner["NRestarts"] == "0"
            && diagnostic_stage_running(owner)
            && f["unit_census"][UNIT] == *owner
            && row["evidence"] == serde_json::to_value(&claims[0].evidence)?
            && pipeline_status::same_exec_start(
                &claims[0].expected_exec_start,
                owner["ExecStart"]
                    .as_str()
                    .context("209 terminal223 prior command")?
            ),
        "209 terminal223 predecessor registered origin/owner differs"
    );
    let diagnostics = o["diagnostic_replays"]
        .as_array()
        .context("209 terminal223 sampled rows")?;
    let samples = diagnostics
        .iter()
        .filter(|r| r["producer_unit"] == UNIT)
        .collect::<Vec<_>>();
    ensure!(
        samples.len() == 1,
        "209 terminal223 predecessor sample missing or duplicate"
    );
    sampled(samples[0])?;
    Ok(Some(Peer {
        binding: BoundFile {
            path: b.path.clone(),
            sha256: b.sha256.clone(),
        },
        proof,
    }))
}
fn sampled(r: &Value) -> Result<()> {
    let v = &r["observation"];
    ensure!(
        r["status"] == "observed"
            && r["error"].is_null()
            && r["expected_producer_invocation_id"] == IID
            && v["invocation_binding_stable"] == true
            && v["producer_before"]["unit"] == UNIT
            && v["producer_after"]["unit"] == UNIT
            && v["producer_before"]["invocation_id"] == IID
            && v["producer_after"]["invocation_id"] == IID
            && v["scratch_path"] == format!("{ROOT}/scratch"),
        "209 terminal223 sampled identity/scope differs"
    );
    Ok(())
}
pub(super) fn arithmetic(f: &Value, o: &Value, peer: Option<&Peer>) -> Result<(Value, Value)> {
    let mut reduced = f.clone();
    let mut observed = o.clone();
    if peer.is_some() {
        reduced["active"]
            .as_array_mut()
            .context("209 terminal223 arithmetic owners")?
            .retain(|r| singleton227_admission::active_owner(r).map_or(true, |u| u["Id"] != UNIT));
        observed["diagnostic_replays"]
            .as_array_mut()
            .context("209 terminal223 arithmetic observations")?
            .retain(|r| r["producer_unit"] != UNIT);
    }
    Ok((reduced, observed))
}
pub(super) fn guards(
    guards: &BTreeMap<String, BoundFile>,
    peer: Option<&Peer>,
) -> BTreeMap<String, BoundFile> {
    guards
        .iter()
        .filter(|(name, _)| peer.is_none() || name.as_str() != UNIT)
        .map(|(k, v)| {
            (
                k.clone(),
                BoundFile {
                    path: v.path.clone(),
                    sha256: v.sha256.clone(),
                },
            )
        })
        .collect()
}
pub(super) fn owners(
    f: &Value,
    current: &BTreeMap<String, Value>,
    peer: Option<&Peer>,
) -> Result<()> {
    if let Some(p) = peer {
        warmup223::terminal_owner(
            &p.proof,
            current
                .get(UNIT)
                .context("209 terminal223 current owner omitted")?,
        )?;
        warmup223::terminal_not_replaced(&p.proof)?;
    }
    singleton227_admission::owners(
        &arithmetic(f, &json!({"diagnostic_replays":[]}), peer)?.0,
        current,
    )
}
pub(super) fn evidence(peer: Option<&Peer>) -> Value {
    match peer {
        Some(p) => {
            json!({"terminal_proof":private157::binding(&p.binding),"unit":UNIT,"invocation_id":IID,
            "arithmetic_only_exclusion":true,"retained_disk_credit_bytes":0,"reclaimed_memory_credit_bytes":0,
            "complete_original_fleet_and_census_preserved":true})
        }
        None => Value::Null,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_exact_actual_v2_terminal_profile_can_enter_the_exclusion_path() {
        let p = json!({"schema":warmup223::TERMINAL_SCHEMA_V2,"epoch":223,"unit":UNIT,"invocation_id":IID,"running_origin":{"path":ORIGIN}});
        scope(&p).unwrap();
        for k in ["schema", "epoch", "unit", "invocation_id", "running_origin"] {
            let mut b = p.clone();
            b[k] = Value::Null;
            assert!(scope(&b).is_err(), "{k}");
        }
    }
    #[test]
    fn absent_proof_preserves_every_active_owner_and_observation() {
        let f = json!({"active":[{"epoch":223,"unit":{"Id":UNIT}},{"epoch":227,"producer":{"Id":"full227"}}],"unit_census":{UNIT:{"Id":UNIT}},"plan":"bound"});
        let o = json!({"diagnostic_replays":[{"producer_unit":UNIT},{"producer_unit":"full227"}]});
        let (rf, ro) = arithmetic(&f, &o, None).unwrap();
        assert_eq!(rf, f);
        assert_eq!(ro, o);
    }
    #[test]
    fn arithmetic_excludes_only_the_proved_peer_without_rewriting_evidence_or_crediting_disk() {
        let peer = Peer {
            binding: BoundFile {
                path: "/fixture/proof.json".into(),
                sha256: "a".repeat(64),
            },
            proof: Value::Null,
        };
        let f = json!({"active":[{"epoch":223,"unit":{"Id":UNIT}},{"epoch":227,"producer":{"Id":"full227"}},{"epoch":225,"producer":{"Id":"full225"}}],"unit_census":{UNIT:{"Id":UNIT},"full227":{"Id":"full227"}},"plan":"unchanged"});
        let o = json!({"diagnostic_replays":[{"producer_unit":UNIT},{"producer_unit":"full227"},{"producer_unit":"full225"}],"filesystem":{"conservative_available_bytes":100}});
        let (rf, ro) = arithmetic(&f, &o, Some(&peer)).unwrap();
        assert_eq!(rf["unit_census"], f["unit_census"]);
        assert_eq!(rf["plan"], f["plan"]);
        assert_eq!(rf["active"].as_array().unwrap().len(), 2);
        assert_eq!(ro["filesystem"], o["filesystem"]);
        assert_eq!(ro["diagnostic_replays"].as_array().unwrap().len(), 2);
        assert_eq!(f["active"].as_array().unwrap().len(), 3);
        assert_eq!(o["diagnostic_replays"].as_array().unwrap().len(), 3);
        assert_eq!(evidence(Some(&peer))["retained_disk_credit_bytes"], 0);
        assert_eq!(evidence(Some(&peer))["reclaimed_memory_credit_bytes"], 0);
    }
    #[test]
    #[ignore = "root-only immutable334 metadata reader; no terminal claim, process/resource observation or network"]
    fn root_saved334_binds_the_exact223v2_peer_without_claiming_it_is_terminal() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let f=bound_json(&BoundFile{path:"/var/lib/jetstreamer/horizon-campaign-fleet/20261023T225300Z-v334/fleet-ledger.json".into(),sha256:"cbb5d8ef13b2f458203b5d2513271483a60c1f8e94cb83616252a137516f029f".into()}).unwrap();
        let o=bound_json(&BoundFile{path:"/home/ubuntu/workspace/jetstreamer/.codex/tmp-readiness/horizon-live-resource-sample-20261023T225300Z-diagnostics-v334.json".into(),sha256:"8feba0f946418de1e67959fc97148333b467348e256101a02a571af0aef614d8".into()}).unwrap();
        let rows = o["diagnostic_replays"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["producer_unit"] == UNIT)
            .collect::<Vec<_>>();
        assert_eq!(rows.len(), 1);
        sampled(rows[0]).unwrap();
        for key in ["expected_producer_invocation_id", "observation", "status"] {
            let mut bad = rows[0].clone();
            bad[key] = Value::Null;
            assert!(sampled(&bad).is_err(), "{key}");
        }
        assert!(diagnostic_stage_running(&f["unit_census"][UNIT]));
        assert_eq!(f["unit_census"][UNIT]["InvocationID"], IID);
        assert_eq!(f["active"].as_array().unwrap().len(), 5);
    }
    #[test]
    #[ignore = "root-only actual terminal223v2/334 metadata proof; no current owner/resource/process query or network"]
    fn root_actual_terminal223v2_proof_preserves334_and_excludes_only_completed_peer_arithmetic() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let fleet=BoundFile{path:"/var/lib/jetstreamer/horizon-campaign-fleet/20261023T225300Z-v334/fleet-ledger.json".into(),sha256:"cbb5d8ef13b2f458203b5d2513271483a60c1f8e94cb83616252a137516f029f".into()};
        let observer=BoundFile{path:"/home/ubuntu/workspace/jetstreamer/.codex/tmp-readiness/horizon-live-resource-sample-20261023T225300Z-diagnostics-v334.json".into(),sha256:"8feba0f946418de1e67959fc97148333b467348e256101a02a571af0aef614d8".into()};
        let proof = BoundFile {
            path: "/var/lib/jetstreamer/horizon-warmup223-native20-terminal-58ab-v2/proof.json"
                .into(),
            sha256: "6790592b9188e7c4a3d32171a326b743f84fc6c5b5ad07f94182c104876b7028".into(),
        };
        let f = bound_json(&fleet).unwrap();
        let o = bound_json(&observer).unwrap();
        let peer = prepare(Some(&proof), &f, &o, &observer, &fleet)
            .unwrap()
            .unwrap();
        let (arithmetic, observed) = arithmetic(&f, &o, Some(&peer)).unwrap();
        assert_eq!(f["active"].as_array().unwrap().len(), 5);
        assert_eq!(arithmetic["active"].as_array().unwrap().len(), 4);
        assert_eq!(arithmetic["unit_census"], f["unit_census"]);
        assert_eq!(observed["filesystem"], o["filesystem"]);
        assert_eq!(peer.proof["bounded_warmup_complete"], true);
        let mut bad = f.clone();
        bad["active"]
            .as_array_mut()
            .unwrap()
            .retain(|r| r["epoch"] != 223);
        assert!(prepare(Some(&proof), &bad, &o, &observer, &fleet).is_err());
    }
}
