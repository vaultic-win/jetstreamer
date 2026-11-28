//! Select the native observer input after the original local publication.
//! Preserve the deadline, predecessor, output, diagnostic rows and every booking.
use super::*;
use std::collections::BTreeSet;
use std::{
    io,
    os::unix::{
        fs::{DirBuilderExt, PermissionsExt},
        process::CommandExt,
    },
};

#[path = "metered168.rs"]
mod metered168;

const BASE: &str = "/var/lib/jetstreamer/horizon_runtime_data";
const NATIVE: &str = "/usr/local/lib/jetstreamer/horizon-observer-exit-census-20261107-v1/jetstreamer-horizon-observe";
const NATIVE_SHA: &str = "6b06665ac4dd0654f6684f4fd178787c37e30af332a657c6c5a6502c2f3e2ab8";
const SEALER: &str = "/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment";
const SEALER_SHA: &str = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3";

fn data(path: &Path, limit: usize) -> Result<Vec<u8>> {
    ensure!(
        path.canonicalize()? == path,
        "unexpected evidence alias: {}",
        path.display()
    );
    let m = path.symlink_metadata()?;
    ensure!(
        m.uid() == 0 && m.mode() & 0o022 == 0,
        "untrusted evidence: {}",
        path.display()
    );
    let bytes = small(path, limit)?;
    let after = path.symlink_metadata()?;
    ensure!(
        (m.dev(), m.ino(), m.ctime(), m.ctime_nsec())
            == (after.dev(), after.ino(), after.ctime(), after.ctime_nsec()),
        "evidence changed"
    );
    Ok(bytes)
}
fn hash(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn binding(p: &Path, b: &[u8]) -> Value {
    json!({"path":p,"sha256":hash(b)})
}
fn bound(ref_: &Value) -> Result<Value> {
    let p = Path::new(s(&ref_["path"])?);
    let b = data(p, 32 << 20)?;
    ensure!(
        ref_ == &binding(p, &b),
        "bad evidence binding: {}",
        p.display()
    );
    Ok(serde_json::from_slice(&b)?)
}
fn rows<'a>(v: &'a Value, k: &str) -> Result<&'a Vec<Value>> {
    v[k].as_array().with_context(|| format!("missing {k}"))
}
fn epochs(v: &Value, k: &str) -> Result<BTreeSet<u64>> {
    let list = rows(v, k)?;
    let set = list
        .iter()
        .map(|r| r["epoch"].as_u64().context("invalid epoch"))
        .collect::<Result<BTreeSet<_>>>()?;
    ensure!(list.len() == set.len(), "duplicate epoch in {k}");
    Ok(set)
}
fn validate_clock(f: &Value, cfg: &Value, previous: &Value) -> Result<()> {
    ensure!(
        f["owner"] == "/root"
            && f["schema"] == "horizon-Root-complete-fleet-operational-review-v1"
            && cfg["previous_sample"] == f["observer"]["path"]
            && previous["recorded_at_utc"] == f["sampled_at_utc"]
            && cfg["not_before_utc"]
                == previous["cadence"]["next_routine_observation_not_before_utc"]
            && cfg["minimum_interval_seconds"] == 1800
            && cfg["observation_reason"] == "routine"
            && cfg["filesystem_path"] == "/home/sol"
            && f["all_reservation_ending_bytes"] == 0
            && f["all_existing_memory_DATA_OS_native_transport_promises_retained"] == true
            && f["all_active_status_reports_authenticated_readback"] == true,
        "changed predecessor, deadline or capacity contract"
    );
    let timer = s(&f["sole_next_timer"])?;
    let tag = timer
        .strip_prefix("horizon-observer-")
        .and_then(|v| v.strip_suffix(".timer"))
        .context("invalid scheduled observer unit")?;
    ensure!(
        !tag.is_empty()
            && tag.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && cfg["output"] == json!(Path::new(BASE).join(format!("sample-{tag}.json"))),
        "scheduled output mismatch"
    );
    Ok(())
}
/// The parent cohort receipt and physical process drain are validated separately.
/// Remove exactly one original primary row. Derive no fresh fleet from an old sample.
fn project(f: &Value, cfg: &Value, live: &Value) -> Result<Value> {
    let private = epochs(f, "actual_active_private_diagnostics")?;
    let retired = f.get("terminal168_trace_mismatch");
    if let Some(event) = retired {
        ensure!(
            event
                == &json!({
                    "path": format!("{BASE}/epoch168-terminal-trace-20261121-v1/TERMINAL.json"),
                    "sha256": "29672efbaff97d23a9a9d45a824840cb2d4cf43c6f5e8427ed3b532b41a38de2"
                }),
            "foreign 168 terminal receipt"
        );
        let terminal = bound(event)?;
        ensure!(
            terminal["epoch"] == 168
                && terminal["terminal_before_routine_sample"] == true
                && terminal["resource_credit_bytes"] == 0
                && terminal["archive_publication_authorized"] == false
                && rows(cfg, "diagnostic_replays")?
                    .iter()
                    .all(|r| r["range"] != "168"),
            "168 terminal conflicts with registered diagnostics"
        );
    }
    let mut expected = if retired.is_some() {
        BTreeSet::from([169])
    } else {
        BTreeSet::from([168, 169])
    };
    if let Some(reference) = f.get("private_epoch136_observation") {
        let capture = bound(reference)?;
        let row = &capture["row"];
        ensure!(
            capture["schema"] == "horizon-private136-cycle-v1"
                && row["epoch"] == 136
                && capture["sample"] == f["observer"]
                && capture["fleet"] == f["previous_Root_operational_review"],
            "136 observation belongs to another sample or fleet"
        );
        if row["positive_worker"] == true {
            let registered = rows(f, "actual_active_private_diagnostics")?
                .iter()
                .find(|r| r["epoch"] == 136)
                .context("missing admitted private 136")?;
            ensure!(
                registered["receipt"] == *reference
                    && registered["canonical_replay_claimed"] == false
                    && [
                        "entry",
                        "children",
                        "admission",
                        "post_prefire_capacity",
                        "native_start_ticks",
                        "unit"
                    ]
                    .iter()
                    .all(|&key| row.get(key).is_some() && registered[key] == row[key]),
                "changed private 136 registration"
            );
            expected.insert(136);
        }
    }
    let (boot, worker) = metered168::roster(f, cfg)?;
    let mut expected_replays = BTreeSet::from([166, 167, 170, 172]);
    if worker {
        expected_replays.insert(168);
    }
    let expected_boots = if boot {
        BTreeSet::from([168])
    } else {
        BTreeSet::new()
    };
    ensure!(
        epochs(f, "actual_executing_replays")? == expected_replays
            && private == expected
            && epochs(f, "actual_active_bootstraps")? == expected_boots
            && f["active_private_diagnostic_count"] == private.len()
            && f["active_producer_count"] == 4 + private.len() + usize::from(boot || worker)
            && f["additional_independent166_DATA_cap_bytes"] == live["reserved_disk_bytes"],
        "166 retirement needs its original primary peers and registered diagnostics"
    );
    let original = rows(f, "actual_executing_replays")?;
    let primary = rows(cfg, "replays")?;
    ensure!(primary.len() == original.len(), "changed native membership");
    for row in original {
        let epoch = row["epoch"].as_u64().context("epoch")?;
        let expected = epoch.to_string();
        let matches: Vec<_> = primary.iter().filter(|p| p["range"] == expected).collect();
        ensure!(matches.len() == 1, "missing or duplicate primary {epoch}");
        let p = matches[0];
        ensure!(
            p["producer_unit"] == row["unit"]["Id"]
                && p["expected_producer_invocation_id"] == row["unit"]["InvocationID"]
                && p["scratch_path"] == row["scratch_path"],
            "primary {epoch} identity changed"
        );
        if epoch == 166 {
            ensure!(
                row["admission"] == live["admission"]
                    && row["guard_protection"] == live["protection"]
                    && p["expected_producer_invocation_id"] == IID
                    && p["producer_unit"] == UNIT
                    && p["append_log"] == live["producer_log"],
                "another 166 generation"
            );
        }
    }
    let mut out = cfg.clone();
    out["replays"]
        .as_array_mut()
        .unwrap()
        .retain(|r| r["range"] != "166");
    Ok(out)
}
fn check_seal(path: &Path, cfg_bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("seal directory")?;
    let seal: Value = serde_json::from_slice(&data(
        &parent.join("deployment-seal-receipt.json"),
        1 << 20,
    )?)?;
    let members = rows(&seal, "members")?;
    ensure!(
        seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && seal["sealer_sha256"] == SEALER_SHA
            && seal["destination"] == json!(parent)
            && members.len() == 1
            && members[0]["name"] == "observer.json"
            && members[0]["sha256"] == hash(cfg_bytes)
            && members[0]["mode"] == "0444"
            && path.symlink_metadata()?.mode() & 0o777 == 0o444,
        "native config seal changed"
    );
    Ok(())
}
fn write_once(path: &Path, v: &Value) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(v)?;
    bytes.push(b'\n');
    super::publish_exact(path, &bytes)
}
fn materialize(path: &Path, cfg: &Value, receipt: &Value) -> Result<PathBuf> {
    let root = path
        .parent()
        .and_then(Path::parent)
        .context("fleet directory")?
        .join("after-166");
    match fs::DirBuilder::new().mode(0o700).create(&root) {
        Ok(()) => fs::File::open(root.parent().unwrap())?.sync_all()?,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    }
    let md = root.symlink_metadata()?;
    ensure!(
        root.canonicalize()? == root
            && md.is_dir()
            && md.uid() == 0
            && md.permissions().mode() & 0o777 == 0o700,
        "foreign transition directory"
    );
    let config = root.join("observer.json");
    let dest = root.join("sealed-next");
    write_once(&config, cfg)?;
    let bytes = data(&config, 1 << 20)?;
    write_once(&root.join("selection.json"), receipt)?;
    let plan = json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":dest,"members":[{"name":"observer.json","source":config,"sha256":hash(&bytes),"mode":0o444}]});
    let p = root.join("plan.json");
    write_once(&p, &plan)?;
    let sealed = dest.join("observer.json");
    if !dest.try_exists()? {
        ensure!(
            hash(&data(Path::new(SEALER), 16 << 20)?) == SEALER_SHA,
            "sealer changed"
        );
        run(
            SEALER,
            &[
                p.to_str().context("plan pathname")?,
                "--plan-sha256",
                &hash(&data(&p, 1 << 20)?),
                "--self-sha256",
                SEALER_SHA,
            ],
        )?;
    }
    let actual = data(&sealed, 1 << 20)?;
    ensure!(actual == bytes, "different sealed effective config");
    check_seal(&sealed, &actual)?;
    Ok(sealed)
}
pub fn select(path: &Path, dispatch: bool) -> Result<Value> {
    let fleet_dir = path
        .parent()
        .and_then(Path::parent)
        .context("invalid expected native config location")?;
    ensure!(
        fleet_dir.parent() == Some(Path::new(BASE))
            && path == fleet_dir.join("sealed-next/observer.json"),
        "wrong registered native config path"
    );
    let fleet_path = fleet_dir.join("ROOT_COMPLETE_OPERATIONAL_FLEET.json");
    let fleet_bytes = data(&fleet_path, 32 << 20)?;
    let f: Value = serde_json::from_slice(&fleet_bytes)?;
    let cfg_bytes = data(path, 1 << 20)?;
    check_seal(path, &cfg_bytes)?;
    ensure!(
        f["sole_next_observer"] == binding(path, &cfg_bytes),
        "unregistered scheduled config"
    );
    let cfg: Value = serde_json::from_slice(&cfg_bytes)?;
    validate_clock(&f, &cfg, &bound(&f["observer"])?)?;
    if dispatch {
        let service = s(&f["sole_next_timer"])?
            .strip_suffix(".timer")
            .context("scheduled timer")?
            .to_owned()
            + ".service";
        ensure!(
            unsafe { libc::geteuid() } == 0
                && fs::read_to_string("/proc/self/cgroup")?.trim()
                    == format!("0::/system.slice/{service}"),
            "only the scheduled native unit may dispatch"
        );
        let n = show(&service)?;
        ensure!(
            n["Id"] == service
                && n["MainPID"] == std::process::id().to_string()
                && n["InvocationID"] == std::env::var("INVOCATION_ID")?
                && !n["InvocationID"].is_empty(),
            "foreign sampler process"
        );
        ensure!(
            !Path::new(s(&cfg["output"])?).try_exists()?,
            "scheduled sample already committed"
        );
    }
    let live = checked_live()?;
    let parent = process_bound(&live["native"]["parent"])?;
    let child = process_bound(&live["native"]["worker"])?;
    let effective;
    let result;
    if parent || child {
        let owner = show(UNIT)?;
        ensure!(
            parent
                && owner["InvocationID"] == IID
                && Some(owner["MainPID"].parse::<u64>()?)
                    == live["native"]["parent"]["pid"].as_u64()
                && rows(&cfg, "replays")?
                    .iter()
                    .any(|v| v["range"] == "166" && v["expected_producer_invocation_id"] == IID),
            "unresolved 166 owner"
        );
        effective = path.to_owned();
        result = json!({"mode":"original","config":f["sole_next_observer"],"node_alive":parent,"worker_alive":child});
    } else {
        let evidence = complete(&live)?;
        let old = rows(&cfg, "replays")?.iter().any(|r| r["range"] == "166");
        if dispatch {
            record(&evidence)?;
        }
        let proof = Path::new(ROOT).join("TERMINAL_SUCCESS.json");
        let terminal = data(&proof, 1 << 20)?;
        ensure!(
            proof.symlink_metadata()?.mode() & 0o777 == 0o400
                && serde_json::from_slice::<Value>(&terminal)? == evidence,
            "terminal record changed"
        );
        let reference = binding(&proof, &terminal);
        if old {
            let projected = project(&f, &cfg, &live)?;
            let decision = json!({"schema":"horizon-166-terminal-native-selection-v1","terminal":reference,"predecessor_fleet":binding(&fleet_path,&fleet_bytes),
                "original":f["sole_next_observer"],"previous_sample":f["observer"],"due":cfg["not_before_utc"],"output":cfg["output"],
                "keep_166_disk_bytes":live["reserved_disk_bytes"],"keep_166_memory_bytes":live["reserved_actor_memory_bytes"],"resource_credit_bytes":0});
            if !dispatch {
                return Ok(
                    json!({"mode":"closed","selection":decision,"projected_config":projected}),
                );
            }
            effective = materialize(path, &projected, &decision)?;
        } else {
            let (boot, worker) = metered168::roster(&f, &cfg)?;
            let mut survivors = BTreeSet::from([167, 170, 172]);
            if worker {
                survivors.insert(168);
            }
            let expected_boots = if boot {
                BTreeSet::from([168])
            } else {
                BTreeSet::new()
            };
            ensure!(
                f["terminal166_local_commit"] == reference
                    && epochs(&f, "actual_active_bootstraps")? == expected_boots
                    && epochs(&f, "actual_executing_replays")? == survivors,
                "scheduled roster already omitted 166 without its bound local disposition"
            );
            effective = path.to_owned();
        }
        result = json!({"mode":"closed","config":effective,"terminal":reference});
    }
    if dispatch {
        ensure!(
            hash(&data(Path::new(NATIVE), 16 << 20)?) == NATIVE_SHA,
            "native sampler changed"
        );
        return Err(Command::new(NATIVE).arg(effective).exec().into());
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "requires the root-owned scheduled fleet, isolated paid fixture and normal sealer"]
    fn scheduled_transition_preserves_survivors_and_clock() -> Result<()> {
        let path = PathBuf::from(std::env::var("TERMINAL166_SCHEDULED_CONFIG")?);
        let scratch = PathBuf::from(std::env::var("TERMINAL166_CADENCE_FIXTURE")?);
        let fleet = path
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("ROOT_COMPLETE_OPERATIONAL_FLEET.json");
        let f: Value = serde_json::from_slice(&data(&fleet, 32 << 20)?)?;
        let bytes = data(&path, 1 << 20)?;
        check_seal(&path, &bytes)?;
        let cfg: Value = serde_json::from_slice(&bytes)?;
        let previous = bound(&f["observer"])?;
        validate_clock(&f, &cfg, &previous)?;
        let live = checked_live()?;
        let reduced = project(&f, &cfg, &live)?;
        let mut proof = reduced.clone();
        let before = rows(&cfg, "replays")?;
        let survivors: Vec<_> = before
            .iter()
            .filter(|r| r["range"] != "166")
            .cloned()
            .collect();
        assert_eq!(reduced["replays"], json!(survivors));
        proof["replays"] = cfg["replays"].clone();
        assert_eq!(cfg, proof);
        for (field, value) in [
            ("/replays/0/expected_producer_invocation_id", json!("other")),
            ("/replays/0/append_log/inode", json!(0)),
            ("/replays/1/range", json!("166")),
            ("/replays/2/scratch_path", json!("/new")),
        ] {
            let mut mismatch = cfg.clone();
            *mismatch.pointer_mut(field).unwrap() = value;
            assert!(project(&f, &mismatch, &live).is_err());
        }
        let mut changed_fleet = f.clone();
        changed_fleet["additional_independent166_DATA_cap_bytes"] = json!(0);
        assert!(project(&changed_fleet, &cfg, &live).is_err());
        if f.get("terminal168_trace_mismatch").is_some() {
            let mut bad = f.clone();
            bad["terminal168_trace_mismatch"]["sha256"] = json!("0".repeat(64));
            assert!(project(&bad, &cfg, &live).is_err());
            let mut missing = f.clone();
            missing
                .as_object_mut()
                .unwrap()
                .remove("terminal168_trace_mismatch");
            assert!(project(&missing, &cfg, &live).is_err());
            let mut resurrected = cfg.clone();
            resurrected["diagnostic_replays"]
                .as_array_mut()
                .unwrap()
                .push(json!({"range":"168"}));
            assert!(project(&f, &resurrected, &live).is_err());
        }
        let mut late = cfg.clone();
        late["not_before_utc"] = json!("2099-01-01T00:00:00Z");
        assert!(validate_clock(&f, &late, &previous).is_err());
        assert!(scratch.is_absolute() && !scratch.try_exists()? && unsafe { libc::geteuid() } == 0);
        fs::DirBuilder::new().mode(0o700).create(&scratch)?;
        if f.get("terminal168_trace_mismatch").is_some() {
            let row = json!({"epoch":136,"positive_worker":true,"canonical_replay_claimed":false,
                "entry":"fixture-entry","children":{"worker":{"pid":std::process::id()}},
                "admission":"fixture-admission","post_prefire_capacity":"fixture-capacity",
                "native_start_ticks":1,"unit":{"InvocationID":"fixture-invocation"}});
            let captured = json!({"schema":"horizon-private136-cycle-v1","sample":f["observer"],
                "fleet":f["previous_Root_operational_review"],"row":row});
            let file = scratch.join("bounded136.json");
            write_once(&file, &captured)?;
            let reference = binding(&file, &data(&file, 1 << 20)?);
            let mut additional = f.clone();
            additional["private_epoch136_observation"] = reference.clone();
            let mut registered = row;
            registered["receipt"] = reference;
            additional["actual_active_private_diagnostics"]
                .as_array_mut()
                .unwrap()
                .push(registered);
            additional["active_private_diagnostic_count"] = json!(2);
            additional["active_producer_count"] = json!(6);
            assert_eq!(project(&additional, &cfg, &live)?, reduced);
            *additional
                .pointer_mut("/actual_active_private_diagnostics/1/native_start_ticks")
                .unwrap() = json!(2);
            assert!(project(&additional, &cfg, &live).is_err());
        }
        let original_name = scratch.join("sealed-next/observer.json");
        let choice = json!({"only_a_test":true,"original":binding(&path,&bytes)});
        let dest = materialize(&original_name, &reduced, &choice)?;
        let inode = dest.metadata()?.ino();
        assert_eq!(
            serde_json::from_slice::<Value>(&data(&dest, 1 << 20)?)?,
            reduced
        );
        assert_eq!(materialize(&original_name, &reduced, &choice)?, dest);
        assert_eq!(dest.metadata()?.ino(), inode);
        assert!(materialize(&original_name, &cfg, &choice).is_err());
        let mut other = choice.clone();
        other["original"]["sha256"] = json!("wrong");
        assert!(materialize(&original_name, &reduced, &other).is_err());
        Ok(())
    }
}
