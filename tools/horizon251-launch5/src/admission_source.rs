//! Capture fresh admission documents from Main-reviewed, separately bound inputs.
//! No unit installation, replay start, archive access or R2 mutation.
use super::*;

fn save(root: &Path, name: &str, v: &Value) -> Result<Value> {
    save_at(root, name, &serde_json::to_vec_pretty(v)?)
}
fn review_values(v: &Value) -> Result<()> {
    ensure!(
        v["schema"] == "horizon251-main-admission-review-v1",
        "foreign Main review"
    );
    for k in [
        "Main_accepted",
        "no_overlapping_campaign_controller",
        "all_required_source_dependencies_reviewed",
        "smaller_fifth_profile_experiment_accepted",
    ] {
        yes(v, k)?;
    }
    ensure!(
        text(v, "launcher_unit")?.starts_with("horizon251-")
            && text(v, "launcher_unit")?.ends_with(".service"),
        "unexpected launcher unit"
    );
    Ok(())
}
fn publication(v: &Value, clock: u64) -> Result<()> {
    ensure!(
        v["schema"] == "horizon251-main-source-publication-v1"
            && v["remote_ref"] == "refs/heads/account-updates",
        "foreign source publication proof"
    );
    let t = number(v, "fetched_unix_seconds")?;
    ensure!(
        t <= clock && clock - t <= 1800,
        "source fetch is stale/future"
    );
    let head = text(v, "remote_head")?;
    ensure!(
        head.len() == 40 && head.bytes().all(|c| c.is_ascii_hexdigit()),
        "invalid remote head"
    );
    for k in [
        "all_required_dependencies_in_remote",
        "exact_deployed_source_provenance_reviewed",
        "no_untracked_required_source",
    ] {
        yes(v, k)?;
    }
    let rows = v["artifacts"].as_array().context("published artifacts")?;
    let mut roles = BTreeSet::new();
    for r in rows {
        let role = text(r, "role")?;
        ensure!(roles.insert(role), "duplicate source role");
        let commit = text(r, "source_commit")?;
        ensure!(
            commit.len() == 40 && commit.bytes().all(|c| c.is_ascii_hexdigit()),
            "invalid source commit"
        );
        yes(r, "contained_in_remote")?;
        bound(&r["provenance"])?;
        let p = Path::new(text(&r["artifact"], "path")?);
        let m = fs::symlink_metadata(p)?;
        ensure!(
            m.is_file() && m.uid() == 0 && m.mode() & 0o022 == 0 && p.canonicalize()? == p,
            "unsafe deployed source artifact"
        );
        ensure!(
            hash(p)? == text(&r["artifact"], "sha256")?,
            "published artifact differs"
        );
    }
    for role in [
        "node",
        "worker",
        "launcher",
        "guard",
        "sealer",
        "producer-template",
        "guard-template",
        "admission-capture",
    ] {
        ensure!(roles.contains(role), "missing required source role {role}");
    }
    for (role, expected) in [
        ("node", NODE.to_owned()),
        ("worker", WORKER.to_owned()),
        ("guard", GUARD.to_owned()),
        ("sealer", SEALER.to_owned()),
        ("producer-template", format!("{STATIC}/{UNIT}")),
        ("guard-template", format!("{STATIC}/{GUARD_UNIT}")),
        ("launcher", LAUNCHER.to_owned()),
        (
            "admission-capture",
            fs::canonicalize("/proc/self/exe")?
                .to_string_lossy()
                .into_owned(),
        ),
    ] {
        let r = rows
            .iter()
            .find(|r| r["role"] == role)
            .context("missing artifact")?;
        ensure!(
            r["artifact"]["path"] == expected,
            "source role does not bind selected artifact {role}"
        );
    }
    // Read-only Git checks supplement Main's authenticated fetch record. Never
    // infer publication from a commit label or a boolean in that record alone.
    let git = |args: &[&str]| -> Result<std::process::Output> {
        Ok(Command::new("/usr/bin/git")
            .args([
                "-c",
                "safe.directory=/home/ubuntu/workspace/jetstreamer",
                "-C",
                "/home/ubuntu/workspace/jetstreamer",
            ])
            .args(args)
            .output()?)
    };
    let current = git(&["rev-parse", "refs/remotes/origin/account-updates"])?;
    ensure!(
        current.status.success() && std::str::from_utf8(&current.stdout)?.trim() == head,
        "remote-tracking head changed since source review"
    );
    for r in rows {
        let result = git(&[
            "merge-base",
            "--is-ancestor",
            text(r, "source_commit")?,
            head,
        ])?;
        ensure!(
            result.status.success(),
            "required source is absent from fetched account-updates"
        );
    }
    Ok(())
}
fn sample_guard(o: &live::Owner, root: &Path) -> Result<Value> {
    let handoff = bound(&json!({"path":o.handoff,"sha256":o.handoff_sha}))?;
    let p = bound(&handoff["guard_plan"])?;
    let dir = Path::new(text(&p, "receipt_directory")?);
    let mut latest = None;
    for e in fs::read_dir(dir)? {
        let e = e?;
        let name = e.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("sample-") || !name.ends_with(".json") {
            continue;
        }
        let m = fs::symlink_metadata(e.path())?;
        ensure!(m.is_file(), "nonregular guard sample");
        let key = (m.mtime(), m.mtime_nsec());
        if latest.as_ref().is_none_or(|(old, _)| key > *old) {
            latest = Some((key, e.path()));
        }
    }
    let path = latest.context("no actual guard sample")?.1;
    let reference = pin(&path)?;
    let mut sample = bound(&reference)?;
    sample["captured_source_receipt"] = reference;
    let mut result = save(root, &format!("guard-{}.json", o.epoch), &sample)?;
    result["epoch"] = json!(o.epoch);
    Ok(result)
}
pub(super) fn capture(path: &str, sha: &str, self_sha: &str) -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "root required");
    ensure!(
        hash(Path::new("/proc/self/exe"))? == self_sha,
        "self mismatch"
    );
    let review_ref = json!({"path":path,"sha256":sha});
    let review = bound(&review_ref)?;
    review_values(&review)?;
    let source = bound(&review["source_publication"])?;
    publication(&source, now()?)?;
    // Main's published source record must bind the actual capture process.
    ensure!(
        source["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["role"] == "admission-capture" && r["artifact"]["sha256"] == self_sha),
        "capture source unbound"
    );
    let plan = bound(&review["launch_plan"])?;
    plan_validate(&plan)?;
    let obs = bound(&review["observer"])?;
    let fleet = bound(&review["fleet"])?;
    let century = bound(&review["century"])?;
    ensure!(
        century["schema"] == "horizon251-qualified-century-census-v1",
        "foreign century census"
    );
    let rows = &century["century_floor_census"];
    let floor = capacity::floor(rows)?;
    // The older verified census remains usable only if every current canonical pair agrees.
    let ready: BTreeMap<_, _> = fleet["inventory"]["entries"]
        .as_array()
        .context("fleet inventory")?
        .iter()
        .filter(|r| r["state"] == "ready-pair")
        .map(|r| {
            Ok((
                number(r, "epoch")?,
                (
                    number(r, "archive_length")?,
                    text(r, "sidecar_sha256")?.to_owned(),
                ),
            ))
        })
        .collect::<Result<_>>()?;
    ensure!(
        fleet["inventory"]["anomalies"] == 0
            && ready.len() == rows.as_array().context("century rows")?.len(),
        "changed century membership"
    );
    for r in rows.as_array().unwrap() {
        ensure!(
            ready.get(&number(r, "epoch")?)
                == Some(&(
                    number(r, "canonical_jet_bytes")?,
                    text(r, "archive_sha256")?.to_owned()
                )),
            "changed canonical archive"
        );
    }
    let root = Path::new(text(&review, "output_directory")?);
    ensure!(
        root.starts_with("/home/ubuntu/.codex/diagnostics") && root.is_absolute(),
        "unexpected admission directory"
    );
    directory(root, 0, 0o700)?;
    let mut a = bound(&review["admission_template"])?;
    ensure!(
        a["Main_accepted"] == false && a["schema"] == "horizon251-reboot-main-admission-five-v1",
        "not an unaccepted template"
    );
    a["launch_plan"] = review["launch_plan"].clone();
    a["launcher_unit"] = review["launcher_unit"].clone();
    a["source_publication"] = review["source_publication"].clone();
    a["Main_review"] = review_ref;
    a["coexisting_services"] = review["coexisting_services"].clone();
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .to_owned();
    let pid = number(&review, "main_controller_pid")?;
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let start = stat
        .rsplit_once(')')
        .context("proc framing")?
        .1
        .split_whitespace()
        .nth(19)
        .context("start ticks")?
        .parse::<u64>()?;
    ensure!(
        review["main_controller_start_ticks"] == start && review["boot_id"] == boot,
        "Main identity differs"
    );
    let owner = json!({"schema":"horizon251-main-owner-capture-v1","boot_id":boot,"main_controller_pid":pid,"main_controller_start_ticks":start,"review":a["Main_review"]});
    for k in [
        "boot_id",
        "main_controller_pid",
        "main_controller_start_ticks",
    ] {
        a[k] = owner[k].clone();
    }
    let timestamp = number(&obs["replays"][0]["useful_work"], "until_unix_seconds")?;
    let normalized = json!({"schema":"horizon251-normalized-observer-v1","source_sample":review["observer"],"observer_unix_seconds":timestamp,"host_memory_total_bytes":number(&obs["host_memory"],"total_kib")?.checked_mul(1024).context("memory overflow")?,"observed_available_bytes":obs["filesystem"]["conservative_available_bytes"]});
    for k in [
        "observer_unix_seconds",
        "host_memory_total_bytes",
        "observed_available_bytes",
    ] {
        a[k] = normalized[k].clone();
    }
    let normalized_fleet = json!({"schema":"horizon251-normalized-fleet-v1","source_fleet":review["fleet"],"actual_executing_before":fleet["memory_target"]["executing_lanes"],"initializing_before":0,"proven_operating_count":4});
    for k in [
        "actual_executing_before",
        "initializing_before",
        "proven_operating_count",
    ] {
        a[k] = normalized_fleet[k].clone();
    }
    for o in &live::OWNERS {
        a[format!("live{}_unit", o.epoch)] = json!(o.unit);
        a[format!("live{}_invocation_id", o.epoch)] = json!(o.iid);
        a[format!("live{}_handoff", o.epoch)] = json!({"path":o.handoff,"sha256":o.handoff_sha});
    }
    // Full native census captures all four exact owners and rejects unknown workers.
    let native = root.join("native");
    directory(&native, 0, 0o700)?;
    let mut n = Native::new(native);
    scope_census(&mut n, &a, false)?;
    let census = json!({"schema":"horizon251-main-native-census-v1","actual_executing_before":4,"initializing_before":0,"boot_id":boot,"coexisting_services":a["coexisting_services"],"native_command_directory":n.root,"native_capture_completed":true});
    let guards: Vec<_> = live::OWNERS
        .iter()
        .map(|o| sample_guard(o, root))
        .collect::<Result<_>>()?;
    let mut inherited = RETAINED_ROOT_OBLIGATION;
    for g in &guards {
        inherited = inherited.max(number(&bound(g)?, "minimum_free_bytes")?);
    }
    let guard_floor = inherited.max((4 * CAP).checked_add(floor).context("disk overflow")?);
    a["century_floor_bytes"] = json!(floor);
    a["guard_minimum_free_bytes"] = json!(guard_floor);
    a["required_initial_free_bytes"] =
        json!(guard_floor.checked_add(CAP).context("disk overflow")?);
    a["memory_obligation_after_bytes"] = json!(RETAINED_MEMORY_OBLIGATION);
    a["desired_replay_lanes"] = fleet["memory_target"]["desired_lanes"].clone();
    for k in [
        "Main_accepted",
        "complete_native_census_reviewed",
        "all_other_obligations_preserved",
        "fifth_lane_experiment_accepted",
        "fifth_lane_fit_proven",
        "clean_1800_second_observer",
        "current_guard_receipts_verified",
        "no_overlapping_campaign_controller",
        "first_guard_before_useful_work_required",
    ] {
        a[k] = json!(true);
    }
    let issued = now()?;
    a["issued_unix_seconds"] = json!(issued);
    a["expires_unix_seconds"] = json!(issued + 300);
    let mut cap = json!({"schema":"horizon251-main-capacity-v1","source_observer":review["observer"],"qualified_century_census":review["century"],"century_floor_census":rows,"allocation_credit_taken_bytes":0,"retained_full_root_claims_bytes":4*CAP,"guard_receipts":guards});
    for (_, fields) in evidence_fields().iter().filter(|(k, _)| *k == "capacity") {
        for k in *fields {
            cap[*k] = a[*k].clone();
        }
    }
    let docs = BTreeMap::from([
        ("owner", owner),
        ("observer", normalized),
        ("fleet", normalized_fleet),
        ("census", census),
        ("capacity", cap),
    ]);
    for (name, v) in &docs {
        a[*name] = save(root, &format!("{name}.json"), v)?;
    }
    for (source, fields) in evidence_fields() {
        for field in fields {
            a["evidence_claims"][source][*field] = json!(format!("/{field}"));
        }
    }
    // The exact same production validator checks every claim and fresh guard.
    validate_admission(&a, &review["launch_plan"])?;
    println!("{}", save(root, "admission.json", &a)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn main_review_cannot_be_implicit() {
        let mut r = json!({"schema":"horizon251-main-admission-review-v1","Main_accepted":true,"no_overlapping_campaign_controller":true,"all_required_source_dependencies_reviewed":true,"smaller_fifth_profile_experiment_accepted":true,"launcher_unit":"horizon251-fifth-launch.service"});
        review_values(&r).unwrap();
        for k in [
            "Main_accepted",
            "no_overlapping_campaign_controller",
            "all_required_source_dependencies_reviewed",
            "smaller_fifth_profile_experiment_accepted",
        ] {
            let old = r[k].take();
            r[k] = json!(false);
            assert!(review_values(&r).is_err());
            r[k] = old;
        }
    }
    #[test]
    fn stale_or_incomplete_publication_is_rejected() {
        let p = json!({"schema":"horizon251-main-source-publication-v1","remote_ref":"refs/heads/account-updates","fetched_unix_seconds":1000,"remote_head":"a".repeat(40),"all_required_dependencies_in_remote":true,"exact_deployed_source_provenance_reviewed":true,"no_untracked_required_source":true,"artifacts":[]});
        assert!(publication(&p, 999).is_err());
        assert!(publication(&p, 2801).is_err());
        assert!(publication(&p, 1100).is_err());
    }
}
