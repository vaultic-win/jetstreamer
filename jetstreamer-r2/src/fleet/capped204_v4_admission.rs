//! Fresh resources only for the separately sealed epoch 204 V4 bridge.
use super::*;
const VERIFY: &str = "horizon-full-verify-204-capped-v4-v1.service";
const PUBLISH: &str = "horizon-publish-204-capped-v4-v1.service";
const CAPABILITY: &str = "horizon-capped204-v4-capability-v1.service";
const RECOVERY: &str = "horizon-publish-204-capped-v4-recovery-v1.service";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    stage: String,
    delivery_plan: BoundFile,
    bridge_helper: BoundFile,
    unit_file: BoundFile,
    resource_basis: Value,
    output: PathBuf,
}
fn profile(stage: &str) -> Result<(&'static str, u64, u64, u64)> {
    Ok(match stage {
        "verify" => (VERIFY, 32 << 30, 64 << 30, 129 << 30),
        "publish" => (PUBLISH, 8 << 30, 16 << 30, 1 << 30),
        "capability" => (CAPABILITY, 8 << 30, 16 << 30, 1 << 30),
        "recover" => (RECOVERY, 8 << 30, 16 << 30, 1 << 30),
        _ => bail!("unsupported epoch 204 V4 admission stage"),
    })
}
fn token(p: &Path) -> Result<&str> {
    let s = p.to_str().context("epoch 204 path is not UTF-8")?;
    ensure!(
        p.is_absolute()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/-_.".contains(&b)),
        "epoch 204 unit path contains an expansion"
    );
    Ok(s)
}
fn file(b: &BoundFile, max: u64) -> Result<Vec<u8>> {
    let m = fs::symlink_metadata(&b.path)?;
    ensure!(
        b.path.canonicalize()? == b.path
            && m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0,
        "epoch 204 admission bound file is not sealed"
    );
    let bytes = read_stable_bounded(&b.path, max, "epoch 204 delivery file")?;
    ensure!(
        is_lower_hex(&b.sha256, 64)
            && hex_lower(&Sha256::digest(&bytes)) == b.sha256
            && identity(&m) == identity(&fs::symlink_metadata(&b.path)?),
        "epoch 204 file digest or identity differs"
    );
    Ok(bytes)
}
fn private(p: &Path, prefix: &str, empty: bool) -> Result<()> {
    let m = fs::symlink_metadata(p)?;
    ensure!(
        p.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && p.canonicalize()? == p
            && p.file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with(prefix))
            && m.is_dir()
            && m.uid() == 0
            && m.mode() & 0o777 == 0o700
            && (!empty || fs::read_dir(p)?.next().is_none()),
        "epoch 204 private metadata namespace differs"
    );
    Ok(())
}
fn layout(stage: &str, p: &Value, output: &Path) -> Result<()> {
    ensure!(
        p["admission_path"].as_str() == output.to_str(),
        "epoch 204 plan does not name this exact admission path"
    );
    match stage {
        "verify" => {
            ensure!(
                p["schema"] == "jetstreamer-capped204-v4-verification-plan-v1"
                    && p["epoch"] == 204
                    && p["publication_authorized"] == false,
                "epoch 204 verification plan scope differs"
            );
            private(
                Path::new(
                    p["private_directory"]
                        .as_str()
                        .context("epoch 204 copy directory missing")?,
                ),
                "horizon-capped204-v4-verify-",
                true,
            )?;
        }
        "publish" | "recover" => {
            ensure!(
                p["schema"]
                    == (if stage == "publish" {
                        "jetstreamer-capped204-v4-publication-plan-v1"
                    } else {
                        "jetstreamer-capped204-v4-recovery-plan-v1"
                    })
                    && p["epoch"] == 204
                    && p["artifact_publication_authorized"] == true,
                "epoch 204 publication plan scope differs"
            );
            for key in [
                "receipt_directory",
                "full_receipt_directory",
                "plugin_receipt_directory",
            ] {
                private(
                    Path::new(
                        p[key]
                            .as_str()
                            .context("epoch 204 receipt directory missing")?,
                    ),
                    "horizon-capped204-v4-",
                    true,
                )?;
            }
            if stage == "publish" {
                let work = Path::new(
                    p["publication_work_directory"]
                        .as_str()
                        .context("epoch 204 work directory missing")?,
                );
                let m = fs::symlink_metadata(work)?;
                ensure!(
                    work.parent() == Some(Path::new("/var/lib/jetstreamer"))
                        && work.canonicalize()? == work
                        && work
                            .file_name()
                            .and_then(|s| s.to_str())
                            .is_some_and(|s| s.starts_with("horizon-capped204-v4-publication-"))
                        && m.is_dir()
                        && m.uid() == 0
                        && m.mode() & 0o777 == 0o755
                        && fs::read_dir(work)?.next().is_none(),
                    "epoch 204 publication work parent is not fresh, root-owned and traversable"
                );
            }
        }
        "capability" => {
            ensure!(
                p["schema"] == "jetstreamer-capped204-v4-capability-plan-v1",
                "epoch 204 capability plan differs"
            );
            let root = Path::new(
                p["root"]
                    .as_str()
                    .context("epoch 204 capability root missing")?,
            );
            let m = fs::symlink_metadata(root)?;
            ensure!(
                root.parent() == Some(Path::new("/var/lib/jetstreamer"))
                    && root.canonicalize()? == root
                    && root
                        .file_name()
                        .and_then(|s| s.to_str())
                        .is_some_and(|s| s.starts_with("horizon-capped204-v4-capability-"))
                    && m.uid() == 0
                    && m.is_dir()
                    && m.mode() & 0o777 == 0o755
                    && fs::read_dir(root)?.next().is_none(),
                "epoch 204 capability root is not fresh and isolated"
            );
        }
        _ => bail!("unsupported epoch 204 delivery plan"),
    }
    if stage != "capability" {
        for key in [
            "runtime_registry_promotion_authorized",
            "retirement_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            ensure!(
                p[key] == false,
                "epoch 204 plan borrows unrelated authority: {key}"
            );
        }
    }
    Ok(())
}
fn unit_text(s: &Spec, p: &Value) -> Result<String> {
    let (_, high, max, _) = profile(&s.stage)?;
    let helper = token(&s.bridge_helper.path)?;
    let plan = token(&s.delivery_plan.path)?;
    let (sandbox, caps) = if s.stage == "verify" {
        let dir = token(Path::new(
            p["private_directory"]
                .as_str()
                .context("epoch 204 directory missing")?,
        ))?;
        (
            format!(
                "ProtectSystem=strict\nProtectHome=read-only\nPrivateMounts=no\nReadWritePaths={dir}\n"
            ),
            "CAP_DAC_READ_SEARCH CAP_SYS_PTRACE",
        )
    } else {
        (
            "ProtectSystem=no\nProtectHome=no\nPrivateMounts=no\n".into(),
            "CAP_DAC_READ_SEARCH CAP_CHOWN CAP_FOWNER CAP_SETUID CAP_SETGID",
        )
    };
    Ok(format!(
        "[Unit]\nDescription=Epoch 204 closed V4 {}\n\n[Service]\nType=exec\nUser=root\nGroup=root\nUMask=0077\nExecStart={helper} {} {plan} --plan-sha256 {} --self-sha256 {}\nRestart=no\nKillMode=control-group\nDelegate=no\nTimeoutStopSec=120\nRuntimeMaxSec=86400\nMemoryAccounting=yes\nMemoryHigh={high}\nMemoryMax={max}\nMemorySwapMax=0\nTasksAccounting=yes\nTasksMax=512\nCPUAccounting=yes\nCPUQuota=800%\nLimitCORE=0\nOOMPolicy=stop\nEnvironment=PATH=/usr/bin:/bin\nEnvironment=LC_ALL=C\nEnvironment=TOKIO_WORKER_THREADS=8\nEnvironment=RAYON_NUM_THREADS=8\nEnvironment=SOLANA_RAYON_THREADS=8\nNoNewPrivileges=yes\nCapabilityBoundingSet={caps}\nAmbientCapabilities={caps}\nPrivateNetwork=yes\nPrivateTmp=no\nPrivateDevices=yes\nProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectControlGroups=yes\n{sandbox}StandardOutput=journal\nStandardError=journal\n",
        s.stage, s.stage, s.delivery_plan.sha256, s.bridge_helper.sha256
    ))
}
fn properties(name: &str) -> Result<BTreeMap<String, String>> {
    let out=ProcessCommand::new("/usr/bin/systemctl").args(["show",name,"--no-pager",
        "--property=Id,Type,User,Group,Restart,FragmentPath,DropInPaths,NeedDaemonReload,Transient,MemoryHigh,MemoryMax,MemorySwapMax,TasksMax,ProtectHome,ProtectSystem,PrivateMounts"]).output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 1 << 20,
        "epoch 204 effective unit query failed"
    );
    let mut p = BTreeMap::new();
    for line in std::str::from_utf8(&out.stdout)?.lines() {
        let (k, v) = line
            .split_once('=')
            .context("epoch 204 malformed property")?;
        ensure!(
            p.insert(k.into(), v.into()).is_none(),
            "epoch 204 duplicate property"
        );
    }
    Ok(p)
}
fn effective(s: &Spec) -> Result<BTreeMap<String, String>> {
    let (name, high, max, _) = profile(&s.stage)?;
    let p = properties(name)?;
    for (key, expected) in [
        ("Id", name.into()),
        ("Type", "exec".into()),
        ("User", "root".into()),
        ("Group", "root".into()),
        ("Restart", "no".into()),
        ("FragmentPath", token(&s.unit_file.path)?.into()),
        ("DropInPaths", String::new()),
        ("NeedDaemonReload", "no".into()),
        ("Transient", "no".into()),
        ("MemoryHigh", high.to_string()),
        ("MemoryMax", max.to_string()),
        ("MemorySwapMax", "0".into()),
        ("TasksMax", "512".into()),
        ("PrivateMounts", "no".into()),
        (
            "ProtectHome",
            if s.stage == "verify" {
                "read-only".into()
            } else {
                "no".into()
            },
        ),
        (
            "ProtectSystem",
            if s.stage == "verify" {
                "strict".into()
            } else {
                "no".into()
            },
        ),
    ] {
        ensure!(
            p.get(key) == Some(&expected),
            "epoch 204 effective property differs: {key}"
        );
    }
    Ok(p)
}
fn inactive(census: &BTreeMap<String, Value>) -> Result<()> {
    for name in [VERIFY, PUBLISH, CAPABILITY, RECOVERY] {
        let u = &census[name];
        ensure!(
            u["MainPID"] == "0"
                && u["NRestarts"] == "0"
                && matches!(u["ActiveState"].as_str(), Some("inactive" | "failed"))
                && matches!(u["SubState"].as_str(), Some("dead" | "failed")),
            "epoch 204 delivery helper is active or restarted"
        );
    }
    Ok(())
}
fn pending() -> Result<()> {
    let out = ProcessCommand::new("/usr/bin/systemctl")
        .args([
            "list-jobs",
            "--no-legend",
            "--no-pager",
            "--plain",
            "--full",
        ])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 1 << 20,
        "epoch 204 queued job query failed"
    );
    let jobs = inactive_status::queued_job_units(&out.stdout)?;
    ensure!(
        !jobs
            .iter()
            .any(|s| [VERIFY, PUBLISH, CAPABILITY, RECOVERY].contains(s)),
        "epoch 204 delivery helper start is pending"
    );
    Ok(())
}
pub(super) fn run() -> Result<()> {
    let (binding, self_sha) = publication203::parsed_args("admit-capped204-v4-delivery")?;
    let s: Spec = serde_json::from_value(native209::immutable_json(&binding)?)?;
    let (name, _, memory, disk) = profile(&s.stage)?;
    ensure!(
        s.schema == "jetstreamer-capped204-v4-delivery-admission-spec-v1"
            && s.output.file_name().is_some_and(|s| s == "admission.json")
            && s.output.parent().and_then(Path::parent) == Some(Path::new("/var/lib/jetstreamer"))
            && s.output
                .parent()
                .and_then(Path::file_name)
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("horizon-capped204-v4-admission-"))
            && s.unit_file.path == Path::new("/etc/systemd/system").join(name),
        "epoch 204 admission scope differs"
    );
    validate_output_destination(&s.output)?;
    let p = native209::immutable_json(&s.delivery_plan)?;
    ensure!(
        p["admission_helper"]["sha256"] == self_sha,
        "epoch 204 plan is not bound to this admission helper"
    );
    layout(&s.stage, &p, &s.output)?;
    ensure!(
        s.bridge_helper
            .path
            .file_name()
            .is_some_and(|n| n == "jetstreamer-capped204-v4-delivery")
            && s.bridge_helper
                .path
                .parent()
                .and_then(Path::file_name)
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-capped204-v4-tools-")),
        "epoch 204 bridge is outside its sealed package namespace"
    );
    native209_admission::sealed_file(&s.bridge_helper.path, &s.bridge_helper.sha256, None)?;
    let expected = unit_text(&s, &p)?;
    ensure!(
        file(&s.unit_file, 64 << 10)? == expected.as_bytes(),
        "epoch 204 unit differs from its bounded profile"
    );
    let fbound: BoundFile = serde_json::from_value(s.resource_basis["fleet"].clone())?;
    let f = bound_json(&fbound)?;
    if s.stage != "capability" {
        ensure!(
            !f["active"]
                .as_array()
                .context("epoch 204 active ledger missing")?
                .iter()
                .any(|r| r["epoch"] == 204),
            "epoch 204 still has an active producer or downstream owner"
        );
    }
    let mut names = f["unit_census"]
        .as_object()
        .context("epoch 204 complete unit census missing")?
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    names.extend(
        [VERIFY, PUBLISH, CAPABILITY, RECOVERY]
            .into_iter()
            .map(str::to_owned),
    );
    let before = census(&names, 201, 300)?;
    inactive(&before)?;
    pending()?;
    let props = effective(&s)?;
    let capacity = maintenance_capacity::check_capped204_v4_delivery(
        &s.resource_basis,
        &s.stage,
        singleton227_admission::century_floor_for_maintenance(&f)?,
    )?;
    let after = census(&names, 201, 300)?;
    inactive(&after)?;
    pending()?;
    ensure!(
        before == after
            && props == effective(&s)?
            && file(&s.unit_file, 64 << 10)? == expected.as_bytes(),
        "epoch 204 owners, limits or unit changed across admission"
    );
    layout(&s.stage, &p, &s.output)?;
    native209_admission::sealed_file(&s.bridge_helper.path, &s.bridge_helper.sha256, None)?;
    private157::immutable_receipt(
        &s.output,
        &json!({"schema":"jetstreamer-capped204-v4-delivery-admission-v1",
        "epoch":204,"stage":s.stage,"admitted":true,"maximum_age_seconds":900,
        "recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        "delivery_plan":private157::binding(&s.delivery_plan),"bridge_helper_sha256":s.bridge_helper.sha256,
        "control_helper_sha256":self_sha,"candidate_hard_memory_bytes":memory,"candidate_incremental_disk_bytes":disk,
        "capacity":capacity,"unit_census_before":before,"unit_census_after":after,"effective_unit":props,
        "unit_file":private157::binding(&s.unit_file),"spec":private157::binding(&binding),"resource_samples_taken":0,
        "archive_qualification_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn closed_stage_and_memory_caps_reject_other_epochs_and_unbounded_profiles() {
        assert_eq!(profile("verify").unwrap().2, 64 << 30);
        assert_eq!(profile("publish").unwrap().3, 1 << 30);
        assert!(profile("upload").is_err());
        assert!(profile("301").is_err());
        assert!(token(Path::new("/sealed/bad%204")).is_err());
        assert!(token(Path::new("/sealed/a 204")).is_err());
    }
}
