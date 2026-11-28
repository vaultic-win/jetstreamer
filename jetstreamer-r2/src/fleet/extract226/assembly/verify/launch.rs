//! Admit the bounded, read-only verifier and release its exact invocation.
use super::*;

const RELEASE_SCHEMA: &str = "foundation-epoch226-verification-fleet-release-v1";
const FIXTURE_UNIT: &str = "test-foundation-226-verification-sandbox-v1.service";
const CHECK_UNIT: &str = "test-foundation-226-verification-production-preflight-v1.service";

fn service_args(unit: &str, image: &Value, plan: &Value, check: bool) -> Result<Vec<String>> {
    let state = Path::new(spec::VERIFY_STATE);
    let archive = Path::new(spec::ROOT).join(ARCHIVE);
    let view = state.join("view/epoch-226.jet");
    let mut args = vec![
        format!("--unit={unit}"),
        "--slice=system.slice".into(),
        if check { "--wait" } else { "--no-block" }.into(),
    ];
    for property in [
        "Type=exec",
        "User=root",
        "Group=root",
        "UMask=0077",
        "Restart=no",
        "KillMode=control-group",
        "Delegate=no",
        "CPUQuota=800%",
        "MemorySwapMax=0",
        "TasksMax=512",
        "LimitFSIZE=64M",
        "RuntimeMaxSec=12h",
        "TimeoutStopSec=30",
        "ProtectSystem=strict",
        "ProtectHome=read-only",
        "ProtectControlGroups=yes",
        "PrivateTmp=yes",
        "PrivateNetwork=yes",
        "NoNewPrivileges=yes",
        "RestrictAddressFamilies=AF_UNIX",
        "CapabilityBoundingSet=CAP_DAC_OVERRIDE",
        "AmbientCapabilities=CAP_DAC_OVERRIDE",
        "UnsetEnvironment=HORIZON_S3_ENDPOINT HORIZON_ACCESS_KEY_ID HORIZON_SECRET_ACCESS_KEY HORIZON_PUBLIC_BASE_URL AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN",
    ] {
        args.push(format!("--property={property}"));
    }
    args.extend([
        format!("--property=AllowedCPUs={}", spec::CPUS),
        format!("--property=CPUAffinity={}", spec::CPUS),
        format!("--property=MemoryHigh={}", spec::VERIFY_MEMORY),
        format!("--property=MemoryMax={}", spec::VERIFY_MEMORY),
        format!("--property=ReadWritePaths={}", state.display()),
        format!(
            "--property=BindReadOnlyPaths={}:{}",
            archive.display(),
            view.display()
        ),
        "--".into(),
        spec::VERIFY_IMAGE.into(),
        "verify-epoch226-assembly".into(),
        state.join("plan.json").display().to_string(),
        "--plan-sha256".into(),
        plan["sha256"]
            .as_str()
            .context("verifier plan digest")?
            .into(),
        "--self-sha256".into(),
        image["sha256"]
            .as_str()
            .context("verifier image digest")?
            .into(),
    ]);
    if check {
        args.push("--check".into());
    }
    Ok(args)
}

fn release() -> Result<Value> {
    let release = suffix::document(Path::new(spec::VERIFY_RELEASE))?;
    ensure!(
        release["schema"] == RELEASE_SCHEMA
            && release["publication_authorized"] == false
            && canonical_digest(&release["controller"]["sha256"])
            && canonical_digest(&release["observer"]["sha256"]),
        "epoch 226 verification fleet release differs"
    );
    let control = Path::new(drain::CYCLE_LOCK).with_file_name("cycle.py");
    suffix::bytes(&release["controller"], &control, 1 << 20)?;
    let image = Path::new(spec::VERIFY_IMAGE);
    ensure!(
        env::current_exe()? == image,
        "epoch 226 verification launcher is outside its release"
    );
    suffix::bytes(&release["runner"], image, 128 << 20)?;
    let evidence = PathBuf::from(
        release["sandbox"]["path"]
            .as_str()
            .context("verifier sandbox path")?,
    );
    let sandbox = sealed_json(&release["sandbox"], &evidence)?;
    let sandbox_invocation = sandbox["invocation_id"]
        .as_str()
        .context("verifier fixture invocation")?;
    ensure!(
        sandbox["schema"] == "foundation-epoch226-reader-sandbox-fixture-v1"
            && sandbox["unit"] == FIXTURE_UNIT
            && iid(&sandbox["invocation_id"])
            && sandbox["read_only_same_inode"] == true
            && sandbox["only_dac_override_effective"] == true
            && sandbox["network_disabled"] == true
            && sandbox["production_executed"] == false
            && sandbox["limits"]["memory.max"] == spec::VERIFY_MEMORY.to_string()
            && sandbox["limits"]["cpuset.cpus.effective"] == spec::CPUS,
        "epoch 226 verifier sandbox proof differs"
    );
    drain::clean_success(FIXTURE_UNIT, sandbox_invocation)?;
    Ok(release)
}

pub(crate) fn run() -> Result<()> {
    let args: Vec<_> = env::args().collect();
    ensure!(
        unsafe { libc::geteuid() } == 0
            && args.len() == 3
            && matches!(args[2].as_str(), "--check" | "--apply"),
        "usage: jetstreamer-r2 launch-epoch226-verification --check|--apply"
    );
    if args[2] == "--check" {
        let release = release()?;
        service_args(
            spec::VERIFY_UNIT,
            &release["runner"],
            &json!({"sha256":"0".repeat(64)}),
            false,
        )?;
        println!(
            "{}",
            json!({"epoch":226,"fleet_release_verified":true,"launched":false})
        );
        return Ok(());
    }
    ensure!(
        env::var("CODEX_THREAD_ID").as_deref() == Ok(suffix::THREAD),
        "Foundation controller changed"
    );
    let _lock = suffix::cadence_lock()?;
    ensure!(
        drain::show(suffix::CADENCE)?["ActiveState"] == "inactive"
            && drain::show(suffix::CADENCE_TIMER)?["ActiveState"] == "active",
        "epoch 226 verification requires the existing idle fleet cadence"
    );
    let release = release()?;
    let state = Path::new(spec::VERIFY_STATE);
    let registration = state.join("cadence-registration.json");
    if registration.try_exists()? {
        let previous = suffix::document(&registration)?;
        ensure!(
            previous["schema"] == spec::VERIFY_LAUNCH
                && previous["image"] == release["runner"]
                && previous["actual"]["Id"] == spec::VERIFY_UNIT,
            "foreign epoch 226 verification registration"
        );
        println!("{}", private157::file_binding(&registration)?);
        return Ok(());
    }
    let unit = drain::show(spec::VERIFY_UNIT)?;
    ensure!(
        unit["LoadState"] == "not-found" && drain::quiet_service(spec::VERIFY_UNIT, &unit),
        "epoch 226 verification already has a service owner"
    );
    let terminal = private157::file_binding(&path("terminal.json"))?;
    let roster = foundation_roster::quote_226_verification()?;
    ensure!(
        roster["schema"] == spec::VERIFY_SCHEMA
            && roster["capacity"]["fits"] == true
            && roster["assembly_226_verification_quote"]["terminal"] == terminal,
        "epoch 226 verification does not fit the complete current roster"
    );
    let plan_path = state.join("plan.json");
    ensure!(
        !plan_path.try_exists()? && !state.join("roster.json").try_exists()?,
        "retained epoch 226 verification intent requires reconciliation"
    );
    let fit_ref = suffix::record(&state.join("roster.json"), &roster)?;
    let plan = json!({"schema":spec::VERIFY_PLAN,"epoch":226,"terminal":terminal,"roster":fit_ref});
    let plan_ref = suffix::record(&plan_path, &plan)?;
    let preflight = ProcessCommand::new("/usr/bin/systemd-run")
        .args(service_args(
            CHECK_UNIT,
            &release["runner"],
            &plan_ref,
            true,
        )?)
        .status()?;
    ensure!(
        preflight.success(),
        "epoch 226 verifier production bind preflight failed"
    );
    fit(&plan, &terminal)?;
    let result = ProcessCommand::new("/usr/bin/systemd-run")
        .args(service_args(
            spec::VERIFY_UNIT,
            &release["runner"],
            &plan_ref,
            false,
        )?)
        .status()?;
    ensure!(
        result.success(),
        "epoch 226 verifier service could not be queued"
    );
    let actual = suffix::wait(20, "epoch 226 verifier manager owner", || {
        let owner = drain::show(spec::VERIFY_UNIT)?;
        Ok((owner["ActiveState"] == "active"
            && owner["SubState"] == "running"
            && iid(&owner["InvocationID"])
            && owner["MainPID"]
                .as_str()
                .and_then(|pid| pid.parse::<u32>().ok())
                .is_some_and(|pid| pid > 1))
        .then_some(owner))
    })?;
    suffix::check_cgroup(&actual, spec::VERIFY_MEMORY)?;
    let pid = actual["MainPID"]
        .as_str()
        .context("missing verifier MainPID")?;
    ensure!(
        fs::read_link(format!("/proc/{pid}/exe"))? == Path::new(spec::VERIFY_IMAGE),
        "epoch 226 verifier mapped image differs"
    );
    let row = json!({
        "schema":spec::VERIFY_LAUNCH,"epoch":226,"image":release["runner"],
        "plan":plan_ref,"terminal":terminal,"roster":fit_ref,"actual":actual,
        "publication_authorized":false,"archive_copy_bytes":0
    });
    println!("{}", suffix::record(&registration, &row)?);
    Ok(())
}
