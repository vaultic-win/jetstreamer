//! Independent verification of the closed 226 assembly through a read-only view.
use super::*;

const STATE: &str = "/var/lib/jetstreamer/horizon226-postassembly-verification-v1";
const EXPECTATION: &str =
    "/var/lib/jetstreamer/horizon226-assembly-verification-evidence-v1/epoch-226.json";
const EXPECTATION_SHA: &str = "b71374bb2129aa8deb82d49477cbcebd29a9713d7785d706d001c9cd0a6e0b7f";
const FULL: &str = "/var/lib/jetstreamer/horizon-public-images-f14f41d9-v1/verify_archive";
const FULL_SHA: &str = "6848c44a949221f87312ed250b66f908e6e06e5f35e487b9ed7dad7333e1d773";
const PLUGIN: &str = "/var/lib/jetstreamer/horizon-public-images-f14f41d9-v1/horizon_pipeline";
const PLUGIN_SHA: &str = "e6af181f8271836ce30655ff4bc8646761a882528ccd38d63d1113a6d31b095b";
const FIRST: u64 = 97_632_000;
const LAST: u64 = 98_063_999;
const SLOTS: u64 = LAST - FIRST + 1;

fn validate_plugin(report: &Value, view: &Path, argv: &[String]) -> Result<()> {
    let row = &report["report"];
    ensure!(
        report["schema"] == "jetstreamer-horizon-plugin-playback-v1"
            && report["source"] == json!(view)
            && report["invocation"] == json!([vec![PLUGIN.to_owned()], argv.to_vec()].concat())
            && report["full_epoch_verified"] == true
            && report["expected_first_slot"] == FIRST
            && report["expected_last_slot"] == LAST
            && row["epoch"] == 226
            && row["first_slot"] == FIRST
            && row["last_slot"] == LAST
            && row["slots"] == SLOTS
            && row["worker_count"] == 1
            && row["stream_digest"].as_array().is_some_and(|bytes| {
                bytes.len() == 32
                    && bytes
                        .iter()
                        .all(|byte| byte.as_u64().is_some_and(|v| v <= 255))
            }),
        "epoch 226 plugin did not verify the exact complete archive"
    );
    Ok(())
}

fn stable_hash(archive: &Path) -> Result<(String, FileIdentity)> {
    let before = regular_identity(archive)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(archive)?;
    ensure!(
        before == identity(&file.metadata()?),
        "archive replaced before verification"
    );
    let mut digest = Sha256::new();
    let read = std::io::copy(&mut file, &mut digest)?;
    ensure!(
        read == before.length
            && identity(&file.metadata()?) == before
            && regular_identity(archive)? == before,
        "archive changed during verification hash"
    );
    Ok((hex_lower(&digest.finalize()), before))
}

fn capacity(plan: &Value, terminal: &Value) -> Result<()> {
    let fit_path = PathBuf::from(
        plan["roster"]["path"]
            .as_str()
            .context("missing verifier roster")?,
    );
    let fit = sealed_json(&plan["roster"], &fit_path)?;
    let at = fit["recorded_unix_seconds"]
        .as_u64()
        .context("missing verifier fit clock")?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let cap = &fit["capacity"];
    let quote = &fit["assembly_226_verification_quote"];
    ensure!(
        now.checked_sub(at).is_some_and(|age| age <= 900)
            && fit["schema"] == spec::VERIFY_SCHEMA
            && cap["fits"] == true
            && cap["candidate_total_memory_bytes"] == spec::VERIFY_MEMORY
            && cap["candidate_disk_bytes"] == spec::RECEIPTS
            && quote["terminal"] == *terminal
            && quote["candidate_cpus"] == json!([16, 17, 18, 19, 20, 21, 22, 23])
            && quote["producer_unit"] == spec::VERIFY_UNIT
            && quote["archive_copy_bytes"] == 0
            && singleton227_admission::disk_free()?
                >= cap["required_disk_bytes"]
                    .as_u64()
                    .context("missing verifier disk floor")?,
        "epoch 226 verification lacks a fresh protected roster"
    );
    let current = drain::show(spec::VERIFY_UNIT)?;
    let iid = env::var("INVOCATION_ID")?;
    ensure!(
        current["Id"] == spec::VERIFY_UNIT
            && current["ActiveState"] == "active"
            && current["SubState"] == "running"
            && current["InvocationID"] == iid
            && current["MainPID"] == std::process::id().to_string()
            && current["ControlGroup"] == format!("/system.slice/{}", spec::VERIFY_UNIT),
        "epoch 226 verifier is outside its admitted invocation"
    );
    suffix::check_cgroup(&current, spec::VERIFY_MEMORY)?;
    Ok(())
}

pub(crate) fn run() -> Result<()> {
    let args = env::args().collect::<Vec<_>>();
    let check = args.len() == 8 && args[7] == "--check";
    ensure!(
        unsafe { libc::geteuid() } == 0
            && (args.len() == 7 || check)
            && args[3] == "--plan-sha256"
            && args[5] == "--self-sha256",
        "usage: jetstreamer-r2 verify-epoch226-assembly PLAN --plan-sha256 HEX --self-sha256 HEX [--check]"
    );
    let state = Path::new(STATE);
    let state_info = state.symlink_metadata()?;
    ensure!(
        state.canonicalize()? == state
            && state_info.is_dir()
            && state_info.uid() == 0
            && state_info.mode() & 0o777 == 0o700,
        "epoch 226 verification state is not root private"
    );
    let self_path = fs::read_link("/proc/self/exe")?;
    suffix::bytes(
        &json!({"path":self_path,"sha256":args[6]}),
        &self_path,
        128 << 20,
    )?;
    let plan_path = state.join("plan.json");
    let plan_ref = json!({"path":args[2],"sha256":args[4]});
    let plan = sealed_json(&plan_ref, &plan_path)?;
    let terminal_path = path("terminal.json");
    let terminal = sealed_json(&plan["terminal"], &terminal_path)?;
    let registration = sealed_json(&terminal["launch"], &path("cadence-registration.json"))?;
    let iid = registration["invocation_id"]
        .as_str()
        .context("assembly invocation missing")?;
    let (_, exit) = drain::clean_success(spec::UNIT, iid)?;
    let archive = archive_identity()?.context("epoch 226 archive missing")?;
    ensure!(
        plan["schema"] == "foundation-epoch226-assembly-verification-plan-v1"
            && terminal["schema"] == "foundation-epoch226-assembly-terminal-v1"
            && terminal["guard_drained"] == true
            && terminal["scope"]["pid1_exit"] == exit
            && terminal["scope"]["archive"] == archive
            && terminal["publication_authorized"] == false,
        "epoch 226 plan is not bound to the closed archive"
    );
    let archive = PathBuf::from(archive["path"].as_str().context("missing archive path")?);
    let view = state.join("view");
    let canonical = view.join("epoch-226.jet");
    let mountinfo = fs::read_to_string("/proc/self/mountinfo")?;
    let mount = mountinfo
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let name = fields.nth(4)?;
            (Path::new(name) == canonical)
                .then(|| fields.next())
                .flatten()
        })
        .collect::<Vec<_>>();
    ensure!(
        mount.len() == 1
            && mount[0].split(',').any(|flag| flag == "ro")
            && regular_identity(&canonical)? == regular_identity(&archive)?
            && !archive.with_extension("jet.sha256").try_exists()?
            && !canonical.with_extension("jet.sha256").try_exists()?,
        "epoch 226 read-only canonical view does not match the private archive"
    );
    let expectation_ref = json!({"path":EXPECTATION,"sha256":EXPECTATION_SHA});
    let expected = sealed_json(&expectation_ref, Path::new(EXPECTATION))?;
    ensure!(
        expected["epoch"] == 226
            && expected["parent_slot"] == FIRST - 1
            && expected["terminal_slot"] == LAST,
        "wrong epoch 226 boundary expectation"
    );
    if check {
        println!(
            "{}",
            json!({"epoch":226,"terminal":plan["terminal"],"read_only_view":true,
            "verifiers_ran":false,"remote_mutations":false})
        );
        return Ok(());
    }
    capacity(&plan, &plan["terminal"])?;
    let expected_sha = terminal["scope"]["archive_sha256"]
        .as_str()
        .context("archive digest missing")?;
    ensure!(
        canonical_digest(&json!(expected_sha)),
        "invalid archive digest"
    );
    let before = stable_hash(&archive)?;
    ensure!(before.0 == expected_sha, "closed assembly SHA-256 differs");
    let full_argv = vec![
        canonical.to_string_lossy().into_owned(),
        "--full".into(),
        "--anchor".into(),
        (FIRST - 1).to_string(),
        expected["parent_blockhash"]
            .as_str()
            .context("parent hash")?
            .into(),
        "--expected-terminal".into(),
        LAST.to_string(),
        expected["terminal_blockhash"]
            .as_str()
            .context("terminal hash")?
            .into(),
        "--expected-provenance-sha256".into(),
        expected["provenance_sha256"]
            .as_str()
            .context("provenance digest")?
            .into(),
        "--threads".into(),
        "8".into(),
    ];
    let full_log = state.join("full.log");
    let full = resource_verify::run_bound_child(Path::new(FULL), FULL_SHA, &full_argv, &full_log)?;
    let full_text = fs::read_to_string(full_log)?;
    ensure!(
        full_text
            .lines()
            .filter(|line| line.trim() == "slot frames visited: 432,000")
            .count()
            == 1
            && full_text
                .lines()
                .any(|line| line.starts_with("RESULT: OK:")),
        "epoch 226 full scan did not report exact anchored coverage"
    );
    let full_ref = suffix::record(&state.join("full.json"), &full)?;

    let plugin_report = state.join("plugin-report.json");
    let plugin_argv = vec![
        "226".into(),
        view.to_string_lossy().into_owned(),
        "--verify-only".into(),
        "--threads".into(),
        "1".into(),
        "--verification-report".into(),
        plugin_report.to_string_lossy().into_owned(),
    ];
    let plugin = resource_verify::run_bound_child_with_stack(
        Path::new(PLUGIN),
        PLUGIN_SHA,
        &plugin_argv,
        &state.join("plugin.log"),
        67_108_864,
    )?;
    let plugin_raw = read_stable_bounded(&plugin_report, 1 << 20, "226 plugin report")?;
    validate_plugin(&serde_json::from_slice(&plugin_raw)?, &view, &plugin_argv)?;
    ensure!(
        stable_hash(&archive)? == before && regular_identity(&canonical)? == before.1,
        "epoch 226 archive changed across the two independent scans"
    );
    let (_, after_exit) = drain::clean_success(spec::UNIT, iid)?;
    ensure!(
        after_exit == exit,
        "epoch 226 producer closure changed during verification"
    );
    println!(
        "{}",
        suffix::record(
            &state.join("completion.json"),
            &json!({
                "schema":"foundation-epoch226-assembly-verification-v1","epoch":226,
                "invocation_id":env::var("INVOCATION_ID")?,"plan":plan_ref,"terminal":plan["terminal"],
                "archive":{"path":archive,"identity":before.1,"sha256":expected_sha},
                "expectation":expectation_ref,"full":full_ref,"plugin":plugin,
                "plugin_report":suffix::reference(&plugin_report,&plugin_raw),
                "independent_full_verified":true,"plugin_verified":true,
                "publication_authorized":false,"retirement_authorized":false,"r2_mutations":false
            })
        )?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plugin_report_is_bound_to_complete_coverage_and_exact_reader_arguments() -> Result<()> {
        let view = Path::new("/private/view");
        let argv = ["226".to_owned(), view.to_string_lossy().into_owned()];
        let mut report = json!({
            "schema":"jetstreamer-horizon-plugin-playback-v1","source":view,
            "invocation":[PLUGIN,&argv[0],&argv[1]],"full_epoch_verified":true,
            "expected_first_slot":FIRST,"expected_last_slot":LAST,
            "report":{"epoch":226,"first_slot":FIRST,"last_slot":LAST,"slots":SLOTS,
                      "worker_count":1,"stream_digest":vec![255;32]}
        });
        validate_plugin(&report, view, &argv)?;
        report["report"]["slots"] = json!(SLOTS - 1);
        assert!(validate_plugin(&report, view, &argv).is_err());
        report["report"]["slots"] = json!(SLOTS);
        report["report"]["stream_digest"][31] = json!(256);
        assert!(validate_plugin(&report, view, &argv).is_err());
        Ok(())
    }
}
