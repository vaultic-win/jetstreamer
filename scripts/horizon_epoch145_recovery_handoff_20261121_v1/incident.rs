//! Follow the funded semantic reader through local verification and publication.
use super::*;
use std::os::unix::{fs::FileTypeExt, process::CommandExt};
use std::process::Stdio;

use generation::*;
const POST: &str = "epoch145-publication-20261121-v1";
const FLEET: &str = "ROOT_COMPLETE_OPERATIONAL_FLEET.json";
#[cfg(not(feature = "cadence-rejoin"))]
const FLEET_DIRECTORY: &str = "root131959-live166167170-20261121-v1";
#[cfg(all(feature = "cadence-rejoin", not(feature = "timer-rejoin")))]
const FLEET_DIRECTORY: &str = "root213922-live166167170-20261121-v1";
#[cfg(all(feature = "cadence-rejoin", not(feature = "timer-rejoin")))]
const HEAD: &str = "bc403aec3d9546b6ed39b58174c18c40606756722a3163044c6a704282a2b15e";
#[cfg(not(feature = "cadence-rejoin"))]
const HEAD: &str = "973b1d0d30142d26d524386c50429a5d121103dfce3190d476a6eb23fe1feadd";
#[cfg(not(any(feature = "timeout-rejoin", feature = "cadence-rejoin")))]
mod generation {
    pub(super) const SOURCE: &str = "dc043eb78c4a4349b0098760dc764a1f";
    pub(super) const START: &str =
        "epoch145-semantic-continuity-20261121-v1/V5B_ACTUAL_ADVANCING_WORKER.json";
    pub(super) const ADVANCING: &str =
        "c8c4a5572906fb348658759ed4c81a7edaf4ee790faab391d700ad9fd4e4c199";
    pub(super) const PKG: &str = "epoch145-semantic-continuity-20261121-v1/tools-v7";
    pub(super) const SEAL: &str =
        "815df6ea2b602a2c6e17a56dfd38af4145e046b63e2e55f440221fcf7c0f568f";
    pub(super) const STATE_PATH: &str = "epoch145-v5b-delivery-handoff-20261121-v1/state";
    pub(super) const FIT_PKG: &str = "incident-replay-fit-20261121-v1/tools-v7";
    pub(super) const FIT_SEAL: &str =
        "680021c25c633362855b0380cbce500a318c8fc72bda2ef28c072e316d18b66d";
    pub(super) const PRIOR: &str = "5e0e20bc974149f096ea4bab10b15e1b";
    pub(super) const IMAGE: &str =
        "710b9c840fe26d964874fa6fadc2b0be9fc59d011755ce5da57a46c6ca2349f1";
    pub(super) const SEMANTIC: &str =
        "epoch145-semantic-continuity-20261121-v1/tools-v5b/export145";
    pub(super) const PIPELINE: &str =
        "8822f0ba8391ea0be3a5f6cb0970dd264352dcfe0b075efc536d915d2763787e";
    pub(super) const INSPECT: &str = "inspect-v5b";
    pub(super) const FOLLOW: &str = "follow-v5b";
}

#[cfg(all(feature = "timeout-rejoin", not(feature = "cadence-rejoin")))]
mod generation {
    pub(super) const SOURCE: &str = "d37f36f898a44932a19fd50d7014a6fe";
    pub(super) const START: &str =
        "epoch145-semantic-continuity-20261121-v1/V5C_ACTUAL_ADVANCING_WORKER.json";
    pub(super) const ADVANCING: &str =
        "6235fbd8e36064d57a9cd6b7af2ad0d05ce8b41766134cde7be7337ebc133d76";
    pub(super) const PKG: &str = "epoch145-semantic-continuity-20261121-v1/tools-v8";
    pub(super) const SEAL: &str =
        "972bb0747591e741b761671a272e536694d6039b870d627f5fac8f87cbab0e0f";
    pub(super) const STATE_PATH: &str = "epoch145-v5c-delivery-handoff-20261121-v1/state";
    pub(super) const FIT_PKG: &str = "incident-replay-fit-20261121-v1/tools-v11";
    pub(super) const FIT_SEAL: &str =
        "50a46e9010b448f2e038300c7aa5ffcdf38bf36ff4caf9bd783fe76ae513f4dc";
    pub(super) const PRIOR: &str = "dc043eb78c4a4349b0098760dc764a1f";
    pub(super) const IMAGE: &str =
        "34d90f2a5ae8a821109b2bbf99c5527d43c3eb141f68cea212109fc876f28c8d";
    pub(super) const SEMANTIC: &str =
        "epoch145-semantic-continuity-20261121-v1/tools-v5c/export145";
    pub(super) const PIPELINE: &str =
        "56bf2bf0937f1b90de8de0519c0a572b06a8ed62cb9e14bf9e9f0fa8021ed916";
    pub(super) const INSPECT: &str = "inspect-v5c";
    pub(super) const FOLLOW: &str = "follow-v5c";
}

#[cfg(all(feature = "cadence-rejoin", not(feature = "timer-rejoin")))]
mod generation {
    pub(super) const SOURCE: &str = "e6551a0bb8a14b989902e15c9ecc0751";
    pub(super) const START: &str =
        "epoch145-semantic-continuity-20261121-v1/V5D_RETRY1_ACTUAL_ADVANCING_WORKER.json";
    pub(super) const ADVANCING: &str =
        "3a41dac31746938b482133b9ff224f9d9d821569cc16f63c83f872fe907c13e0";
    pub(super) const PKG: &str = "epoch145-semantic-continuity-20261121-v1/tools-v10";
    pub(super) const SEAL: &str =
        "1dd8bea17cc568ae34d7cc60b80e1ffd4486840527a16c85a6de6386e98f6391";
    pub(super) const STATE_PATH: &str = "epoch145-v5d-retry1-delivery-handoff-20261121-v1/state";
    pub(super) const FIT_PKG: &str = "incident-replay-fit-20261121-v1/tools-v15";
    pub(super) const FIT_SEAL: &str =
        "7f887c933698d424cd69244dede860f62cea2759a83f9edacc96f09c60c75eb6";
    pub(super) const PRIOR: &str = "500c8d717a4147b087ff302b5afa7fc0";
    pub(super) const IMAGE: &str =
        "3d60de86d45a497bcd1b9836c485ffab4ce1da19cb6d989d56c9d3b92ad60066";
    pub(super) const SEMANTIC: &str =
        "epoch145-semantic-continuity-20261121-v1/tools-v5d/export145";
    pub(super) const PIPELINE: &str =
        "56bf2bf0937f1b90de8de0519c0a572b06a8ed62cb9e14bf9e9f0fa8021ed916";
    pub(super) const INSPECT: &str = "inspect-v5d";
    pub(super) const FOLLOW: &str = "follow-v5d";
}

// Each value is derived from the sealed worker, its accepted fleet and its
// qualified post driver at build time. The deployment receipt binds that
// input manifest alongside the native live-inspection result.
#[cfg(feature = "timer-rejoin")]
const FLEET_DIRECTORY: &str = env!("HORIZON_145_ACCEPTED_FLEET_DIRECTORY");
#[cfg(feature = "timer-rejoin")]
const HEAD: &str = env!("HORIZON_145_ACCEPTED_FLEET_SHA256");

#[cfg(all(feature = "timer-rejoin", not(feature = "fixture-post")))]
mod generation {
    pub(super) const SOURCE: &str = env!("HORIZON_145_SEMANTIC_INVOCATION");
    pub(super) const START: &str =
        "epoch145-semantic-continuity-20261121-v1/V5E_ACTUAL_ADVANCING_WORKER.json";
    pub(super) const ADVANCING: &str = env!("HORIZON_145_ADVANCING_SHA256");
    #[cfg(not(feature = "registered-post"))]
    pub(super) const PKG: &str = "epoch145-semantic-continuity-20261121-v1/tools-v11";
    #[cfg(feature = "registered-post")]
    pub(super) const PKG: &str = "epoch145-semantic-continuity-20261121-v1/tools-v12";
    pub(super) const SEAL: &str = env!("HORIZON_145_POST_SEAL_SHA256");
    pub(super) const STATE_PATH: &str = "epoch145-v5e-delivery-handoff-20261121-v1/state";
    #[cfg(not(feature = "registered-post"))]
    pub(super) const FIT_PKG: &str = "incident-replay-fit-20261121-v1/tools-v17";
    #[cfg(feature = "registered-post")]
    pub(super) const FIT_PKG: &str = "incident-replay-fit-20261121-v1/tools-v19";
    pub(super) const FIT_SEAL: &str = env!("HORIZON_145_FIT_SEAL_SHA256");
    pub(super) const PRIOR: &str = "e6551a0bb8a14b989902e15c9ecc0751";
    pub(super) const IMAGE: &str =
        "148804337a0c47093f67ae642fe01dc3a529cb07dbc809bfd9ab0ff9ca714a7c";
    pub(super) const SEMANTIC: &str =
        "epoch145-semantic-continuity-20261121-v1/tools-v5e/export145";
    pub(super) const PIPELINE: &str =
        "0f29fd116ef54668698089c01f8cd50ffcf729b430e311bb90b989f4d5ad8e94";
    pub(super) const INSPECT: &str = "inspect-v5e";
    pub(super) const FOLLOW: &str = "follow-v5e";
}

#[cfg(feature = "fixture-post")]
pub(super) mod generation {
    #[cfg(not(feature = "retry-post"))]
    mod selected {
        pub(crate) const SOURCE: &str = "50af3d8ab5da47e8bdc2828feab53908";
        pub(crate) const START: &str =
            "epoch145-semantic-continuity-20261121-v1/V5F_ACTUAL_ADVANCING_WORKER.json";
        pub(crate) const MANAGER: &str =
            "epoch145-semantic-continuity-20261121-v1/V5F_ACTUAL_MANAGER.json";
        pub(crate) const ADVANCING: &str =
            "a2a888054492a2be68c5e332ae36daa070b9688c143005cbc97e5cace7cfd496";
        pub(crate) const PKG: &str = "epoch145-semantic-continuity-20261121-v1/tools-v13b";
        pub(crate) const STATE_PATH: &str = "epoch145-fixture-phase-dispatch-20261122-v1/state";
        pub(crate) const FIT_PKG: &str = "incident-replay-fit-20261121-v1/tools-v21b";
        pub(crate) const PRIOR: &str = "a99ed8b51e8a482b805b8a36a11b2700";
        pub(crate) const FAILURE: &str =
            "da29d82a4349444ccc15e0be020aa12918ae5bbb4634f9b62e13cc83a93c5f43";
    }
    #[cfg(all(feature = "retry-post", not(feature = "v5n-136-post")))]
    mod selected {
        pub(crate) const SOURCE: &str = "afcf6cdd1ec0400ea2757f81472987b3";
        pub(crate) const START: &str =
            "epoch145-semantic-continuity-20261121-v1/V5F_RETRY1_ACTUAL_ADVANCING_WORKER.json";
        pub(crate) const MANAGER: &str =
            "epoch145-semantic-continuity-20261121-v1/V5F_RETRY1_ACTUAL_MANAGER.json";
        pub(crate) const ADVANCING: &str =
            "1b16ce2d061e2ec97ab8c1ba81cd2dbcff9d0a759f317fbaf53b64e731a19501";
        pub(crate) const PKG: &str = "epoch145-semantic-continuity-20261121-v1/tools-v13c";
        pub(crate) const STATE_PATH: &str = "epoch145-fixture-retry1-dispatch-20261122-v1/state";
        pub(crate) const FIT_PKG: &str = "incident-replay-fit-20261121-v1/tools-v23";
        pub(crate) const PRIOR: &str = "50af3d8ab5da47e8bdc2828feab53908";
        pub(crate) const FAILURE: &str =
            "38d828362fed1910cc60c605200380576c165168738dbf00520ce2b2522a0fcd";
    }
    #[cfg(feature = "v5n-136-post")]
    mod selected {
        pub(crate) const SOURCE: &str = "f86e7e61f4b34dc7aedc4e08a128e713";
        pub(crate) const START: &str =
            "epoch145-semantic-continuity-20261121-v1/v5n-name-handoff/submission-result.json";
        pub(crate) const ADVANCING: &str =
            "57eb2aadef0bd6e5591800c439fa0f2e6d701c2f4baa3dc45b5074fdddebd02e";
        pub(crate) const PKG: &str = "epoch145-semantic-continuity-20261121-v1/tools-v13h";
        pub(crate) const STATE_PATH: &str = "epoch145-v5n-136-dispatch-20261123-v1/state";
        pub(crate) const FIT_PKG: &str =
            "incident-replay-fit-20261121-v1/tools-homefloor-145-post-v5n-136-v1";
    }
    pub(crate) use selected::*;
    pub(crate) const SEAL: &str = env!("HORIZON_145_POST_SEAL_SHA256");
    pub(crate) const FIT_SEAL: &str = env!("HORIZON_145_FIT_SEAL_SHA256");
    #[cfg(not(feature = "v5n-136-post"))]
    pub(crate) const IMAGE: &str =
        "016f1beab41795dae2bbaa1cef5173773eeafae617a5f5db92ebd4aaa1887c21";
    #[cfg(not(feature = "v5n-136-post"))]
    pub(crate) const SEMANTIC: &str =
        "epoch145-semantic-continuity-20261121-v1/tools-v5f/export145";
    #[cfg(feature = "v5n-136-post")]
    pub(crate) const IMAGE: &str =
        "d6bc752180c265f6d680464ffec7ac2cc6bc4125440ef6ac1bb43534f3db2c34";
    #[cfg(feature = "v5n-136-post")]
    pub(crate) const SEMANTIC: &str =
        "epoch145-semantic-continuity-20261121-v1/tools-v5n/export145";
    pub(crate) const PIPELINE: &str =
        "0f29fd116ef54668698089c01f8cd50ffcf729b430e311bb90b989f4d5ad8e94";
    pub(crate) const INSPECT: &str = if cfg!(feature = "v5n-136-post") {
        "inspect-v5n"
    } else {
        "inspect-v5f"
    };
    pub(crate) const FOLLOW: &str = if cfg!(feature = "v5n-136-post") {
        "follow-v5n"
    } else {
        "follow-v5f"
    };
}

pub fn handles(mode: &str) -> bool {
    mode == INSPECT || mode == FOLLOW
}

pub(super) fn fleet() -> Result<Value> {
    let mut dir = rt(FLEET_DIRECTORY);
    let mut at = json!({"path":dir.join(FLEET),"sha256":HEAD});
    loop {
        let body = from_ref(&at)?;
        ensure!(
            body["owner"] == "/root"
                && body["schema"] == "horizon-Root-complete-fleet-operational-review-v1",
            "foreign fleet"
        );
        let next = outcome::next(&body)?;
        ensure!(
            next.parent() != Some(dir.as_path()),
            "self-referential successor"
        );
        if !next.try_exists()? {
            return Ok(at);
        }
        let r = bound(&next)?;
        let n = from_ref(&r)?;
        ensure!(
            n["previous_Root_operational_review"] == at
                && n["recorded_unix_seconds"]
                    .as_u64()
                    .context("successor time")?
                    > body["recorded_unix_seconds"]
                        .as_u64()
                        .context("fleet time")?,
            "different or nonchronological fleet successor"
        );
        dir = next.parent().context("fleet directory")?.to_owned();
        at = r;
    }
}
/// Only a successful complete current booking can submit either next stage.
fn funded(boundary: impl Fn() -> Result<Option<fs::File>>) -> Result<(Value, Option<fs::File>)> {
    let pkg = rt(FIT_PKG);
    let reader = check_member(&pkg, FIT_SEAL, "post-stop-fit")?;
    loop {
        let operation = boundary()?;
        let head = fleet()?;
        let out = Command::new(&reader)
            .args(["145", text(&head["path"])?, text(&head["sha256"])?])
            .output()?;
        if !out.status.success()
            && String::from_utf8_lossy(&out.stderr)
                .trim_end()
                .ends_with("ValueError: superseded fleet")
            && fleet()? != head
        {
            continue;
        }
        ensure!(
            out.stderr.is_empty() && (out.status.success() || out.status.code() == Some(1)),
            "complete provider failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let v: Value = serde_json::from_slice(&out.stdout)?;
        let number = |key: &str| -> Result<u64> {
            v[key].as_u64().with_context(|| format!("missing {key}"))
        };
        let fits = number("available_HOME_bytes")? >= number("complete_required_HOME_bytes")?
            && number("available_memory_bytes")? >= number("required_available_memory_bytes")?;
        ensure!(
            v["schema"] == "horizon-incident-replay-fit-v1"
                && v["epoch"] == 145
                && v["fleet"] == head
                && v["resource_credit_bytes"] == 0
                && v["fits"] == fits
                && fits == out.status.success(),
            "foreign complete fit"
        );
        if fits {
            return Ok((head, operation));
        }
        drop(operation);
        let next = outcome::next(&from_ref(&head)?)?;
        eprintln!(
            "epoch 145 awaiting {} after native fit: HOME {}/{} B, RAM {}/{} B",
            next.display(),
            v["available_HOME_bytes"],
            v["complete_required_HOME_bytes"],
            v["available_memory_bytes"],
            v["required_available_memory_bytes"]
        );
        outcome::wait_file(&next)?;
    }
}
#[cfg(not(feature = "v5n-136-post"))]
fn original() -> Result<Value> {
    let a = pinned(&rt(START), ADVANCING)?;
    let manager = from_ref(&a["manager"])?;
    let start = from_ref(&a["start"])?;
    let launch = from_ref(&manager["intent"])?;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .replace('-', "");
    ensure!(
        launch["boot"] == boot && launch["old"] == PRIOR,
        "different boot or semantic start"
    );
    ensure!(
        a["invocation_id"] == SOURCE
            && manager["new"]["InvocationID"] == SOURCE
            && start["iid"] == SOURCE
            && start["image"] == IMAGE
            && start["r2_mutations"] == false
            && a["observations"]
                .as_array()
                .is_some_and(|rows| rows.len() == 2),
        "foreign semantic predecessor"
    );
    #[cfg(feature = "fixture-post")]
    {
        let state = rt("epoch145-guarded-export-20261121-v1/state");
        let failed = json!({"path":state.join(PRIOR).join("failed.json"),
            "sha256":FAILURE});
        let inner = json!({"path":state.join("a99ed8b51e8a482b805b8a36a11b2700/failed.json"),
            "sha256":"da29d82a4349444ccc15e0be020aa12918ae5bbb4634f9b62e13cc83a93c5f43"});
        ensure!(
            a["start"] == bound(&state.join(SOURCE).join("recovery-started.json"))?
                && a["manager"] == bound(&rt(MANAGER))?
                && start["prior_frozen_recovery"]["failed_qualification_census"]["current_boot_failure"]
                    ["failure"]
                    == inner
                && launch["failure"] == failed
                && from_ref(&failed)?["iid"] == PRIOR,
            "different V5f registration or predecessor"
        );
        #[cfg(feature = "retry-post")]
        {
            let family = rt("epoch145-semantic-continuity-20261121-v1");
            ensure!(
                manager["intent"] == bound(&family.join("V5F_RETRY1_START_INTENT.json"))?
                    && launch["previous_advancement"]
                        == bound(&family.join("V5F_ACTUAL_ADVANCING_WORKER.json"))?
                    && launch["recovery"]
                        == bound(&state.join(PRIOR).join("recovery-started.json"))?
                    && from_ref(&launch["previous_advancement"])?["invocation_id"] == PRIOR
                    && launch["verifier"]
                        == bound(&family.join("tools-v5f/deployment-seal-receipt.json"))?
                    && from_ref(&inner)?["iid"] == "a99ed8b51e8a482b805b8a36a11b2700",
                "same-image retry did not follow the original failed worker"
            );
        }
    }
    Ok(a)
}

#[cfg(feature = "v5n-136-post")]
fn original() -> Result<Value> {
    let result = pinned(&rt(START), ADVANCING)?;
    let handoff = rt("epoch145-semantic-continuity-20261121-v1/v5n-name-handoff");
    let init = handoff.join("submission-intent.json");
    let intent = pinned(
        &init,
        "d15dfa6d3212f8a868bd00ac5df3ef26eee42466c0ac7afc7f0e9ab42aa2f23e",
    )?;
    let state = rt("epoch145-guarded-export-20261121-v1/state").join(SOURCE);
    let start_ref = bound(&state.join("recovery-started.json"))?;
    let start = from_ref(&start_ref)?;
    let snapshot_path = Path::new("/home/sol/.jetstreamer-private/epoch145-lease-stop-20261123")
        .join(format!("v5n-{SOURCE}-advancing.json"));
    let sample = pinned(
        &snapshot_path,
        "7c9fe570d5317309d2891e559706d913760f145789c752882e19c1bf2f58118f",
    )?;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .replace('-', "");
    ensure!(
        result["invocation_id"] == SOURCE
            && intent["argv"] == result["argv"]
            && intent["original"]["_BOOT_ID"] == boot
            && intent["original"]["INVOCATION_ID"] == "dba04d40f1b046b4875d7e27e0ff224a"
            && start["iid"] == SOURCE
            && start["image"] == IMAGE
            && start["r2_mutations"] == false
            && sample["invocation_id"] == SOURCE
            && sample["submission"] == bound(&rt(START))?
            && sample["intent"] == bound(&init)?
            && sample["image_sha256"] == IMAGE
            && sample["window"]["recovery"] == start_ref,
        "different original V5n invocation"
    );
    Ok(json!({"start":start_ref,"sample":sample,"result":result}))
}

pub(super) fn completed_semantics() -> Result<Value> {
    let s = rt("epoch145-guarded-export-20261121-v1/state").join(SOURCE);
    ensure!(
        !s.join("failed.json").try_exists()?,
        "semantic worker failed"
    );
    let done = bound(&s.join("complete.json"))?;
    let d = from_ref(&done)?;
    let e = from_ref(&d["receipt"])?;
    #[cfg(feature = "v5n-136-post")]
    {
        let inputs = check_member(&rt(PKG), SEAL, "post-inputs")?;
        let current: Value = serde_json::from_slice(&command(&inputs, &["inspect"])?)?;
        let captured = rt(
            "epoch145-semantic-continuity-20261121-v1/v5n-name-handoff/semantic-completion.json",
        );
        ensure!(
            current["semantic_pending"] == false
                && current["semantic"] == from_ref(&bound(&captured)?)?
                && current["semantic"]["completion"] == done
                && current["semantic"]["invocation_id"] == SOURCE,
            "missing captured V13h completion"
        );
    }
    ensure!(
        d["iid"] == SOURCE
            && d["recovered_from"] == ORIGINAL
            && d["r2_mutations"] == false
            && d["receipt"] == bound(&s.join("extraction-complete.json"))?
            && e["actor_iid"] == SOURCE
            && e["verified_frozen"] == bound(&s.join("verified-frozen.json"))?
            && e["recovery_evidence"] == original()?["start"]
            && e["original_export"] == ORIGINAL
            && e["extraction"]["epoch"] == 145
            && e["extraction"]["output_slot_count"] == 432000
            && e["extraction"]["independent_output_reread_passed"] == true,
        "different semantic completion"
    );
    Ok(done)
}
fn socket() -> Result<PathBuf> {
    let mut paths = Vec::new();
    for entry in fs::read_dir("/tmp")? {
        let e = entry?;
        let p = e.path();
        if !e.file_name().to_string_lossy().starts_with("ssh-") {
            continue;
        }
        let m = fs::symlink_metadata(&p)?;
        if !m.is_dir() || m.uid() != 1001 || m.mode() & 0o077 != 0 {
            continue;
        }
        for child in fs::read_dir(&p)? {
            let f = child?;
            let m = fs::symlink_metadata(f.path())?;
            if f.file_name().to_string_lossy().starts_with("agent.")
                && m.file_type().is_socket()
                && m.uid() == 1001
            {
                paths.push(f.path());
            }
        }
    }
    paths.sort();
    for p in paths {
        if Command::new("/usr/bin/timeout")
            .args(["4", "/usr/bin/ssh-add", "-l"])
            .env_clear()
            .env("SSH_AUTH_SOCK", &p)
            .uid(1001)
            .gid(1001)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?
            .success()
        {
            return Ok(p);
        }
    }
    bail!("no active login SSH agent could validate the publication branch")
}
#[cfg(feature = "registered-post")]
fn check_selected_submission(
    actor: Option<&Value>,
    submission: &Value,
    intent: &Value,
    launcher: &Value,
    boundary: &Value,
) -> Result<()> {
    ensure!(
        actor.is_none_or(|row| row["submission"] == *submission)
            && intent["launcher"] == *launcher
            && intent["boundary"] == *boundary,
        "recorded actor belongs to a different post-verification deployment or selector"
    );
    Ok(())
}
fn stage(mode: &str, prior: &str, prerequisite: &Value) -> Result<String> {
    let state = rt(STATE_PATH);
    let receipt = state.join(format!("{mode}-actor.json"));
    let argv_head = [
        rt(PKG).join("export145").display().to_string(),
        mode.to_owned(),
    ];
    let intent = state.join(format!("{mode}-submission.json"));
    if receipt.try_exists()? {
        let v = from_ref(&bound(&receipt)?)?;
        let iid = text(&v["invocation"])?;
        ensure!(
            v["mode"] == mode
                && v["prior"] == prior
                && v["prerequisite"] == *prerequisite
                && valid_iid(iid),
            "foreign recorded stage"
        );
        #[cfg(feature = "registered-post")]
        {
            let reference = bound(&intent)?;
            let submission = from_ref(&reference)?;
            ensure!(
                submission["prior"] == prior
                    && submission["prerequisite"] == *prerequisite
                    && submission["mode"] == mode,
                "crossed recorded submission"
            );
            check_selected_submission(
                Some(&v),
                &reference,
                &submission,
                &bound(&check_member(&rt(PKG), SEAL, "run-post")?)?,
                &boundary::selected_boundary()?,
            )?;
        }
        return Ok(iid.to_owned());
    }
    let before = native(E)?;
    let already = before["ActiveState"] == "active";
    if !already {
        drained(&before, E)?;
        ensure!(
            !intent.try_exists()?,
            "unanswered {mode} submission requires native reconciliation"
        );
        let (head, _operation) = funded(|| {
            #[cfg(feature = "registered-post")]
            if mode == "post-full" {
                return boundary::before_post(prerequisite).map(Some);
            }
            Ok(None)
        })?;
        let launcher = check_member(&rt(PKG), SEAL, "run-post")?;
        let mut argv = vec![mode.to_owned(), text(&head["path"])?.to_owned()];
        if mode == "publish" {
            argv.extend([prior.to_owned(), socket()?.display().to_string()]);
        }
        let submission = json!({"mode":mode,"prior":prior,"prerequisite":prerequisite,"fleet":head,"launcher":bound(&launcher)?});
        #[cfg(feature = "registered-post")]
        let submission = {
            let mut submission = submission;
            submission["boundary"] = boundary::selected_boundary()?;
            submission
        };
        platform::save(&intent, &submission)?;
        let args = argv.iter().map(String::as_str).collect::<Vec<_>>();
        command(&launcher, &args)?;
    }
    let v = from_ref(&bound(&intent)?)?;
    ensure!(
        v["prior"] == prior && v["mode"] == mode && v["prerequisite"] == *prerequisite,
        "crossed submission"
    );
    #[cfg(feature = "registered-post")]
    check_selected_submission(
        None,
        &bound(&intent)?,
        &v,
        &bound(&check_member(&rt(PKG), SEAL, "run-post")?)?,
        &boundary::selected_boundary()?,
    )?;
    let (pid, iid) = stable(&native(E)?, E)?;
    let cmd = fs::read(format!("/proc/{pid}/cmdline"))?;
    let mut expected = Vec::from(argv_head);
    expected.push(text(&v["fleet"]["path"])?.to_owned());
    expected.push(text(&v["fleet"]["sha256"])?.to_owned());
    if mode == "publish" {
        expected.push(prior.to_owned());
    }
    let image = check_member(&rt(PKG), SEAL, "export145")?;
    expected.push(text(&bound(&image)?["sha256"])?.to_owned());
    ensure!(
        platform::proc_exe(pid)? == image
            && cmd == [expected.join("\0").into_bytes(), vec![0]].concat(),
        "foreign post process"
    );
    platform::save(
        &receipt,
        &json!({"mode":mode,"invocation":iid,"pid":pid,"ticks":platform::ticks(pid)?,
        "prior":prior,"prerequisite":prerequisite,"submission":bound(&intent)?}),
    )?;
    Ok(iid)
}
fn local_result(d: &Value, p: &Value, id: &str) -> Result<()> {
    ensure!(
        d["schema"] == "horizon-145-current-native-full-acceptance-v1"
            && p["schema"] == "horizon-145-current-native-plugin-acceptance-v1"
            && d["exit_code"] == 0
            && p["exit_code"] == 0
            && d["r2_mutations"] == false
            && p["r2_mutations"] == false
            && d["archive_sha256"]
                .as_str()
                .is_some_and(|h| h.len() == 64 && h.bytes().all(|c| c.is_ascii_hexdigit()))
            && d["invocation"] == id
            && p["invocation"] == id
            && d["epoch"] == 145
            && p["epoch"] == 145
            && d["archive_sha256"] == p["archive_sha256"]
            && d["verifier"]["sha256"]
                == "eec3a8093b52f7dd3a87d508b3b09e34680f2a5d887343cf12df70621d99f8a0"
            && p["pipeline"]["sha256"] == PIPELINE,
        "local verification is incomplete"
    );
    Ok(())
}
pub fn run(mode: &str) -> Result<()> {
    let original = original()?;
    check_member(&rt(PKG), SEAL, "run-post")?;
    check_member(&rt(PKG), SEAL, "export145")?;
    if mode == INSPECT {
        let current = native(E)?;
        let (pid, iid) = stable(&current, E)?;
        #[cfg(not(feature = "v5n-136-post"))]
        let obs = &original["observations"][1];
        #[cfg(feature = "v5n-136-post")]
        let obs = &original["sample"]["window"]["native_parent"];
        let (pid_key, ticks_key) = if cfg!(feature = "v5n-136-post") {
            ("pid", "start_ticks")
        } else {
            ("parent_pid", "parent_ticks")
        };
        ensure!(
            iid == SOURCE
                && i64::from(pid) == obs[pid_key].as_i64().context("semantic parent")?
                && platform::ticks(pid)? == obs[ticks_key]
                && platform::proc_exe(pid)? == rt(SEMANTIC),
            "different original live verifier"
        );
        #[cfg(all(feature = "fixture-post", not(feature = "v5n-136-post")))]
        {
            let child = i32::try_from(obs["child_pid"].as_i64().context("original V5f worker")?)?;
            let parent_command = fs::read(format!("/proc/{pid}/cmdline"))?;
            let worker_command = fs::read(format!("/proc/{child}/cmdline"))?;
            let manager = from_ref(&original["manager"])?;
            let intent = from_ref(&manager["intent"])?;
            let image = rt(SEMANTIC);
            let exe = platform::string_path(&image)?;
            ensure!(
                platform::proc_exe(child)? == image
                    && platform::ticks(child)? == obs["child_ticks"]
                    && parent_command
                        == [
                            exe,
                            "recover-full-output",
                            text(&intent["fleet"]["path"])?,
                            text(&intent["fleet"]["sha256"])?,
                            IMAGE,
                            ""
                        ]
                        .join("\0")
                        .as_bytes()
                    && worker_command
                        == [exe, "recover-worker", &pid.to_string(), IMAGE, ""]
                            .join("\0")
                            .as_bytes()
                    && fs::read_to_string(format!("/proc/{child}/cgroup"))?.trim()
                        == format!("0::/system.slice/{E}")
                    && fs::read_to_string(format!("/proc/{child}/stat"))?
                        .rsplit_once(')')
                        .context("worker stat")?
                        .1
                        .split_whitespace()
                        .nth(1)
                        .context("worker parent")?
                        .parse::<i32>()?
                        == pid,
                "different live V5f parent or worker"
            );
            ensure!(bound(&image)?["sha256"] == IMAGE, "V5f image changed");
            check_member(&rt(FIT_PKG), FIT_SEAL, "post-stop-fit")?;
        }
        #[cfg(feature = "v5n-136-post")]
        {
            let child = &original["sample"]["window"]["native_child"];
            let child_pid = i32::try_from(child["pid"].as_i64().context("V5n child")?)?;
            ensure!(
                platform::proc_exe(child_pid)? == rt(SEMANTIC)
                    && platform::ticks(child_pid)? == child["start_ticks"]
                    && fs::read_to_string(format!("/proc/{child_pid}/cgroup"))?.trim()
                        == format!("0::/system.slice/{E}"),
                "different advancing V5n child"
            );
            check_member(&rt(FIT_PKG), FIT_SEAL, "post-stop-fit")?;
        }
        println!(
            "{}",
            json!({"original":iid,"manager":pid,"fleet":fleet()?,"post_seal":SEAL,"launch":false})
        );
        return Ok(());
    }
    ensure!(mode == FOLLOW, "invalid incident mode");
    #[cfg(feature = "fixture-post")]
    let _previous = boundary::guard_predecessor()?;
    let _lock = guard_instance(&rt(STATE_PATH))?;
    events::manager(E, SOURCE)?;
    if cfg!(feature = "v5n-136-post") {
        let inputs = check_member(&rt(PKG), SEAL, "post-inputs")?;
        command(&inputs, &["capture"])?;
        let retained = completed_semantics()?;
        let _operation = boundary::before_post(&retained)?;
        platform::save(
            &rt(STATE_PATH).join("bounded-136-closed.json"),
            &json!({"semantic_completion":retained,"boundary":boundary::selected_boundary()?,"post_started":false}),
        )?;
        return Ok(());
    }
    let retained = completed_semantics()?;
    let id = stage("post-full", SOURCE, &retained)?;
    events::manager(E, &id)?;
    let full = rt(POST).join(format!("full-{id}"));
    let local = bound(&full.join("verified.json"))?;
    let d = from_ref(&local)?;
    let p = from_ref(&bound(&full.join("verified-plugin.json"))?)?;
    local_result(&d, &p, &id)?;
    let network = stage("publish", &id, &local)?;
    events::manager(E, &network)?;
    let published = bound(&rt(POST).join(format!("network-{network}/complete.json")))?;
    let done = from_ref(&published)?;
    ensure!(
        done["invocation"] == network
            && done["original_source_retained"] == true
            && done["canonical_output_retained"] == true
            && done["public_playback"].is_object()
            && done["verified_pair"].is_object(),
        "incomplete authenticated publication"
    );
    let end = rt(STATE_PATH).join("completed.json");
    let result = json!({"epoch":145,"semantic_completion":retained,"local_verification":local,"public_verification":published,"network_invocation":network});
    if end.try_exists()? {
        ensure!(from_ref(&bound(&end)?)? == result, "foreign completion");
    } else {
        platform::save(&end, &result)?;
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "registered-post")]
    #[test]
    fn previous_actor_cannot_cross_the_registered_post_boundary() {
        let reference = json!({"path":"post-full-submission.json","sha256":"current"});
        let actor = json!({"submission":reference});
        let boundary = json!({"selector":"ready","decision":"selected"});
        let launcher = json!({"path":"v12/run-post","sha256":"current"});
        let mut intent = json!({"launcher":launcher,"boundary":boundary});
        assert!(
            check_selected_submission(Some(&actor), &reference, &intent, &launcher, &boundary)
                .is_ok()
        );
        assert!(
            check_selected_submission(
                Some(&json!({"submission":"old"})),
                &reference,
                &intent,
                &launcher,
                &boundary
            )
            .is_err()
        );
        intent["launcher"]["path"] = json!("v11/run-post");
        assert!(
            check_selected_submission(None, &reference, &intent, &launcher, &boundary).is_err()
        );
        intent["launcher"] = launcher.clone();
        intent["boundary"]["decision"] = json!("old");
        assert!(
            check_selected_submission(Some(&actor), &reference, &intent, &launcher, &boundary)
                .is_err()
        );
    }

    #[test]
    fn publication_waits_for_both_matching_current_local_results() {
        let mut d = json!({"schema":"horizon-145-current-native-full-acceptance-v1","exit_code":0,"r2_mutations":false,"epoch":145,
            "invocation":SOURCE,"archive_sha256":"a".repeat(64),"verifier":{"sha256":"eec3a8093b52f7dd3a87d508b3b09e34680f2a5d887343cf12df70621d99f8a0"}});
        let p = json!({"schema":"horizon-145-current-native-plugin-acceptance-v1","exit_code":0,"r2_mutations":false,"epoch":145,
            "invocation":SOURCE,"archive_sha256":"a".repeat(64),"pipeline":{"sha256":PIPELINE}});
        assert!(local_result(&d, &p, SOURCE).is_ok());
        assert!(local_result(&d, &p, "unrelated").is_err());
        let mut stale = p.clone();
        stale["pipeline"]["sha256"] = json!("unqualified archive reader");
        assert!(local_result(&d, &stale, SOURCE).is_err());
        for (key, value) in [
            ("epoch", json!(146)),
            ("exit_code", json!(1)),
            ("archive_sha256", json!("b".repeat(64))),
            ("verifier", json!({})),
            ("schema", json!("other")),
        ] {
            let old = d[key].clone();
            d[key] = value;
            assert!(local_result(&d, &p, SOURCE).is_err());
            d[key] = old;
        }
    }
}
