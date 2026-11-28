//! Re-read the original epoch 168 scan after its closing Git comparison refused.
//! This command prints private evidence. It has no output path or R2 client.
#[allow(dead_code)]
#[path = "../horizon_epoch168_private_verify/custody.rs"]
mod custody;
mod native;
#[allow(dead_code)]
#[path = "../horizon_epoch168_private_verify/scan.rs"]
mod scan;
#[allow(dead_code)]
#[path = "../horizon_epoch168_private_verify/scope.rs"]
mod scope;
mod source;

use anyhow::{Context, Result, ensure};
use custody::{Bound, Opened, bound, digest, reference};
use scope::Inputs;
use serde_json::{Value, json};
use std::{env, fs, os::unix::fs::MetadataExt, path::Path};

const CONTROL: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch168-exact-private-verification-20261127-v1";
const ATTEMPT: &str = "attempt-1795827125309095402";
const UNIT: &str = "horizon-168-private-archive-verify-1795827125309095402.service";
const INVOCATION: &str = "185698e560b44c2793e059e0be868e86";
const BOOT: &str = "763ea84ca81f4dddad364b1ea2ba36dd";
const PID: &str = "538572";

fn pin(path: impl AsRef<Path>, sha256: &str) -> Bound {
    Bound {
        path: path.as_ref().to_owned(),
        sha256: sha256.to_owned(),
    }
}

fn validate_reports(
    inputs: &Inputs,
    assembled: &Value,
    full: &Bound,
    plugin: &Bound,
) -> Result<Value> {
    full.binary()?;
    let text = fs::read_to_string(&full.path)?;
    ensure!(
        digest(text.as_bytes()) == full.sha256,
        "full PoH report changed"
    );
    let report = plugin.json()?;
    let args = vec![
        inputs.scope.epoch.to_string(),
        inputs.scope.assembly_dir.display().to_string(),
        "--verify-only".into(),
        "--threads".into(),
        inputs.scope.threads.to_string(),
        "--verification-report".into(),
        plugin.path.display().to_string(),
    ];
    scan::validate_semantics(assembled, inputs, &text, &report, &args)?;
    Ok(report["report"].clone())
}

fn report_window(modified: u128, changed: u128, native: &Value) -> Result<()> {
    let journal = &native["journal"];
    let begin = journal["full_poh"]["at_realtime_usec"]
        .as_u64()
        .context("native playback start")?;
    let end = journal["closing_diff"]["at_realtime_usec"]
        .as_u64()
        .context("native closing source refusal")?;
    ensure!(
        u128::from(begin) <= modified && modified <= changed && changed <= u128::from(end),
        "plugin report dates fall outside the original native playback"
    );
    Ok(())
}

fn reconcile(tip: &str) -> Result<Value> {
    let rt = Path::new(CONTROL);
    let attempt = rt.join(ATTEMPT);
    let output = attempt.join("output");
    let intent = pin(
        attempt.join("INTENT.json"),
        "fb4f6191815d3bc83cf6b3650a87facaa3e46d82d67ecabb562f278323a99251",
    );
    let plan = intent.json()?;
    let scope = reference(&plan, "scope")?;
    let admission = reference(&plan, "admission")?;
    let original = reference(&plan, "binary")?;
    let ad = admission.json()?;
    let command = plan["command"].as_array().context("recorded invocation")?;
    let split = command
        .iter()
        .position(|v| v == "--")
        .context("native program delimiter")?;
    let cmdline = command[split + 1..]
        .iter()
        .map(|v| v.as_str().context("native command argument"))
        .collect::<Result<Vec<_>>>()?
        .join(" ");
    let native = native::failure(&cmdline, &original.path)?;

    let deployed = pin(
        rt.join("deployment.json"),
        "55a9eecbcd29346d344f4aa9501d35890c5276392e1c84e5437957210a3b537d",
    );
    let deployment = deployed.json()?;
    original.binary()?;
    let build = reference(&deployment, "native_build")?.json()?;
    ensure!(
        deployment["binary"] == json!(original) && build["binary"]["sha256"] == original.sha256,
        "frozen verification program changed"
    );
    let launch = pin(
        attempt.join("LAUNCH.json"),
        "d538b31cef011332d420b574f4584439cfba76ed353615550ada2716e8c7bf28",
    );
    let launched = launch.json()?;
    let started = reference(&launched, "started")?;
    let entered = started.json()?;
    let assembly = reference(&ad, "assembly")?;
    let refused = bound(&attempt.join("REFUSED.json"))?;
    let refusal = refused.json()?;
    ensure!(
        plan["unit"] == UNIT
            && launched["native"]["InvocationID"] == INVOCATION
            && launched["admission"] == json!(admission)
            && entered["scope"] == json!(scope)
            && entered["admission"] == json!(admission)
            && entered["assembly"] == json!(assembly)
            && entered["invocation"] == INVOCATION
            && entered["pid"] == 538572
            && entered["scan_unit"] == UNIT
            && entered["exclusive_serial_lock"] == true
            && ad["output"] == json!(output)
            && refusal["enter"] == json!(started)
            && refusal["unit"] == UNIT
            && refusal["messages"]
                == json!([{"id":native::MAIN_EXIT, "invocation":INVOCATION,
            "message":native["journal"]["main_exit"]["message"]}]),
        "different original launch or private refusal"
    );
    for p in [
        rt.join("ACCEPTED.json"),
        output.join("SCAN.json"),
        output.join("ACCEPTANCE.json"),
    ] {
        ensure!(
            matches!(fs::symlink_metadata(p), Err(e) if e.kind() == std::io::ErrorKind::NotFound),
            "original attempt has another disposition"
        );
    }

    let inputs = Inputs::load(&scope)?;
    let assembled = assembly.json()?;
    inputs.assembly(&assembled)?;
    let archive_path = inputs.scope.assembly_dir.join("epoch-168.jet");
    let archive = Opened::open(&archive_path)?;
    ensure!(
        json!(archive.start) == ad["archive_stamp"]
            && archive.start.len == 121787223572
            && assembled["archive_sha256"]
                == "311d78ee8e4ae91ed2e868e1b9de98f5edd6433b45796b2744374fbf47dfc994"
            && assembled["blocks"] == 389999
            && assembled["transactions"] == 217219070
            && assembled["normalized_writes"] == 614250774,
        "different assembled archive"
    );
    let full = pin(
        output.join("full.stdout"),
        "4939aadc1f25160b7d41ae573ba6e1bb8d7cb15336f01a38520b00a51d3d5c78",
    );
    let plugin_path = output.join("plugin.json");
    let mut plugin_file = Opened::open(&plugin_path)?;
    let plugin = pin(&plugin_path, &plugin_file.hash()?);
    let stat = fs::symlink_metadata(&plugin_path)?;
    let unix_usec = |seconds: i64, nanos: i64| -> Result<u128> {
        Ok(u128::try_from(seconds)? * 1_000_000 + u128::try_from(nanos)? / 1_000)
    };
    report_window(
        unix_usec(stat.mtime(), stat.mtime_nsec())?,
        unix_usec(stat.ctime(), stat.ctime_nsec())?,
        &native,
    )?;
    let counters = validate_reports(&inputs, &assembled, &full, &plugin)?;
    let diagnostics = ["full.stderr", "playback.stdout", "playback.stderr"]
        .iter()
        .map(|name| bound(&output.join(name)))
        .collect::<Result<Vec<_>>>()?;
    let sources = source::review(tip, &inputs)?;
    archive.unchanged()?;
    plugin_file.unchanged()?;
    ensure!(
        bound(&plugin.path)? == plugin,
        "plugin report changed during review"
    );
    Ok(
        json!({"schema":"horizon-168-original-private-scan-source-reconciliation-v1",
        "original_outcome":"failed-closing-git-diff","private_native_reports_validated":true,
        "scope":scope,"admission":admission,"intent":intent,"native_launch":launch,"entered":started,
        "original_refusal":refused,"original_binary":original,"original_deployment":deployed,
        "terminal":native,"assembly":assembly,"archive":archive_path,"archive_stamp":archive.start,
        "archive_sha256":assembled["archive_sha256"],"expectation":inputs.scope.expectation,
        "provenance_sha256":assembled["provenance_sha256"],"reader_branch_at_entry":ad["reader_branch"],
        "current_reader":sources,"full_stdout":full,"plugin":plugin,"plugin_stamp":plugin_file.start,"diagnostics":diagnostics,
        "counters":counters,"normalized_writes":assembled["normalized_writes"],
        "canonical_writes":false,"publication_authorized":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_reports_within_the_native_playback_window_qualify() {
        let native = json!({"journal":{"full_poh":{"at_realtime_usec":10},"closing_diff":{"at_realtime_usec":20}}});
        assert!(report_window(10, 20, &native).is_ok());
        assert!(report_window(9, 15, &native).is_err());
        assert!(report_window(19, 21, &native).is_err());
        assert!(report_window(18, 17, &native).is_err());
    }

    #[test]
    #[ignore = "needs the original root-owned qualification on Anza"]
    fn original_native_fixture_accepts_only_the_bound_semantics() -> Result<()> {
        let proof = pin(
            Path::new(CONTROL).join("QUALIFICATION.json"),
            "4b593da940aded44eb46b5500fc3f5f67c9b66f6806811c2423e2a80a8d30932",
        )
        .json()?;
        let fixture = reference(&proof, "positive")?.json()?;
        ensure!(
            fixture["fixture"] == true && fixture["epoch"] == 251 && proof["accepted"] == true,
            "wrong native qualification"
        );
        let inputs = Inputs::load(&reference(&fixture, "scope")?)?;
        let full = reference(&fixture["full"], "stdout")?;
        let plugin = reference(&fixture, "local_plugin")?;
        let mut assembled = reference(&fixture, "assembly")?.json()?;
        let counters = validate_reports(&inputs, &assembled, &full, &plugin)?;
        assert_eq!(counters, fixture["counters"]);
        assembled["normalized_writes"] = json!(999);
        assert!(validate_reports(&inputs, &assembled, &full, &plugin).is_err());
        let wrong = pin(&plugin.path, &"0".repeat(64));
        assert!(validate_reports(&inputs, &assembled, &full, &wrong).is_err());
        Ok(())
    }
}

fn main() -> Result<()> {
    let args: Vec<_> = env::args().skip(1).collect();
    let report = match args.as_slice() {
        [cmd, tip] if cmd == "reconcile" => reconcile(tip)?,
        [cmd, tip] if cmd == "check-source" => {
            let b = pin(
                Path::new(CONTROL).join("scope.json"),
                "b914d8570f3fe8fd2cc2bc91cc5285a9598b11515ab8763f17eeb28f13373a9c",
            );
            source::review(tip, &Inputs::load(&b)?)?
        }
        _ => anyhow::bail!(
            "expected check-source or reconcile followed by the fresh account-updates commit"
        ),
    };
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}
