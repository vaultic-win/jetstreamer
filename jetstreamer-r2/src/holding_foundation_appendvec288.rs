//! Byte custody for the closed epoch 288 sparse AccountsDb bundle.
use super::*;
use std::process::Command;

#[path = "holding_foundation_appendvec288_compare.rs"]
mod compare;

const PARK: &str = "holding-foundation-288-appendvec-park";
const CHECK: &str = "holding-foundation-288-appendvec-check-stage";
const CONTROL: &str = "/var/lib/jetstreamer/horizon288-closed-appendvec-study-v1";
const BUNDLE: &str = "/home/ubuntu/.jetstreamer-private/epoch288-appendvec-stage-tmpfs-v1/epoch-288-closed-appendvecs.pax.zst";
const STAGE_UNIT: &str = "foundation-288-appendvec-stage-v2.service";
const STAGE_INVOCATION: &str = "14387438c8264a37843323d1031613bd";
const STAGE_PID: u64 = 1_459_700;
const STAGE_START_SHA: &str = "bedd974a205f7991c2be53317c78bb9bdafbe554bf5aef14450cb4386af3ac51";
const STAGE_INTENT_SHA: &str = "8a07d7a6c95981897a7805ed801364bc40c01bc88d508a7558cd5a4f1b0b515b";
const SAMPLE_SHA: &str = "5c07a84b6b2c7fd38dd5c3eb74db191b826d53b8827b5b9735d5c214188d6272";
const CENSUS_SHA: &str = "287f5bd0fa48f9d32b38198704762d462b9975702c9b64c5233944d8e19d8931";
const ORIGINAL_TERMINAL_SHA: &str =
    "876b040f74480907639e0321016b3f0187a2f45347ae8bc8523e32535db874d1";
const CAP: u64 = 96 << 30;
const MEMBERS: u64 = 178_655;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    mapping: Bound,
    staged_body: Bound,
}

struct Body<'a> {
    length: u64,
    sha256: &'a str,
}

pub(super) fn command(action: &str) -> bool {
    matches!(action, PARK | CHECK | compare::ACTION)
}

fn body<'a>(stage: &'a Value, sample: &Value) -> Result<Body<'a>> {
    let length = stage["length"]
        .as_u64()
        .context("missing 288 bundle length")?;
    let sha256 = stage["sha256"]
        .as_str()
        .context("missing 288 bundle SHA-256")?;
    ensure!(
        stage["schema"] == "foundation-epoch288-appendvec-staging-body-v1"
            && stage["epoch"] == 288
            && stage["sample_sha256"] == SAMPLE_SHA
            && stage["source"] == sample["source"]
            && stage["source_census_sha256"] == CENSUS_SHA
            && stage["terminal_sha256"] == ORIGINAL_TERMINAL_SHA
            && stage["unit"] == STAGE_UNIT
            && stage["invocation_id"] == STAGE_INVOCATION
            && stage["pid"] == STAGE_PID
            && stage["path"] == BUNDLE
            && stage["members"] == MEMBERS
            && stage["local_retirement_authorized"] == false
            && stage["remote_mutations"] == false
            && stage["process_references_before"]["references"] == json!([])
            && stage["process_references_after"]["references"] == json!([])
            && 0 < length
            && length < CAP
            && digest(sha256)
            && sha256.bytes().any(|byte| byte != b'0'),
        "foreign or incomplete 288 staging receipt"
    );
    Ok(Body { length, sha256 })
}

fn closed_source(body: &Body) -> Result<FileIdentity> {
    let group = Path::new("/sys/fs/cgroup/system.slice").join(STAGE_UNIT);
    let state = Command::new("/usr/bin/systemctl")
        .args([
            "show",
            STAGE_UNIT,
            "-p",
            "ActiveState",
            "-p",
            "MainPID",
            "-p",
            "ControlGroup",
        ])
        .output()?;
    let stdout = std::str::from_utf8(&state.stdout)?;
    ensure!(
        state.status.success()
            && ["ActiveState=inactive", "MainPID=0", "ControlGroup="]
                .iter()
                .all(|entry| stdout.lines().any(|line| line == *entry))
            && !group.try_exists()?,
        "288 staging unit has not closed"
    );
    let bundle = Path::new(BUNDLE);
    let meta = bundle.symlink_metadata()?;
    ensure!(
        bundle.canonicalize()? == bundle
            && meta.is_file()
            && meta.len() == body.length
            && meta.uid() == 0
            && meta.gid() == 0
            && meta.mode() & 0o7777 == 0o400
            && meta.nlink() == 1,
        "288 staging bundle inode or permissions differ"
    );
    regular_identity(bundle)
}

fn manager_terminal() -> Result<Value> {
    let message = format!("{STAGE_UNIT}: Deactivated successfully.");
    let output = Command::new("/usr/bin/journalctl")
        .args([
            "--quiet",
            "--no-pager",
            "--output=json",
            "--lines=1",
            "-b",
            "_PID=1",
        ])
        .args([
            format!("UNIT={STAGE_UNIT}"),
            format!("INVOCATION_ID={STAGE_INVOCATION}"),
            format!("MESSAGE={message}"),
        ])
        .output()?;
    ensure!(output.status.success(), "288 staging journal lookup failed");
    let event: Value = serde_json::from_slice(&output.stdout)
        .context("missing PID1 completion for the exact 288 staging invocation")?;
    ensure!(
        event["_PID"] == "1"
            && event["_SYSTEMD_UNIT"] == "init.scope"
            && event["UNIT"] == STAGE_UNIT
            && event["INVOCATION_ID"] == STAGE_INVOCATION
            && event["MESSAGE"] == message
            && event["__REALTIME_TIMESTAMP"].as_str().is_some(),
        "288 staging manager terminal proof differs"
    );
    Ok(event)
}

pub(super) async fn run(action: &str, value: Value, spec: &Bound) -> Result<()> {
    if action == compare::ACTION {
        return compare::run(value, spec).await;
    }
    let plan: Plan = serde_json::from_value(value)?;
    mapping(&plan.mapping)?;
    let control = Path::new(CONTROL);
    ensure!(
        plan.schema == "foundation-epoch288-appendvec-park-v1"
            && plan.staged_body.path == control.join("staging-body.json"),
        "foreign 288 custody plan"
    );
    for (name, sha) in [
        ("staging-start-v2.json", STAGE_START_SHA),
        ("staging-intent-v2.json", STAGE_INTENT_SHA),
    ] {
        saved(&Bound {
            path: control.join(name),
            sha256: sha.into(),
        })?;
    }
    let sample = saved(&Bound {
        path: control.join("sample-qualification.json"),
        sha256: SAMPLE_SHA.into(),
    })?;
    let stage = saved(&plan.staged_body)?;
    let body = body(&stage, &sample)?;
    let manager = manager_terminal()?;
    let identity = closed_source(&body)?;
    let before = no_references(Path::new(BUNDLE))?;
    let proof = hash_and_etag(Path::new(BUNDLE), identity, DEFAULT_PART_SIZE)?;
    ensure!(
        proof.sha256_hex == body.sha256,
        "288 staged bundle SHA-256 differs"
    );
    if action == CHECK {
        println!(
            "{}",
            json!({"path":BUNDLE,"length":body.length,"sha256":body.sha256,
            "process_census":before,"manager_terminal":manager,"remote_mutations":false})
        );
        return Ok(());
    }

    let r2 = r2_config_from_env()?;
    ensure!(r2.bucket == BUCKET, "foreign 288 holding bucket");
    let client = s3_client(&r2);
    let object = key(body.sha256)?;
    let manifest = json!({
        "schema":"foundation-epoch288-appendvec-manifest-v1","host":host::HOST,
        "prefix":SUBPREFIX,"epoch":288,"format":"gnu-sparse-pax-zstd","length":body.length,
        "sha256":body.sha256,"object_key":object,"stage_receipt":plan.staged_body,
        "stage":stage,"sample_sha256":SAMPLE_SHA,"source_census":sample["source_census"],
        "preserved_archive":sample["preserved_archive"],"canonical_archive":false,
        "runtime_checkpoint_qualified":false,"local_retirement_authorized":false
    });
    let manifest_bytes = serde_json::to_vec(&manifest)?;
    let manifest_sha = hex_lower(&Sha256::digest(&manifest_bytes));
    let manifest_key = manifest_key(&manifest_sha)?;
    claim_owner(&client, host::PREFIX, &owner_bytes()?).await?;
    let transport = Park {
        schema: "transport-only".into(),
        mapping: plan.mapping,
        eligibility: spec.clone(),
        source: BUNDLE.into(),
        length: body.length,
        sha256: body.sha256.to_owned(),
    };
    let remote = verified_blob(&client, &object, &transport, identity, &proof).await?;
    ensure!(
        closed_source(&body)? == identity,
        "288 staged bundle inode changed"
    );
    let after = no_references(Path::new(BUNDLE))?;
    ensure!(
        hash_and_etag(Path::new(BUNDLE), identity, DEFAULT_PART_SIZE)?.sha256_hex == body.sha256,
        "288 staged bundle changed after remote readback"
    );
    small_create(&client, &manifest_key, &manifest_bytes).await?;
    let remote_head = head_archive(&client, BUCKET, &object)
        .await?
        .context("288 holding bundle disappeared")?;
    remote_matches(
        &remote_head,
        &object,
        body.length,
        body.sha256,
        Some(&remote.etag),
    )?;
    native_checksum(&remote_head, &proof, body.length)?;
    let path = receipt(
        &format!("appendvec288-custody-{}.json", spec.sha256),
        &json!({
            "schema":"foundation-epoch288-appendvec-custody-v1","host":host::HOST,
            "bucket":BUCKET,"prefix":SUBPREFIX,"epoch":288,"object_key":object,"object_etag":remote.etag,
            "manifest_key":manifest_key,"manifest_sha256":manifest_sha,"manifest":manifest,
            "park_spec":spec,"manager_terminal":manager,"reference_census_before":before,
            "reference_census_after":after,"remote_sha256_readback":true,"local_source_revalidated":true,
            "complete_tree_restore_verified":false,"publication_authorized":false,
            "local_retirement_authorized":false
        }),
    )?;
    println!("{}", path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage_receipt_rejects_wrong_invocation_source_and_bounds() {
        let sample = json!({"source":"/closed/accounts-state"});
        let stage = json!({
            "schema":"foundation-epoch288-appendvec-staging-body-v1","epoch":288,
            "sample_sha256":SAMPLE_SHA,"source":sample["source"],"source_census_sha256":CENSUS_SHA,
            "terminal_sha256":ORIGINAL_TERMINAL_SHA,"unit":STAGE_UNIT,"invocation_id":STAGE_INVOCATION,
            "pid":STAGE_PID,"path":BUNDLE,"members":MEMBERS,"length":CAP-1,"sha256":"a".repeat(64),
            "local_retirement_authorized":false,"remote_mutations":false,
            "process_references_before":{"references":[]},"process_references_after":{"references":[]}
        });
        assert_eq!(body(&stage, &sample).unwrap().length, CAP - 1);
        for (field, replacement) in [
            ("invocation_id", json!("foreign")),
            ("source", json!("/other/accounts-state")),
            ("length", json!(CAP)),
            ("sha256", json!("0".repeat(64))),
            ("process_references_after", json!({"references":["live"]})),
        ] {
            let mut changed = stage.clone();
            changed[field] = replacement;
            assert!(body(&changed, &sample).is_err(), "accepted {field}");
        }
    }
}
