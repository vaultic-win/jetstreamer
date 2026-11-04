// Shared read-only metadata engine with a compile-time exact object profile.
#[allow(dead_code)]
mod epoch141_ledger_common;
use {
    anyhow::{Context, Result, ensure},
    epoch141_ledger_common::{
        bound_file, observe_gcloud_object, sha, validate_object_metadata, write_receipt,
    },
    profile::{EPOCH, METADATA_PLAN_SCHEMA, METADATA_SCHEMA, OBJECT},
    serde::Deserialize,
    serde_json::{Value, json},
    std::{
        collections::BTreeMap,
        env,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    },
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    gcloud_sha256: String,
    output: PathBuf,
}

fn run() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "metadata observer must run as root"
    );
    let mut args = env::args().skip(1);
    let mut values = BTreeMap::new();
    while let Some(key) = args.next() {
        ensure!(
            ["--plan", "--plan-sha256", "--self-sha256"].contains(&key.as_str()),
            "unknown option"
        );
        let value = args.next().context("missing option value")?;
        ensure!(values.insert(key, value).is_none(), "duplicate option");
    }
    ensure!(
        values.len() == 3,
        "require --plan, --plan-sha256 and --self-sha256"
    );
    bound_file(
        Path::new("/proc/self/exe").read_link()?.as_path(),
        &values["--self-sha256"],
        64 * 1024 * 1024,
        true,
    )?;
    let bytes = bound_file(
        Path::new(&values["--plan"]),
        &values["--plan-sha256"],
        65536,
        true,
    )?;
    let plan: Plan = serde_json::from_slice(&bytes)?;
    ensure!(plan.schema == METADATA_PLAN_SCHEMA, "wrong plan schema");
    let gcloud = Path::new("/usr/lib/google-cloud-sdk/bin/gcloud");
    bound_file(gcloud, &plan.gcloud_sha256, 16 * 1024 * 1024, false)?;
    let invocation = env::var("INVOCATION_ID").context("persistent systemd invocation required")?;
    ensure!(
        invocation.len() == 32
            && invocation
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid invocation ID"
    );
    let metadata = observe_gcloud_object(&OBJECT)?;
    let value: Value = serde_json::from_slice(&metadata)?;
    validate_object_metadata(&value, &OBJECT)?;
    bound_file(gcloud, &plan.gcloud_sha256, 16 * 1024 * 1024, false)?;
    write_receipt(
        &plan.output,
        &json!({
            "schema":METADATA_SCHEMA,"epoch":EPOCH,
            "recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            "invocation_id":invocation,"plan_sha256":values["--plan-sha256"],"self_sha256":values["--self-sha256"],
            "gcloud_sha256":plan.gcloud_sha256,"effective_cloudsdk_config":"/home/sol/.config/gcloud",
        "cli_uid_enforced_before_exec":1001,"cli_gid_enforced_before_exec":1003,
            "metadata":value,"raw_metadata_sha256":sha(&metadata),
            "download_performed":false,"compressed_input_verified":false,"source_completeness_proven":false,
            "resource_admission_proven":false,"replay_launch_authorized":false,"publication_authorized":false,
            "remote_mutations":false,"r2_mutations":false
        }),
    )?;
    println!("exact generation metadata matched; private no-clobber receipt written");
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use epoch141_ledger_common::{MAX_METADATA, capture, drop_cli_identity, wait_bounded};
    use profile::{CRC, GENERATION, MD5, SIZE, URI};
    const BUCKET: &str = OBJECT.bucket;
    const NAME: &str = OBJECT.name;
    fn validate_metadata(value: &Value) -> Result<()> {
        validate_object_metadata(value, &OBJECT)
    }
    use std::{
        fs,
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    fn normalized() -> Value {
        json!({"bucket":BUCKET,"name":NAME,"generation":GENERATION,
        "size":SIZE,"crc32c_hash":CRC,"md5_hash":MD5,"storage_url":URI})
    }
    #[test]
    fn exact_normalized_and_raw_metadata_pass() {
        validate_metadata(&normalized()).unwrap();
        let raw = json!({"bucket":BUCKET,"name":NAME,"generation":GENERATION.parse::<u64>().unwrap(),
            "size":SIZE.to_string(),"crc32c":CRC,"md5Hash":MD5,"id":format!("{BUCKET}/{NAME}/{GENERATION}")});
        validate_metadata(&raw).unwrap();
    }
    #[test]
    fn rejects_wrong_generation_length_location_hash_and_alias_conflicts() {
        for (key, value) in [
            ("generation", json!("1634789748052740")),
            ("size", json!(true)),
            ("size", json!(SIZE - 1)),
            ("name", json!("other/rocksdb.tar.bz2")),
            ("bucket", json!("other")),
            ("crc32c_hash", json!("AAAAAA==")),
            ("md5_hash", Value::Null),
            ("md5Hash", json!("AAAAAAAAAAAAAAAAAAAAAA==")),
            ("crc32c", json!("AAAAAA==")),
            ("id", json!("other")),
            ("storage_url", json!(URI.replace('#', "?generation="))),
        ] {
            let mut value2 = normalized();
            value2[key] = value;
            assert!(validate_metadata(&value2).is_err(), "accepted wrong {key}");
        }
    }
    #[test]
    fn refuses_missing_generation_identity_or_hash_evidence() {
        for key in [
            "generation",
            "size",
            "storage_url",
            "crc32c_hash",
            "md5_hash",
        ] {
            let mut value = normalized();
            value.as_object_mut().unwrap().remove(key);
            assert!(validate_metadata(&value).is_err(), "accepted missing {key}");
        }
    }
    #[test]
    fn capture_is_bounded_and_unsafe_parent_cannot_overwrite() {
        assert_eq!(
            capture(std::io::repeat(7)).unwrap().len() as u64,
            MAX_METADATA + 1
        );
        // Root ownership is an operational gate, not bypassed by a user test.
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("receipt.json");
        fs::write(&path, b"preserve").unwrap();
        assert!(write_receipt(&path, &json!({})).is_err());
        assert_eq!(fs::read(path).unwrap(), b"preserve");
    }

    #[test]
    #[ignore = "root capability sandbox only; kills and reaps its own disposable child"]
    fn root_sandbox_kills_unprivileged_child_and_refuses_receipt_overwrite() {
        use std::os::unix::{fs::PermissionsExt, process::ExitStatusExt};
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let mut command = Command::new("/usr/bin/sleep");
        command
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        drop_cli_identity(&mut command);
        let mut child = command.spawn().unwrap();
        let status = fs::read_to_string(format!("/proc/{}/status", child.id())).unwrap();
        assert!(
            status
                .lines()
                .any(|line| line == "Uid:\t1001\t1001\t1001\t1001")
        );
        assert!(
            status
                .lines()
                .any(|line| line.starts_with("Groups:") && line.split_whitespace().count() == 1)
        );
        let start = Instant::now();
        let error = wait_bounded(&mut child, Duration::from_millis(100)).unwrap_err();
        assert!(error.to_string().contains("timed out"), "{error:#}");
        assert!(start.elapsed() < Duration::from_secs(3));
        assert_eq!(child.try_wait().unwrap().unwrap().signal(), Some(9));
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("receipt.json");
        write_receipt(&path, &json!({"preserve":true})).unwrap();
        let original = fs::read(&path).unwrap();
        assert!(write_receipt(&path, &json!({"replace":true})).is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
    }
}
