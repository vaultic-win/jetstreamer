//! Compare the exact signed epoch 167 swap with its finalized RPC execution.
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const SIGNATURE: &str =
    "5t34U1SzGfQMDxmY61U3iPnydiHWViWGuZTX5Pqz5sfQMZMpLxgDtRWo3mEJffnnrgvH9rtcz865mSE3zGVEnWwZ";
const RPC_SHA: &str = "2a714b919eec61fdd20c87ddbe7650b7775484e92cea62f7f0ed6f4747070ab0";
const WORKER_SHA: &str = "07b09d779706a789c668681ad9685e9ad62290a6930667c5f74a099a516d28cc";
const MAX_LINE: u64 = 1024 * 1024;

fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn regular(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.nlink() != 1 || path.canonicalize()? != path {
        return Err("expected canonical regular file".into());
    }
    Ok(file)
}

fn pinned(path: &Path, digest: &str) -> Result<Value> {
    let mut bytes = Vec::new();
    regular(path)?.take(MAX_LINE + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_LINE || sha(&bytes) != digest {
        return Err("evidence SHA-256 mismatch".into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}

fn compare(log: impl BufRead, canonical: &[String]) -> Result<Value> {
    let key = format!(
        "epoch167 trace slot=72512769 entry=143 transaction=179 signature={SIGNATURE} execution="
    );
    let mut report = None;
    let mut reader = log;
    let mut line = Vec::new();
    let mut offset = 0usize;
    loop {
        line.clear();
        let len = (&mut reader)
            .take(MAX_LINE + 1)
            .read_until(b'\n', &mut line)?;
        if len as u64 > MAX_LINE {
            return Err("oversize diagnostic line".into());
        }
        if len == 0 || !line.ends_with(b"\n") {
            break;
        }
        if line.starts_with(b"epoch167 trace ") {
            let text = std::str::from_utf8(&line[..len - 1])?;
            let payload = text
                .strip_prefix(&key)
                .ok_or("unexpected epoch 167 trace identity")?;
            if report.is_some() {
                return Err("duplicate signed trace".into());
            }
            let (execution, logs) = payload
                .split_once(" logs=")
                .ok_or("incomplete signed trace")?;
            if !execution.starts_with("Some(") || !execution.ends_with(')') {
                return Err("missing native result".into());
            }
            let encoded = logs
                .strip_prefix("Some(")
                .and_then(|v| v.strip_suffix(')'))
                .ok_or("missing native logs")?;
            let observed: Vec<String> = serde_json::from_str(encoded)?;
            let first_difference = (0..canonical.len().max(observed.len()))
                .find(|&i| canonical.get(i) != observed.get(i))
                .map(
                    |i| json!({"index":i,"observed":observed.get(i),"finalized":canonical.get(i)}),
                );
            report = Some(
                json!({"slot":72512769,"entry":143,"transaction":179,"signature":SIGNATURE,
                "trace_offset":offset,"trace_line_sha256":sha(&line),"execution":execution,
                "matches_finalized_success":execution=="Some(Ok(()))","native_logs":observed,
                "finalized_log_count":canonical.len(),"all_logs_equal":observed==canonical,"first_difference":first_difference}),
            );
        }
        offset += len;
    }
    report.ok_or_else(|| "signed trace has not been recorded".into())
}

fn run(progress_path: &Path, progress_sha: &str, rpc_path: &Path) -> Result<Value> {
    let progress = pinned(progress_path, progress_sha)?;
    let actor = &progress["actor"];
    if progress["schema"] != "horizon-epoch167-bounded-first-protected-progress-v1"
        || progress["worker_sha256"] != WORKER_SHA
        || progress["archive_publication_authorized"] != false
        || actor["producer_unit"] != "horizon-qualify-167-checkpoint-bounded-20261127-v2.service"
    {
        return Err("wrong protected replay".into());
    }
    let release_ref = &progress["release"];
    let release = pinned(
        Path::new(release_ref["path"].as_str().ok_or("release path")?),
        release_ref["sha256"].as_str().ok_or("release digest")?,
    )?;
    if release["actor"] != *actor
        || release["intent"] != progress["intent"]
        || release["archive_publication_authorized"] != false
    {
        return Err("release differs from protected progress".into());
    }
    let rpc = pinned(rpc_path, RPC_SHA)?;
    let tx = &rpc["result"];
    if tx["slot"] != 72512769
        || tx["transactionIndex"] != 179
        || tx["transaction"]["signatures"][0] != SIGNATURE
        || tx["meta"]["status"] != json!({"Ok":null})
    {
        return Err("unexpected finalized transaction".into());
    }
    let canonical: Vec<String> = serde_json::from_value(tx["meta"]["logMessages"].clone())?;
    let evidence = &progress["producer_log"];
    let log_path = Path::new(evidence["path"].as_str().ok_or("log path")?);
    let mut log = regular(log_path)?;
    let meta = log.metadata()?;
    let limit = meta.len();
    let prefix_len = evidence["read_bytes"]
        .as_u64()
        .ok_or("startup log length")?;
    if evidence["device"] != meta.dev()
        || evidence["inode"] != meta.ino()
        || evidence["read_offset_bytes"] != 0
        || prefix_len == 0
        || prefix_len > 8 * 1024 * 1024
        || prefix_len > limit
        || limit > 512 * 1024 * 1024
    {
        return Err("foreign or inconsistent append log".into());
    }
    let mut prefix = Vec::new();
    (&mut log).take(prefix_len).read_to_end(&mut prefix)?;
    if evidence["read_sha256"] != sha(&prefix) {
        return Err("startup log prefix changed".into());
    }
    log.seek(SeekFrom::Start(0))?;
    let result = compare(BufReader::new((&mut log).take(limit)), &canonical)?;
    let after = regular(log_path)?.metadata()?;
    if (after.dev(), after.ino()) != (meta.dev(), meta.ino()) || after.len() < limit {
        return Err("append log replaced or truncated".into());
    }
    Ok(
        json!({"schema":"horizon-167-signed-swap-comparison-v1","release":release_ref,"first_progress_sha256":progress_sha,
        "producer_invocation_id":actor["producer_invocation_id"],"worker_sha256":WORKER_SHA,"finalized_rpc_sha256":RPC_SHA,
        "log_bytes_examined":limit,"comparison":result,"archive_publication_authorized":false}),
    )
}

fn main() -> Result<()> {
    let [_, proof, digest, rpc]: [String; 4] = std::env::args()
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| "expected FIRST_PROGRESS SHA256 FINALIZED_RPC_JSON")?;
    println!(
        "{}",
        serde_json::to_string_pretty(&run(Path::new(&proof), &digest, Path::new(&rpc))?)?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn line(result: &str, logs: &str) -> String {
        format!(
            "epoch167 trace slot=72512769 entry=143 transaction=179 signature={SIGNATURE} execution=Some({result}) logs=Some({logs})\n"
        )
    }
    #[test]
    fn compares_execution_and_all_ordered_logs_independently() {
        let canonical = vec!["a".into(), "b".into()];
        let good = line("Ok(())", r#"["a", "b"]"#);
        let result = compare(good.as_bytes(), &canonical).unwrap();
        assert_eq!(result["all_logs_equal"], true);
        assert_eq!(result["matches_finalized_success"], true);
        let bad = line(
            "Err(InstructionError(0, ProgramFailedToComplete))",
            r#"["b", "a"]"#,
        );
        let result = compare(bad.as_bytes(), &canonical).unwrap();
        assert_eq!(result["matches_finalized_success"], false);
        assert_eq!(result["first_difference"]["index"], 0);
        let short = line("Ok(())", r#"["a"]"#);
        assert_eq!(
            compare(short.as_bytes(), &canonical).unwrap()["first_difference"]["index"],
            1
        );
    }
    #[test]
    fn rejects_foreign_duplicate_and_partial_records() {
        let good = line("Ok(())", "[]");
        for text in [
            good.replace("entry=143", "entry=144"),
            good.repeat(2),
            good.trim_end().to_string(),
        ] {
            assert!(compare(text.as_bytes(), &[]).is_err());
        }
    }
}
