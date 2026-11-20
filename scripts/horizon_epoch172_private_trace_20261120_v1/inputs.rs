//! Check actual root-owned input and executable evidence before either host fit.
use super::*;
const EVIDENCE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch171-172-original-transaction-evidence-20261120-v1/evidence.json";
const PROVENANCE: &str = "27dfe64d9136561ad691b690ce83a1a2d8a9a3d6d1d414b12785999077758323";
pub(super) const SNAP: &str =
    "snapshot-74379198-7sUN98jiB8FuSu3nkpCm1gLBbPbFH1HtfocPKPV7asPj.tar.zst";
pub(super) const SNAP_SHA: &str =
    "fa7936328f4a4898ce9f35fd2892d9ba8f8ba03df345f8bc282ee6e913b2cc5f";
const SRC: &str = "/home/sol/.jetstreamer-private/epoch168-extractor-build-20261120-v1/work/171-172-incident-inputs-20261120-g1/download";
const WORKER: &str = "jetstreamer-historical-worker-v1-5-6";
const MERGED_WORKER: &str = "4ec0291d9bc3aa8164ff28e94eee46276cc0a624";
fn user_input(p: &Path, expected: u64, mode: u32) -> Result<File> {
    ensure!(p.canonicalize()? == p, "noncanonical download");
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(p)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && m.nlink() == 1
            && m.uid() == 1001
            && m.gid() == 1003
            && m.mode() & 0o7777 == mode
            && m.len() == expected,
        "unexpected download {}",
        p.display()
    );
    Ok(f)
}
pub(super) fn verify(proof: &Value) -> Result<Value> {
    let e = json_pin(Path::new(EVIDENCE), PROVENANCE)?;
    let row = &e["epochs"]["172"];
    let target = at(row, "signature")?;
    let terminal = &row["terminal"];
    ensure!(
        terminal["sha256"] == "cc7b8ea179ba89efff7d96224941d591e13fa71f6b13e3efb7b4cdc1c716c0cf",
        "terminal generation"
    );
    let old = json_pin(Path::new(at(terminal, "path")?), at(terminal, "sha256")?)?;
    ensure!(
        old["original_IID"] == "5359f45fc6df479ca62b17912f08e43d"
            && old["no_memory_DATA_or_slot_promise_ending"] == true
            && row["slot"] == 74380784
            && row["original_entry"] == 645
            && row["ordinal"] == 984
            && row["canonical_error"] == "ComputationalBudgetExceeded"
            && row["local_error"] == "instruction2 ProgramFailedToComplete",
        "historical evidence"
    );
    let response = &row["artifacts"]["response.json"];
    ensure!(
        response["sha256"] == "347700bb892006620a5d9d0a195cc13dce3725a6b6296f295ded5aeb498c24c6",
        "wrong signed response"
    );
    let rpc = json_pin(Path::new(at(response, "path")?), at(response, "sha256")?)?;
    ensure!(
        rpc["result"]["transaction"]["signatures"][0] == target
            && rpc["result"]["meta"]["err"]
                == json!({"InstructionError":[2,"ComputationalBudgetExceeded"]})
            && rpc["result"]["meta"]["logMessages"]
                == serde_json::from_slice::<Value>(include_bytes!("canonical-logs.json"))?,
        "canonical transaction/logs"
    );
    let input_dir = Path::new(BASE).join("inputs-v1");
    let seal = json_pin(
        &input_dir.join("deployment-seal-receipt.json"),
        at(proof, "input_seal_sha256")?,
    )?;
    let members = seal["members"].as_array().context("input package")?;
    ensure!(
        seal["destination"].as_str() == input_dir.to_str() && seal["remote_mutations"] == false,
        "wrong input package"
    );
    let worker_sha = env!("HORIZON172_TRACE_WORKER_SHA256");
    let worker_bytes: u64 = env!("HORIZON172_TRACE_WORKER_BYTES").parse()?;
    let member = |name: &str| -> Result<&Value> {
        let mut rows = members.iter().filter(|r| r["name"] == name);
        let r = rows.next().context("missing input member")?;
        ensure!(rows.next().is_none(), "duplicate input member");
        Ok(r)
    };
    let worker = member(WORKER)?;
    ensure!(
        worker["sha256"] == worker_sha
            && worker["bytes"] == worker_bytes
            && worker["mode"] == "0555",
        "worker seal"
    );
    pinned(&input_dir.join(WORKER), worker_sha)?;
    let meta = member("artifact-proof.json")?;
    let build = json_pin(&input_dir.join("artifact-proof.json"), at(meta, "sha256")?)?;
    ensure!(
        build["worker_source_commit"] == MERGED_WORKER
            && build["worker_source_contained_in_origin_account_updates"] == true
            && build["worker_sha256"] == worker_sha
            && build["worker_bytes"] == worker_bytes
            && build["signed_input_trace_test_passed"] == true
            && build["tests_failed"] == 0,
        "worker qualification"
    );
    // The whole digest was emitted after verification against GCS MD5 and CRC32C.
    // The payload rehashes every byte while copying the read-only bind, before exec.
    let headers = Path::new(SRC).join("172.headers");
    let mut h = String::new();
    user_input(&headers, 832, 0o600)?.read_to_string(&mut h)?;
    ensure!(
        digest(h.as_bytes()) == "47f19b3e5ca44acf625f63cc7f6a4ef9b05b96fbc011f15ad884d85dca8a9005"
            && h.lines()
                .any(|l| l == "x-goog-generation: 1634786215364147")
            && h.lines()
                .any(|l| l == "x-goog-hash: crc32c=yysMog==,md5=rOc4FiXjMYrupror5w4K1w=="),
        "hourly generation"
    );
    let p = Path::new(SRC).join(SNAP);
    let f = user_input(&p, 2_110_486_214, 0o400)?;
    let hourly_dir = Path::new(
        "/var/lib/jetstreamer/horizon_runtime_data/epoch171-172-hourly-snapshots-20261120-g1",
    );
    let hourly_sha = "bac7a1feecbb5b47af46c7ecdaa76d1c8cf17b1c5aa2edb1283a193a791fcc80";
    let hourly = json_pin(&hourly_dir.join("inputs.json"), hourly_sha)?;
    let auth = &hourly["epochs"]["172"];
    let downloaded = &auth["download"];
    let metadata = f.metadata()?;
    let route: Value = serde_json::from_slice(include_bytes!("hourly-route.json"))?;
    ensure!(
        hourly["schema"] == "horizon-historical-diagnostic-snapshot-inputs-v1"
            && hourly["source_commit"] == MERGED_WORKER
            && hourly["transfer_invocation"] == "c6146d871c524739b4426267cb006f9d"
            && hourly["whole_tar_listed"] == true
            && hourly["fetched_generation_and_validated_size_md5_crc32c"] == true
            && hourly["immutable_input_sha256_rechecked"] == true
            && hourly["restored_bank"] == false,
        "hourly snapshot authority"
    );
    ensure!(
        auth["source"] == route["bootstrap"]
            && auth["terminal_checkpoint"] == route["checkpoint"]
            && downloaded["sha256"] == SNAP_SHA
            && downloaded["path"].as_str() == p.to_str()
            && downloaded["size"] == metadata.len()
            && downloaded["device"] == metadata.dev()
            && downloaded["inode"] == metadata.ino()
            && downloaded["mtime_ns"].as_i64()
                == metadata
                    .mtime()
                    .checked_mul(1_000_000_000)
                    .and_then(|s| s.checked_add(metadata.mtime_nsec()))
            && auth["archive_inventory"]["tar_members"] == 385702
            && auth["archive_inventory"]["declared_member_bytes"] == 9_193_597_739u64,
        "hourly published snapshot identity"
    );
    let mut written = String::new();
    let expected = format!("{SNAP_SHA}  {SNAP}\n");
    user_input(
        &Path::new(SRC).join("172.sha256"),
        expected.len() as u64,
        0o600,
    )?
    .read_to_string(&mut written)?;
    ensure!(written == expected, "download digest");
    Ok(
        json!({"download":binding(&p,SNAP_SHA),"download_device":f.metadata()?.dev(),"download_inode":f.metadata()?.ino(),"hourly_inputs":binding(&hourly_dir.join("inputs.json"),hourly_sha),"gcs_generation":"1634786215364147","canonical_response":response,"original_terminal":terminal,"worker_seal":proof["input_seal_sha256"],"worker_sha256":worker_sha}),
    )
}
