//! Check actual root-owned input and executable evidence before either host fit.
use super::*;
const EVIDENCE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch171-172-original-transaction-evidence-20261120-v1/evidence.json";
const PROVENANCE: &str = "27dfe64d9136561ad691b690ce83a1a2d8a9a3d6d1d414b12785999077758323";
const SRC: &str = "/home/sol/.jetstreamer-private/epoch168-extractor-build-20261120-v1/work/171-172-incident-inputs-20261120-g1/download";
const WORKER: &str = "jetstreamer-historical-worker-v1-5-6";
const MERGED_WORKER: &str = "4ec0291d9bc3aa8164ff28e94eee46276cc0a624";
fn retained_input(p: &Path, expected: u64) -> Result<File> {
    ensure!(p.canonicalize()? == p, "noncanonical download");
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(p)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && m.nlink() == 1
            && m.uid() == 0
            && m.gid() == 0
            && m.mode() & 0o7777 == 0o444
            && m.len() == expected,
        "unexpected download {}",
        p.display()
    );
    Ok(f)
}
pub(super) fn verify(proof: &Value) -> Result<Value> {
    let e = json_pin(Path::new(EVIDENCE), PROVENANCE)?;
    let row = &e["epochs"][EPOCH_KEY];
    let target = at(row, "signature")?;
    let terminal = &row["terminal"];
    ensure!(
        terminal["sha256"] == ORIGINAL_TERMINAL_SHA,
        "terminal generation"
    );
    let old = json_pin(Path::new(at(terminal, "path")?), at(terminal, "sha256")?)?;
    ensure!(
        old["original_IID"] == ORIGINAL_IID
            && old["no_memory_DATA_or_slot_promise_ending"] == true
            && target == SIGNATURE
            && row["slot"] == TARGET
            && row["original_entry"] == ENTRY
            && row["ordinal"] == ORDINAL
            && row["canonical_error"] == CANONICAL_ERROR
            && row["local_error"] == format!("instruction2 {LOCAL_ERROR}"),
        "historical evidence"
    );
    let response = &row["artifacts"]["response.json"];
    ensure!(
        response["sha256"] == CANONICAL_RPC_SHA,
        "wrong signed response"
    );
    let rpc = json_pin(Path::new(at(response, "path")?), at(response, "sha256")?)?;
    ensure!(
        rpc["result"]["transaction"]["signatures"][0] == target
            && rpc["result"]["meta"]["err"] == json!({"InstructionError":[2,CANONICAL_ERROR]})
            && rpc["result"]["meta"]["logMessages"]
                == serde_json::from_slice::<Value>(CANONICAL_LOGS)?,
        "canonical transaction/logs"
    );
    let input_dir = Path::new(
        "/var/lib/jetstreamer/horizon_runtime_data/epoch172-metered-admission-20261120-g2/inputs-v1",
    );
    ensure!(
        proof["input_seal_sha256"]
            == "1200fdaf53b5326f68e093cd2035fff9ec276c8e3031cb855ed7a179c46e38b8",
        "wrong shared metered worker seal"
    );
    let seal = json_pin(
        &input_dir.join("deployment-seal-receipt.json"),
        at(proof, "input_seal_sha256")?,
    )?;
    let members = seal["members"].as_array().context("input package")?;
    ensure!(
        seal["destination"].as_str() == input_dir.to_str() && seal["remote_mutations"] == false,
        "wrong input package"
    );
    if EPOCH == 171 {
        let node_seal = json_pin(
            Path::new(NODE_PACKAGE)
                .join("deployment-seal-receipt.json")
                .as_path(),
            "a0b39e58bb539d03bcbbfd4835f926219f59186809b2106658836128410cc7e4",
        )?;
        ensure!(
            node_seal["destination"] == NODE_PACKAGE
                && node_seal["members"]
                    .as_array()
                    .context("node package")?
                    .iter()
                    .filter(|m| m["name"] == "jetstreamer-node"
                        && m["sha256"]
                            == "a09b8e5aa9426beaf42e6b5f2a469a5a147436bab8b7bf79f268758b60aa2e65"
                        && m["mode"] == "0555")
                    .count()
                    == 1,
            "171 node package seal"
        );
        pinned(
            Path::new(NODE),
            "a09b8e5aa9426beaf42e6b5f2a469a5a147436bab8b7bf79f268758b60aa2e65",
        )?;
    }
    let worker_sha = WORKER_SHA;
    let worker_bytes = WORKER_BYTES;
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
        build["worker_source_commit"] == WORKER_SOURCE
            && build["worker_tree"] == WORKER_TREE
            && build["worker_features"] == json!([WORKER_FEATURE])
            && build["build_invocation"] == "837e462108564861851d0c7bdc3ae218"
            && build["build_unit"] == "horizon-171-172-metered-worker-build-g3.service"
            && build["evidence"]["release.jsonl"]
                == "de59717a69f72c1cdf8c193da0cc29a40cd0844077d9df3f1d0862afa5418639"
            && build["evidence"]["tests.log"]
                == "300ba582612ff806af8457ae29d8c3e2bb8f61707f7073fc928696fc5cd36228"
            && build["tests_passed"] == 48
            && build["worker_source_contained_in_origin_account_updates"] == true
            && build["worker_sha256"] == worker_sha
            && build["worker_bytes"] == worker_bytes
            && build["signed_input_trace_test_passed"] == true
            && build["tests_failed"] == 0,
        "worker qualification"
    );
    // The whole digest was emitted after verification against GCS MD5 and CRC32C.
    // The payload rehashes every byte while copying the read-only bind, before exec.
    let headers = Path::new(SRC).join(format!("{EPOCH}.headers"));
    let mut h = String::new();
    retained_input(&headers, 832)?.read_to_string(&mut h)?;
    ensure!(
        digest(h.as_bytes()) == HEADERS_SHA
            && h.lines()
                .any(|l| l == format!("x-goog-generation: {SNAP_GENERATION}"))
            && h.lines().any(|l| l == CHECKSUM_HEADER),
        "hourly generation"
    );
    let p = Path::new(SRC).join(SNAP);
    let f = retained_input(&p, SNAP_BYTES)?;
    let hourly_dir = Path::new(
        "/var/lib/jetstreamer/horizon_runtime_data/epoch171-172-hourly-snapshots-20261120-g1",
    );
    let hourly_sha = "bac7a1feecbb5b47af46c7ecdaa76d1c8cf17b1c5aa2edb1283a193a791fcc80";
    let hourly = json_pin(&hourly_dir.join("inputs.json"), hourly_sha)?;
    let auth = &hourly["epochs"][EPOCH_KEY];
    let downloaded = &auth["download"];
    let metadata = f.metadata()?;
    let route: Value = serde_json::from_slice(HOURLY)?;
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
            && auth["archive_inventory"]["tar_members"] == TAR_MEMBERS
            && auth["archive_inventory"]["declared_member_bytes"] == TAR_BYTES,
        "hourly published snapshot identity"
    );
    let mut written = String::new();
    let expected = format!("{SNAP_SHA}  {SNAP}\n");
    retained_input(
        &Path::new(SRC).join(format!("{EPOCH}.sha256")),
        expected.len() as u64,
    )?
    .read_to_string(&mut written)?;
    ensure!(written == expected, "download digest");
    Ok(
        json!({"download":binding(&p,SNAP_SHA),"download_device":f.metadata()?.dev(),"download_inode":f.metadata()?.ino(),"hourly_inputs":binding(&hourly_dir.join("inputs.json"),hourly_sha),"gcs_generation":SNAP_GENERATION,"canonical_response":response,"original_terminal":terminal,"worker_seal":proof["input_seal_sha256"],"worker_sha256":worker_sha}),
    )
}

#[cfg(test)]
mod matched_route_tests {
    use super::*;

    #[test]
    #[ignore = "requires actual retained root-owned hourly and executable seals; read only"]
    fn authenticate_worker_and_epoch_inputs() {
        let r = verify(&json!({"input_seal_sha256":"1200fdaf53b5326f68e093cd2035fff9ec276c8e3031cb855ed7a179c46e38b8"})).unwrap();
        assert_eq!(r["worker_sha256"], WORKER_SHA);
        assert_eq!(r["download"]["sha256"], SNAP_SHA);
        assert_eq!(r["canonical_response"]["sha256"], CANONICAL_RPC_SHA);
        assert_eq!(r["original_terminal"]["sha256"], ORIGINAL_TERMINAL_SHA);
        assert!(verify(&json!({"input_seal_sha256":"wrong"})).is_err());
    }
}
