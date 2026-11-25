//! Independently restore and compare every member from authenticated R2 ranges.
use super::super::appendvec292::tree;
use super::*;
use std::process::Stdio;

pub(super) const ACTION: &str = "holding-foundation-288-appendvec-restore-compare";
const STAGE_BINARY: &str =
    "/var/lib/jetstreamer/horizon288-closed-appendvec-study-v1/horizon-epoch288-appendvec-stage-v2";
const STAGE_BINARY_SHA: &str = "3c275261ca63ecd48f7c45d9e1f0d8c8a9918aab586d217eb9c688a732f13576";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ComparePlan {
    schema: String,
    mapping: Bound,
    custody: Bound,
}

fn source_census() -> Result<Value> {
    let output = Command::new(STAGE_BINARY).arg("check").output()?;
    ensure!(
        output.status.success(),
        "288 closed source census failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let census: Value = serde_json::from_slice(&output.stdout)?;
    ensure!(
        census["epoch"] == 288
            && census["census_sha256"] == CENSUS_SHA
            && census["process_scan"]["references"] == json!([]),
        "288 closed source census differs"
    );
    Ok(census)
}

async fn compare_payload(client: &Client, read: RemoteReadSpec<'_>, source: &Path) -> Result<()> {
    let mut decoder = Command::new(tree::ZSTD)
        .env_clear()
        .args(["-qdc", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let mut destination = decoder.stdin.take().context("missing decoder input")?;
    let mut tar = match Command::new(tree::TAR)
        .env_clear()
        .env("LC_ALL", "C")
        .args([
            "--compare",
            "--sparse",
            "--numeric-owner",
            "--file=-",
            "--directory",
        ])
        .arg(source)
        .stdin(decoder.stdout.take().context("missing decoder output")?)
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            let _ = decoder.kill();
            let _ = decoder.wait();
            return Err(error.into());
        }
    };
    let download = read_remote_sha256_resumable(client, read, &mut destination).await;
    drop(destination);
    if download.is_err() {
        let _ = decoder.kill();
        let _ = tar.kill();
    }
    let decoded = decoder.wait()?;
    let compared = tar.wait()?;
    download?;
    ensure!(
        decoded.success() && compared.success(),
        "288 full sparse restore differs"
    );
    Ok(())
}

pub(super) async fn run(value: Value, spec: &Bound) -> Result<()> {
    let plan: ComparePlan = serde_json::from_value(value)?;
    mapping(&plan.mapping)?;
    ensure!(
        plan.schema == "foundation-epoch288-appendvec-restore-compare-v1",
        "foreign 288 comparison plan"
    );
    let custody = saved(&plan.custody)?;
    let manifest = &custody["manifest"];
    let manifest_bytes = serde_json::to_vec(manifest)?;
    let manifest_sha = hex_lower(&Sha256::digest(&manifest_bytes));
    let manifest_key = manifest_key(&manifest_sha)?;
    let park: Bound = serde_json::from_value(custody["park_spec"].clone())?;
    ensure!(
        digest(&park.sha256)
            && plan.custody.path
                == Path::new(STATE)
                    .join("receipts")
                    .join(format!("appendvec288-custody-{}.json", park.sha256)),
        "288 custody receipt path differs"
    );
    let sample = saved(&Bound {
        path: Path::new(CONTROL).join("sample-qualification.json"),
        sha256: SAMPLE_SHA.into(),
    })?;
    let stage = &manifest["stage"];
    let body = body(stage, &sample)?;
    let staged_body: Bound = serde_json::from_value(manifest["stage_receipt"].clone())?;
    let object_key = key(body.sha256)?;
    let etag = custody["object_etag"]
        .as_str()
        .filter(|value| !value.is_empty())
        .context("288 custody ETag")?;
    ensure!(
        custody["schema"] == "foundation-epoch288-appendvec-custody-v1"
            && custody["host"] == host::HOST
            && custody["bucket"] == BUCKET
            && custody["prefix"] == SUBPREFIX
            && custody["epoch"] == 288
            && custody["object_key"] == object_key
            && custody["manifest_key"] == manifest_key
            && custody["manifest_sha256"] == manifest_sha
            && custody["remote_sha256_readback"] == true
            && custody["local_source_revalidated"] == true
            && custody["local_retirement_authorized"] == false
            && custody["publication_authorized"] == false
            && manifest["schema"] == "foundation-epoch288-appendvec-manifest-v1"
            && manifest["host"] == host::HOST
            && manifest["prefix"] == SUBPREFIX
            && manifest["epoch"] == 288
            && manifest["format"] == "gnu-sparse-pax-zstd"
            && manifest["object_key"] == object_key
            && manifest["length"] == body.length
            && manifest["sha256"] == body.sha256
            && manifest["sample_sha256"] == SAMPLE_SHA
            && manifest["source_census"] == sample["source_census"]
            && manifest["preserved_archive"] == sample["preserved_archive"]
            && manifest["canonical_archive"] == false
            && manifest["runtime_checkpoint_qualified"] == false
            && manifest["local_retirement_authorized"] == false
            && staged_body.path == Path::new(CONTROL).join("staging-body.json")
            && saved(&staged_body)? == *stage,
        "foreign or incomplete 288 custody evidence"
    );
    let source = Path::new(sample["source"].as_str().context("288 source")?);
    tree::require_read_only(source)?;
    tree::verify_tools()?;
    ensure!(
        hex_lower(&Sha256::digest(read_stable_bounded(
            Path::new(STAGE_BINARY),
            8 << 20,
            "288 source census binary"
        )?)) == STAGE_BINARY_SHA,
        "288 source census binary differs"
    );
    let before = source_census()?;
    let config = r2_config_from_env()?;
    ensure!(config.bucket == BUCKET, "foreign 288 comparison bucket");
    let client = s3_client(&config);
    let remote_owner = get_mutable_object(&client, BUCKET, &format!("{}owner.json", host::PREFIX))
        .await?
        .context("Foundation holding owner absent")?;
    ensure!(
        remote_owner.bytes == owner_bytes()?,
        "foreign Foundation holding owner"
    );
    let remote_manifest = get_mutable_object(&client, BUCKET, &manifest_key)
        .await?
        .context("288 remote manifest absent")?;
    ensure!(
        remote_manifest.bytes == manifest_bytes,
        "288 remote manifest differs"
    );
    let before_remote = head_archive(&client, BUCKET, &object_key)
        .await?
        .context("288 remote bundle absent")?;
    remote_matches(
        &before_remote,
        &object_key,
        body.length,
        body.sha256,
        Some(etag),
    )?;
    compare_payload(
        &client,
        RemoteReadSpec {
            bucket: BUCKET,
            key: &object_key,
            etag,
            expected_length: body.length,
            expected_sha256: body.sha256,
            concurrency: 1,
        },
        source,
    )
    .await?;
    tree::require_read_only(source)?;
    let after = source_census()?;
    let final_remote = head_archive(&client, BUCKET, &object_key)
        .await?
        .context("288 remote bundle disappeared")?;
    remote_matches(
        &final_remote,
        &object_key,
        body.length,
        body.sha256,
        Some(etag),
    )?;
    let path = receipt(
        &format!("appendvec288-stream-comparison-{}.json", spec.sha256),
        &json!({
            "schema":"foundation-epoch288-appendvec-stream-comparison-v1","epoch":288,
            "spec":spec,"custody":plan.custody,"source":source,"object_key":object_key,"object_etag":etag,
            "sha256":body.sha256,"length":body.length,"members":MEMBERS,"source_census_before":before,
            "source_census_after":after,"authenticated_remote_sha256_readback":true,
            "complete_sparse_payload_matches":true,"source_retirement_authorized":false,
            "publication_authorized":false
        }),
    )?;
    println!("{}", path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Seek, SeekFrom, Write},
        net::TcpListener,
    };

    #[tokio::test]
    async fn sparse_restore_stream_rejects_different_local_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let mut member = File::create(root.join("accounts")).unwrap();
        member.seek(SeekFrom::Start(2 << 20)).unwrap();
        member.write_all(b"last page").unwrap();
        let mtime = member.metadata().unwrap().modified().unwrap();
        let archive = Command::new(tree::TAR)
            .current_dir(root)
            .args(["--format=pax", "--sparse", "-cf", "-", "accounts"])
            .output()
            .unwrap();
        assert!(archive.status.success());
        let mut compressor = Command::new(tree::ZSTD)
            .args(["-qc", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        compressor
            .stdin
            .take()
            .unwrap()
            .write_all(&archive.stdout)
            .unwrap();
        let compressed = compressor.wait_with_output().unwrap();
        assert!(compressed.status.success());
        let bytes = compressed.stdout;
        let length = bytes.len() as u64;
        let sha256 = hex_lower(&Sha256::digest(&bytes));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let client = Client::from_conf(
            S3ConfigBuilder::new()
                .behavior_version(BehaviorVersion::latest())
                .region(Region::new("auto"))
                .credentials_provider(SharedCredentialsProvider::new(Credentials::new(
                    "fixture", "fixture", None, None, "fixture",
                )))
                .endpoint_url(format!("http://{}", listener.local_addr().unwrap()))
                .force_path_style(true)
                .build(),
        );
        let server = std::thread::spawn(move || {
            for _ in 0..2 {
                let deadline = Instant::now() + Duration::from_secs(10);
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(Instant::now() < deadline, "fixture request timed out");
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(error) => panic!("{error}"),
                    }
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    let mut next = [0];
                    stream.read_exact(&mut next).unwrap();
                    request.push(next[0]);
                    assert!(request.len() < 16 << 10);
                }
                let request = String::from_utf8(request).unwrap().to_ascii_lowercase();
                assert!(request.contains("if-match: \"fixture\"\r\n"));
                assert!(request.contains(&format!("range: bytes=0-{}\r\n", length - 1)));
                write!(stream, "HTTP/1.1 206 Partial Content\r\nContent-Length: {length}\r\nContent-Range: bytes 0-{}/{length}\r\nETag: \"fixture\"\r\nConnection: close\r\n\r\n", length - 1).unwrap();
                stream.write_all(&bytes).unwrap();
            }
        });
        let read = RemoteReadSpec {
            bucket: "fixture",
            key: "bundle",
            etag: "fixture",
            expected_length: length,
            expected_sha256: &sha256,
            concurrency: 1,
        };
        compare_payload(&client, read, root).await.unwrap();
        member.seek(SeekFrom::Start(2 << 20)).unwrap();
        member.write_all(b"bad bytes").unwrap();
        member.set_modified(mtime).unwrap();
        assert!(compare_payload(&client, read, root).await.is_err());
        server.join().unwrap();
    }
}
