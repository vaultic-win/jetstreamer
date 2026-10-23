//! Closed, read-only range diagnostics for one backed failed artifact.
//! A sampled range is never a verified archive, prefix, or restart proof.
use super::*;
use jetstreamer_horizon::archive::{
    BucketHeader, FOOTER_LEN, FileHeader, Footer, MAX_BUCKET_INDEX_BYTES, MAX_BUCKET_INDEX_ENTRIES,
    parse_file_header,
};
use lencode::Decode;
use reqwest::{Method, StatusCode, header::HeaderMap};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const SHA: &str = "2122223b4e468bbd97cdf4562f2c079f4dcbcb81515152f781730af5bb47540f";
const ETAG: &str = "2ac69e5548618a7a92e60dfedf0a0de6-1486";
const LENGTH: u64 = 99_718_944_924;
const CUSTODY_SHA: &str = "8c45aba0c0f14e850839e276cafc1eee004dfcd9adbf4bb5da1de48dd4494cd4";
const CUSTODY_PATH: &str = "/home/sol/.jetstreamer-private/r2-holding-state-dev-samjohnson-v1/receipts/custody-b9fa90010f64d81436c674dd8ad98be16b51b91e2b643a85c75dd370eff6da72.json";
const MAP_SHA: &str = "61f7601f78a7aa1f71394a020cbbb28aa9dbd85de858f139def1c989f2b2a89e";
const ROOT: &str = "/var/lib/jetstreamer/horizon-epoch136-held-framing-probe-20261023-v1";
const BODY_CAP: usize = 512 * 1024;
const SMALL_CAP: usize = 64 * 1024;
const OUTPUT_CAP: usize = 4 * 1024 * 1024;
const OS_ALLOWANCE: u64 = 8 * 1024 * 1024;
const PREFIX: u64 = 65_536;
const OS_DEVICE: u64 = 2304;
const RETAINED_FLOOR: u64 = 205_211_459_014;
const MODERN_RESERVATION: u64 = 4 << 30;
const LEGACY_RESERVATION: u64 = 8 << 30;
const FIXTURE_RESERVATION: u64 = 10 << 30;
const PROTECTED_OS: u64 = 228_833_779_142;
const REQUIRED_OS: u64 = 228_842_167_750;
const BUDGET_PATH: &str =
    "/usr/local/lib/jetstreamer/horizon-v1425-portability-os-budget-20261023-v2/budget.json";
const BUDGET_SHA: &str = "2e95927a3c49972630c9de458e32359a859b90de7b0fa9b195d6dbb1083ed620";
const ADMISSION_PATH: &str =
    "/var/lib/jetstreamer/horizon-epoch136-held-framing-probe-20261023-v1/admission.json";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    mapping: Bound,
    custody: Bound,
    os_admission: Bound,
    self_sha256: String,
    output_directory: PathBuf,
    remote_mutations: bool,
    r2_mutations: bool,
}

fn scope(m: &Mapping, p: &Plan, c: &Value, own: &str) -> Result<(String, String)> {
    mapping(m)?;
    ensure!(
        p.schema == "jetstreamer-private-epoch136-held-framing-plan-v1"
            && p.mapping.path
                == Path::new(
                    "/usr/local/lib/jetstreamer/horizon-node02-holding-20261023-v1/mapping.json"
                )
            && p.mapping.sha256 == MAP_SHA
            && m.prefix == "node_02/"
            && p.custody.path == Path::new(CUSTODY_PATH)
            && p.custody.sha256 == CUSTODY_SHA
            && p.self_sha256 == own
            && digest(own)
            && !p.remote_mutations
            && !p.r2_mutations,
        "framing plan differs from exact closed136 scope"
    );
    let (key, etag, sha, length) = custody(c, m)?;
    ensure!(
        sha == SHA
            && length == LENGTH
            && etag == ETAG
            && c["mapping"]["path"] == p.mapping.path.to_string_lossy().as_ref()
            && c["mapping"]["sha256"] == MAP_SHA,
        "framing custody identity differs"
    );
    Ok((
        key,
        c["manifest_key"]
            .as_str()
            .context("manifest key")?
            .to_owned(),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmissionPlan {
    schema: String,
    mapping: Bound,
    custody: Bound,
    os_budget: Bound,
    self_sha256: String,
    receipt: PathBuf,
    not_before_unix_seconds: u64,
    not_after_unix_seconds: u64,
    remote_mutations: bool,
    r2_mutations: bool,
    replay_launch_authorized: bool,
    restore_authorized: bool,
}
#[derive(Clone, Serialize)]
struct StatfsSample {
    device: u64,
    directory_inode: u64,
    bavail: u64,
    block_size: u64,
    statfs_available_bytes: u64,
    recorded_unix_seconds: u64,
}
fn now_seconds() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn invocation(value: &str) -> Result<()> {
    ensure!(
        value.len() == 32
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && value != "0".repeat(32),
        "framing admission requires exact nonzero manager invocation ID"
    );
    Ok(())
}
fn validate_budget(b: &Value) -> Result<()> {
    ensure!(
        b["schema"] == "jetstreamer-v1425-portability-os-experiment-budget-v2"
            && b["host"] == HOST
            && b["filesystem"] == "/var/lib"
            && b["device"] == OS_DEVICE
            && b["minimum_retained_free_bytes"] == RETAINED_FLOOR
            && b["reservations"]["modern_builder_remaining_bytes"] == MODERN_RESERVATION
            && b["reservations"]["legacy_build_and_artifact_staging_increment_bytes"]
                == LEGACY_RESERVATION
            && b["reservations"]["fixture_maximum_physical_bytes"] == FIXTURE_RESERVATION
            && b["required_initial_free_bytes"] == PROTECTED_OS
            && RETAINED_FLOOR + MODERN_RESERVATION + LEGACY_RESERVATION + FIXTURE_RESERVATION
                == PROTECTED_OS
            && PROTECTED_OS + OS_ALLOWANCE == REQUIRED_OS,
        "framing admission must preserve every exact sealed OS reservation"
    );
    Ok(())
}
fn validate_statfs(s: &StatfsSample, now: u64) -> Result<()> {
    ensure!(
        s.device == OS_DEVICE
            && s.directory_inode > 0
            && s.block_size > 0
            && s.bavail.checked_mul(s.block_size) == Some(s.statfs_available_bytes)
            && s.statfs_available_bytes >= REQUIRED_OS
            && now
                .checked_sub(s.recorded_unix_seconds)
                .is_some_and(|age| age <= 30),
        "framing actual statfs device/freshness/full reservation floor differs"
    );
    Ok(())
}
fn actual_statfs() -> Result<StatfsSample> {
    private(Path::new(ROOT))?;
    let before = fs::symlink_metadata(ROOT)?;
    ensure!(
        before.dev() == OS_DEVICE,
        "framing root is not exact OS device2304"
    );
    let path = std::ffi::CString::new(ROOT)?;
    let mut output = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: fixed NUL-terminated path and correctly sized output storage.
    ensure!(
        unsafe { libc::statfs(path.as_ptr(), output.as_mut_ptr()) } == 0,
        "framing actual statfs syscall failed"
    );
    // SAFETY: successful statfs initialized the output structure.
    let output = unsafe { output.assume_init() };
    let after = fs::symlink_metadata(ROOT)?;
    ensure!(
        before.dev() == after.dev() && before.ino() == after.ino(),
        "framing root changed during statfs"
    );
    let block_size = u64::try_from(output.f_bsize).context("statfs negative block size")?;
    let bytes = output
        .f_bavail
        .checked_mul(block_size)
        .context("statfs available byte overflow")?;
    Ok(StatfsSample {
        device: after.dev(),
        directory_inode: after.ino(),
        bavail: output.f_bavail,
        block_size,
        statfs_available_bytes: bytes,
        recorded_unix_seconds: now_seconds()?,
    })
}
fn identity_fact(b: &Bound) -> Result<Value> {
    let md = fs::symlink_metadata(&b.path)?;
    Ok(
        json!({"path":b.path,"sha256":b.sha256,"device":md.dev(),"inode":md.ino(),
        "length":md.len(),"uid":md.uid(),"gid":md.gid(),"mode":md.mode(),"links":md.nlink(),
        "mtime_seconds":md.mtime(),"mtime_nanoseconds":md.mtime_nsec(),
        "ctime_seconds":md.ctime(),"ctime_nanoseconds":md.ctime_nsec()}),
    )
}
fn admission_receipt(
    p: &AdmissionPlan,
    spec: &Bound,
    own: &str,
    iid: &str,
    samples: [&StatfsSample; 2],
    identities: &Value,
    now: u64,
) -> Result<Value> {
    invocation(iid)?;
    ensure!(
        digest(&spec.sha256)
            && spec.path.is_absolute()
            && identities.as_array().is_some_and(|v| v.len() == 4),
        "admission requires exact bound plan and four-input identity census"
    );
    ensure!(
        p.schema == "jetstreamer-private-epoch136-held-framing-admission-plan-v1"
            && p.self_sha256 == own
            && digest(own)
            && p.mapping.sha256 == MAP_SHA
            && p.mapping.path.as_os_str()
                == Path::new(
                    "/usr/local/lib/jetstreamer/horizon-node02-holding-20261023-v1/mapping.json"
                )
                .as_os_str()
            && p.custody.sha256 == CUSTODY_SHA
            && p.custody.path.as_os_str() == Path::new(CUSTODY_PATH).as_os_str()
            && p.os_budget.sha256 == BUDGET_SHA
            && p.os_budget.path.as_os_str() == Path::new(BUDGET_PATH).as_os_str()
            && p.receipt.as_os_str() == Path::new(ADMISSION_PATH).as_os_str()
            && now >= p.not_before_unix_seconds
            && now <= p.not_after_unix_seconds
            && p.not_after_unix_seconds
                .checked_sub(p.not_before_unix_seconds)
                .is_some_and(|span| span <= 1800)
            && !p.remote_mutations
            && !p.r2_mutations
            && !p.replay_launch_authorized
            && !p.restore_authorized,
        "framing admission plan scope/age/authority differs"
    );
    for sample in samples {
        validate_statfs(sample, now)?;
    }
    ensure!(
        samples[1].recorded_unix_seconds >= samples[0].recorded_unix_seconds
            && samples[0].directory_inode == samples[1].directory_inode,
        "framing statfs samples reversed"
    );
    Ok(
        json!({"schema":"jetstreamer-private-epoch136-held-framing-os-admission-v1",
        "host":HOST,"self_sha256":own,"custody_sha256":CUSTODY_SHA,"mapping_sha256":MAP_SHA,
        "admission_plan":{"path":spec.path,"sha256":spec.sha256},"invocation_id":iid,
        "sealed_os_budget":{"path":p.os_budget.path,"sha256":p.os_budget.sha256},
        "input_identities":identities,"recorded_unix_seconds":now,"root":ROOT,"device":OS_DEVICE,
        "reserved_bytes":OS_ALLOWANCE,"protected_free_bytes":PROTECTED_OS,
        "required_initial_free_bytes":REQUIRED_OS,"statfs_available_bytes":samples[0].statfs_available_bytes.min(samples[1].statfs_available_bytes),
        "statfs_samples":samples,"reservation_release_assumed":false,
        "remote_mutations":false,"r2_mutations":false,"network_access_performed":false,
        "restore_authorized":false,"replay_launch_authorized":false,"publication_authorized":false,
        "r2_reads_authorized":false,"full_growth_admission":false,
        "runtime_checkpoint_qualified":false,"job_resume_authorized":false}),
    )
}
pub(super) fn admit(m: &Mapping, spec: &Bound, own: &str, value: Value) -> Result<()> {
    ensure!(
        env::var("TOKIO_WORKER_THREADS").as_deref() == Ok("2"),
        "framing admission requires2Tokio workers"
    );
    let p: AdmissionPlan = serde_json::from_value(value)?;
    let iid = env::var("INVOCATION_ID").context("framing admission manager invocation ID")?;
    invocation(&iid)?;
    private(Path::new(ROOT))?;
    ensure!(
        !p.receipt.try_exists()?,
        "framing admission receipt already exists"
    );
    let first = actual_statfs()?;
    let inputs = [spec, &p.mapping, &p.custody, &p.os_budget];
    let mut identities = Vec::new();
    for input in inputs {
        bound(input)?;
        identities.push(identity_fact(input)?);
    }
    let c = bound(&p.custody)?;
    let (key, etag, sha, length) = custody(&c, m)?;
    ensure!(
        m.prefix == "node_02/"
            && key == object_key(m, SHA)?
            && etag == ETAG
            && sha == SHA
            && length == LENGTH,
        "framing admission custody scope differs"
    );
    validate_budget(&bound(&p.os_budget)?)?;
    let second = actual_statfs()?;
    for (input, previous) in inputs.into_iter().zip(&identities) {
        bound(input)?;
        ensure!(
            &identity_fact(input)? == previous,
            "framing admission input identity changed"
        );
    }
    let receipt = admission_receipt(
        &p,
        spec,
        own,
        &iid,
        [&first, &second],
        &json!(identities),
        now_seconds()?,
    )?;
    write_new_receipt(&p.receipt, &receipt)
}
fn admission(a: &Value, own: &str, now: u64) -> Result<()> {
    let recorded = a["recorded_unix_seconds"]
        .as_u64()
        .context("admission clock")?;
    let iid = a["invocation_id"]
        .as_str()
        .context("admission invocation")?;
    invocation(iid)?;
    ensure!(
        a["schema"] == "jetstreamer-private-epoch136-held-framing-os-admission-v1"
            && a["host"] == HOST
            && a["self_sha256"] == own
            && a["custody_sha256"] == CUSTODY_SHA
            && a["mapping_sha256"] == MAP_SHA
            && a["root"] == ROOT
            && a["device"] == OS_DEVICE
            && a["reserved_bytes"] == OS_ALLOWANCE
            && a["protected_free_bytes"] == PROTECTED_OS
            && a["required_initial_free_bytes"] == REQUIRED_OS
            && a["statfs_available_bytes"]
                .as_u64()
                .is_some_and(|n| n >= REQUIRED_OS)
            && a["sealed_os_budget"]["path"] == BUDGET_PATH
            && a["sealed_os_budget"]["sha256"] == BUDGET_SHA
            && a["admission_plan"]["sha256"].as_str().is_some_and(digest)
            && a["input_identities"]
                .as_array()
                .is_some_and(|v| v.len() == 4)
            && now.checked_sub(recorded).is_some_and(|age| age <= 1800)
            && a["reservation_release_assumed"] == false
            && a["network_access_performed"] == false
            && a["remote_mutations"] == false
            && a["r2_mutations"] == false
            && a["replay_launch_authorized"] == false
            && a["restore_authorized"] == false
            && a["publication_authorized"] == false
            && a["job_resume_authorized"] == false
            && a["r2_reads_authorized"] == false
            && a["full_growth_admission"] == false,
        "framing needs emitted fresh exact OS admission"
    );
    let samples = a["statfs_samples"]
        .as_array()
        .context("admission statfs samples")?;
    ensure!(
        samples.len() == 2,
        "admission requires exactly two actual statfs samples"
    );
    let samples = samples
        .iter()
        .map(parse_statfs)
        .collect::<Result<Vec<_>>>()?;
    for sample in &samples {
        validate_statfs(sample, recorded)?;
    }
    ensure!(
        samples[0].directory_inode == samples[1].directory_inode
            && samples[1].recorded_unix_seconds >= samples[0].recorded_unix_seconds
            && a["statfs_available_bytes"]
                == samples[0]
                    .statfs_available_bytes
                    .min(samples[1].statfs_available_bytes),
        "admission sample identity/ordering/minimum differs"
    );
    Ok(())
}

fn parse_statfs(s: &Value) -> Result<StatfsSample> {
    Ok(StatfsSample {
        device: s["device"].as_u64().context("statfs device")?,
        directory_inode: s["directory_inode"]
            .as_u64()
            .context("statfs directory inode")?,
        bavail: s["bavail"].as_u64().context("statfs bavail")?,
        block_size: s["block_size"].as_u64().context("statfs block size")?,
        statfs_available_bytes: s["statfs_available_bytes"]
            .as_u64()
            .context("statfs bytes")?,
        recorded_unix_seconds: s["recorded_unix_seconds"]
            .as_u64()
            .context("statfs clock")?,
    })
}
fn verify_admission_sources(a: &Value, own: &str) -> Result<()> {
    let spec: Bound = serde_json::from_value(a["admission_plan"].clone())?;
    let p: AdmissionPlan = serde_json::from_value(bound(&spec)?)?;
    let inputs = [&spec, &p.mapping, &p.custody, &p.os_budget];
    let identities = a["input_identities"]
        .as_array()
        .context("admission identities")?;
    ensure!(
        identities.len() == inputs.len(),
        "admission input census differs"
    );
    for (input, old) in inputs.into_iter().zip(identities) {
        bound(input)?;
        ensure!(
            &identity_fact(input)? == old,
            "admission input changed after emission"
        );
    }
    validate_budget(&bound(&p.os_budget)?)?;
    let samples = a["statfs_samples"]
        .as_array()
        .context("admission statfs samples")?;
    ensure!(samples.len() == 2, "admission sample count differs");
    let first = parse_statfs(&samples[0])?;
    let second = parse_statfs(&samples[1])?;
    let expected = admission_receipt(
        &p,
        &spec,
        own,
        a["invocation_id"]
            .as_str()
            .context("admission invocation")?,
        [&first, &second],
        &a["input_identities"],
        a["recorded_unix_seconds"]
            .as_u64()
            .context("admission clock")?,
    )?;
    ensure!(
        &expected == a,
        "admission receipt does not reproduce exact emitter inputs"
    );
    Ok(())
}

fn header_text<'a>(h: &'a HeaderMap, key: &str) -> Result<&'a str> {
    h.get(key)
        .context("missing diagnostic response header")?
        .to_str()
        .context("non-ASCII diagnostic response header")
}
fn head_identity(h: &HeaderMap) -> Result<()> {
    ensure!(
        header_text(h, "content-length")?.parse::<u64>()? == LENGTH
            && normalize_etag(header_text(h, "etag")?) == ETAG
            && header_text(h, "x-amz-meta-sha256")? == SHA,
        "held object HEAD identity differs"
    );
    Ok(())
}
fn response_bounds(status: StatusCode, h: &HeaderMap, range: Option<(u64, u64)>) -> Result<usize> {
    let length = header_text(h, "content-length")?.parse::<usize>()?;
    if let Some((start, end)) = range {
        ensure!(
            status == StatusCode::PARTIAL_CONTENT,
            "range GET must return206"
        );
        ensure!(
            start < end && end <= LENGTH && u64::try_from(length)? == end - start,
            "range response length differs"
        );
        ensure!(
            header_text(h, "content-range")? == format!("bytes {start}-{}/{LENGTH}", end - 1)
                && normalize_etag(header_text(h, "etag")?) == ETAG,
            "range response identity differs"
        );
    } else {
        ensure!(
            status == StatusCode::OK && length <= SMALL_CAP,
            "small object response status/length differs"
        );
    }
    ensure!(
        !h.contains_key("content-encoding"),
        "encoded diagnostic response is forbidden"
    );
    Ok(length)
}

#[derive(Default, Serialize)]
struct Trace {
    body_bytes: usize,
    requests: Vec<Value>,
}
impl Trace {
    fn add_chunk(&mut self, target: &mut Vec<u8>, chunk: &[u8], expected: usize) -> Result<()> {
        // Check BOTH caps before extending/allocating our destination buffer.
        self.body_bytes = self.body_bytes.saturating_add(chunk.len());
        ensure!(
            self.body_bytes <= BODY_CAP,
            "diagnostic aggregate body budget exceeded"
        );
        ensure!(
            chunk.len() <= expected.saturating_sub(target.len()),
            "diagnostic body exceeds declared length"
        );
        target.extend_from_slice(chunk);
        Ok(())
    }
}
struct Probe {
    client: Client,
    http: reqwest::Client,
    trace: Trace,
    blob_key: String,
    manifest_key: String,
    blob_gets: usize,
    small_gets: usize,
    heads: usize,
}
impl Probe {
    async fn request(
        &mut self,
        key: &str,
        head: bool,
        range: Option<(u64, u64)>,
    ) -> Result<Vec<u8>> {
        if head {
            self.heads += 1;
            ensure!(
                self.heads <= 2 && key == self.blob_key && range.is_none(),
                "unexpected HEAD census"
            );
        } else if let Some((start, end)) = range {
            self.blob_gets += 1;
            ensure!(
                self.blob_gets <= 3
                    && key == self.blob_key
                    && ((start == 0 && end == PREFIX)
                        || (start == LENGTH - FOOTER_LEN as u64 && end == LENGTH)
                        || (start >= 8 && start <= PREFIX && end - start <= 256)),
                "unexpected blob request census"
            );
        } else {
            self.small_gets += 1;
            ensure!(
                self.small_gets <= 4 && (key == "node_02/owner.json" || key == self.manifest_key),
                "unexpected small request census"
            );
        }
        let index = self.trace.requests.len();
        self.trace
            .requests
            .push(json!({"method":if head {"HEAD"} else {"GET"},
            "key":key,"range":range,"if_match":if range.is_some() {Some(ETAG)} else {None},
            "outcome":"pending","received_bytes":0}));
        let started = Instant::now();
        let result = tokio::time::timeout(
            Duration::from_secs(20),
            self.request_inner(index, key, head, range),
        )
        .await;
        self.trace.requests[index]["elapsed_millis"] = json!(started.elapsed().as_millis());
        let result = result.unwrap_or_else(|_| Err(anyhow!("diagnostic request20second deadline")));
        self.trace.requests[index]["outcome"] = json!(match &result {
            Ok(_) => "success",
            Err(_) => "failure",
        });
        if let Err(e) = &result {
            self.trace.requests[index]["error"] = json!(e.to_string());
        }
        result
    }
    async fn request_inner(
        &mut self,
        index: usize,
        key: &str,
        head: bool,
        range: Option<(u64, u64)>,
    ) -> Result<Vec<u8>> {
        use aws_sdk_s3::presigning::PresigningConfig;
        let expires = || PresigningConfig::expires_in(Duration::from_secs(120));
        // Presigning makes no request. Actual HTTP below has retries/redirects
        // disabled and never exposes credential-bearing URL errors.
        let signed = if head {
            self.client
                .head_object()
                .bucket(BUCKET)
                .key(key)
                .presigned(expires()?)
                .await
                .map_err(|_| anyhow!("HEAD signing failed"))?
        } else {
            let mut builder = self.client.get_object().bucket(BUCKET).key(key);
            if let Some((start, end)) = range {
                builder = builder
                    .range(format!("bytes={start}-{}", end - 1))
                    .if_match(format!("\"{ETAG}\""));
            }
            builder
                .presigned(expires()?)
                .await
                .map_err(|_| anyhow!("GET signing failed"))?
        };
        let mut request = self
            .http
            .request(if head { Method::HEAD } else { Method::GET }, signed.uri());
        for (key, value) in signed.headers() {
            request = request.header(key, value);
        }
        let mut response = request
            .send()
            .await
            .map_err(|_| anyhow!("diagnostic HTTP request failed"))?;
        self.trace.requests[index]["status"] = json!(response.status().as_u16());
        let mut headers = serde_json::Map::new();
        for name in [
            "content-length",
            "content-range",
            "etag",
            "x-amz-meta-sha256",
            "content-encoding",
        ] {
            if let Some(value) = response.headers().get(name) {
                ensure!(
                    value.as_bytes().len() <= 1024,
                    "diagnostic response header exceeds limit"
                );
                headers.insert(name.into(), json!(value.to_str().unwrap_or("<non-ASCII>")));
            }
        }
        self.trace.requests[index]["response_headers"] = Value::Object(headers);
        if head {
            ensure!(response.status() == StatusCode::OK, "HEAD status differs");
            head_identity(response.headers())?;
            return Ok(Vec::new());
        }
        let expected = response_bounds(response.status(), response.headers(), range)?;
        ensure!(
            expected <= BODY_CAP.saturating_sub(self.trace.body_bytes),
            "declared aggregate byte budget exceeded"
        );
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| anyhow!("diagnostic body stream failed"))?
        {
            self.trace.requests[index]["received_bytes"] =
                json!(bytes.len().saturating_add(chunk.len()));
            self.trace.add_chunk(&mut bytes, &chunk, expected)?;
            self.trace.requests[index]["body_base64"] = json!(BASE64_STANDARD.encode(&bytes));
            self.trace.requests[index]["partial_sha256"] =
                json!(hex_lower(&Sha256::digest(&bytes)));
        }
        ensure!(bytes.len() == expected, "diagnostic body truncated");
        self.trace.requests[index]["sha256"] = json!(hex_lower(&Sha256::digest(&bytes)));
        Ok(bytes)
    }
    async fn verify_owner_manifest(&mut self, m: &Mapping, custody: &Value) -> Result<()> {
        let owner = self.request("node_02/owner.json", false, None).await?;
        ensure!(owner == owner_bytes(m)?, "holding owner differs");
        let key = self.manifest_key.clone();
        let manifest = self.request(&key, false, None).await?;
        ensure!(
            hex_lower(&Sha256::digest(&manifest))
                == custody["manifest_sha256"]
                    .as_str()
                    .context("manifest SHA")?
                && serde_json::from_slice::<Value>(&manifest)? == custody["manifest"],
            "holding manifest changed"
        );
        Ok(())
    }
    async fn inspect(&mut self, m: &Mapping, custody: &Value) -> Result<Value> {
        self.verify_owner_manifest(m, custody).await?;
        let key = self.blob_key.clone();
        self.request(&key, true, None).await?;
        let front = self.request(&key, false, Some((0, PREFIX))).await?;
        let (header, offset) = uncompressed_header(&front)?;
        ensure!(
            header.epoch == 136 && header.slot_start == 58_752_000 && header.slot_count == 432_000,
            "held original output scope differs"
        );
        let provenance = json!({"encoded_bytes":header.meta.reserved.len(),
            "encoded_sha256":hex_lower(&Sha256::digest(&header.meta.reserved)),
            "decoded":false,"reason":"no-decompression diagnostic; original bytes preserved"});
        let bucket_bytes = if front.len().saturating_sub(offset) < 256 {
            self.request(&key, false, Some((offset as u64, offset as u64 + 256)))
                .await?
        } else {
            front[offset..offset + 256].to_vec()
        };
        let bucket = first_bucket(&header, offset, &bucket_bytes)?;
        let tail = self
            .request(&key, false, Some((LENGTH - FOOTER_LEN as u64, LENGTH)))
            .await?;
        let footer = footer_facts(offset as u64, &tail);
        self.request(&key, true, None).await?;
        self.verify_owner_manifest(m, custody).await?;
        Ok(
            json!({"format_version":header.format_version,"flags":header.flags,
            "epoch":header.epoch,"slot_start":header.slot_start,"slot_count":header.slot_count,
            "bucket_slots":header.bucket_slots,"header_end":offset,
            "provenance_envelope":provenance,"first_bucket":bucket,"footer":footer,
            "first_frame":"not_attempted_full_bucket_required",
            "prefix_base64":BASE64_STANDARD.encode(front),"first_bucket_header_window_base64":BASE64_STANDARD.encode(bucket_bytes),
            "tail_base64":BASE64_STANDARD.encode(tail)}),
        )
    }
}

// The ordinary header parser permits bounded compressed metadata. This probe
// forbids decompression, including metadata: inspect scalar/byte-vector framing
// first, before calling it. The separately versioned provenance stays opaque.
fn uncompressed_header(prefix: &[u8]) -> Result<(FileHeader, usize)> {
    ensure!(
        prefix.get(..8) == Some(&jetstreamer_horizon::archive::MAGIC[..]),
        "held header magic"
    );
    let mut framed = &prefix[8..];
    let length = usize::try_from(u64::decode_ext(&mut framed, None)?)?;
    ensure!(
        length <= SMALL_CAP && length <= framed.len(),
        "held header exceeds fixed probe window"
    );
    let mut fields = &framed[..length];
    u16::decode_ext(&mut fields, None)?;
    u16::decode_ext(&mut fields, None)?;
    for _ in 0..6 {
        u64::decode_ext(&mut fields, None)?;
    }
    for _ in 0..2 {
        let marker = u64::decode_ext(&mut fields, None)?;
        ensure!(
            marker & 1 == 0,
            "compressed header metadata unsupported by no-decompression probe"
        );
        let bytes = usize::try_from(marker >> 1)?;
        ensure!(bytes <= fields.len(), "truncated raw header metadata");
        fields = &fields[bytes..];
    }
    ensure!(fields.is_empty(), "trailing header metadata");
    parse_file_header(prefix).context("held file header")
}

fn first_bucket(header: &FileHeader, offset: usize, bytes: &[u8]) -> Result<Value> {
    let mut remaining = bytes;
    let bucket =
        BucketHeader::decode_ext(&mut remaining, None).context("held first bucket header")?;
    let header_bytes = bytes.len() - remaining.len();
    let payload_start = (offset as u64)
        .checked_add(header_bytes as u64)
        .context("bucket offset overflow")?;
    let payload_end = payload_start
        .checked_add(bucket.stored_len)
        .context("bucket extent overflow")?;
    ensure!(
        bucket.first_slot == header.slot_start
            && bucket.slot_count > 0
            && u64::from(bucket.slot_count) <= u64::from(header.bucket_slots)
            && bucket.stored_len > 0
            && bucket.uncompressed_len > 0
            && payload_end <= LENGTH,
        "held first bucket extent differs"
    );
    // Hard diagnostic bound; no payload is fetched or allocated.
    ensure!(
        bucket.stored_len <= jetstreamer_horizon::archive::MAX_BUCKET_STORED_BYTES
            && bucket.uncompressed_len
                <= jetstreamer_horizon::archive::MAX_BUCKET_UNCOMPRESSED_BYTES
            && !(header.format_version == 1
                && bucket.compression == jetstreamer_horizon::archive::Compression::Lz4)
            && (bucket.compression != jetstreamer_horizon::archive::Compression::None
                || bucket.stored_len == bucket.uncompressed_len),
        "held first bucket length exceeds diagnostic bound"
    );
    Ok(
        json!({"first_slot":bucket.first_slot,"slot_count":bucket.slot_count,
        "compression":format!("{:?}",bucket.compression),"stored_len":bucket.stored_len,
        "uncompressed_len":bucket.uncompressed_len,"xxh64":bucket.xxh64,
        "poh_start_hash":bucket.poh_start_hash.to_string(),"header_bytes":header_bytes,
        "payload_start":payload_start,"next_header_candidate_offset":payload_end,
        "payload_integrity_verified":false,"complete_bucket_verified":false}),
    )
}
fn footer_facts(header_end: u64, bytes: &[u8]) -> Value {
    let parsed = (|| -> Result<Footer> {
        let fixed: &[u8; FOOTER_LEN] = bytes.try_into().context("footer byte length")?;
        let footer = Footer::from_bytes(fixed)?;
        ensure!(
            footer.index_offset >= header_end
                && footer.index_len <= MAX_BUCKET_INDEX_BYTES
                && footer.bucket_count > 0
                && footer.bucket_count <= MAX_BUCKET_INDEX_ENTRIES
                && footer.index_offset.checked_add(footer.index_len)
                    == Some(LENGTH - FOOTER_LEN as u64),
            "footer index extent invalid"
        );
        Ok(footer)
    })();
    match parsed {
        Ok(f) => json!({"footer_structure_present":true,"index_offset":f.index_offset,
            "index_len":f.index_len,"bucket_count":f.bucket_count,"index_xxh64":f.index_xxh64,
            "index_integrity_verified":false,"complete_container_verified":false}),
        Err(error) => json!({"footer_structure_present":false,"diagnostic":error.to_string(),
            "complete_container_verified":false}),
    }
}

fn write_new_receipt(path: &Path, value: &Value) -> Result<()> {
    private(path.parent().context("receipt parent")?)?;
    let bytes = serde_json::to_vec_pretty(value)?;
    ensure!(
        bytes.len() <= OUTPUT_CAP,
        "diagnostic output budget exceeded"
    );
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    File::open(path.parent().unwrap())?.sync_all()?;
    Ok(())
}

pub(super) async fn run(m: &Mapping, spec: &Bound, own: &str, value: Value) -> Result<()> {
    let invocation_started = Instant::now();
    ensure!(
        env::var("TOKIO_WORKER_THREADS").as_deref() == Ok("2"),
        "framing requires exactly2Tokio workers"
    );
    let p: Plan = serde_json::from_value(value)?;
    let custody = bound(&p.custody)?;
    let (key, manifest_key) = scope(m, &p, &custody, own)?;
    ensure!(
        p.output_directory.as_os_str() == Path::new(ROOT).join("output").as_os_str(),
        "framing output alias/path differs"
    );
    private(Path::new(ROOT))?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    ensure!(
        p.os_admission.path.as_os_str() == Path::new(ADMISSION_PATH).as_os_str(),
        "framing admission receipt alias differs"
    );
    let emitted_admission = bound(&p.os_admission)?;
    admission(&emitted_admission, own, now)?;
    verify_admission_sources(&emitted_admission, own)?;
    validate_statfs(&actual_statfs()?, now_seconds()?)?;
    fs::create_dir(&p.output_directory)?;
    fs::set_permissions(&p.output_directory, fs::Permissions::from_mode(0o700))?;
    private(&p.output_directory)?;
    File::open(ROOT)?.sync_all()?;
    let config = r2_config_from_env()?;
    ensure!(config.bucket == BUCKET, "foreign framing bucket");
    let signing = s3_client(&config);
    let signing = Client::from_conf(
        signing
            .config()
            .to_builder()
            .retry_config(aws_sdk_s3::config::retry::RetryConfig::disabled())
            .build(),
    );
    let mut probe = Probe {
        client: signing,
        http: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .timeout(Duration::from_secs(20))
            .build()?,
        trace: Trace::default(),
        blob_key: key,
        manifest_key,
        blob_gets: 0,
        small_gets: 0,
        heads: 0,
    };
    let started = invocation_started;
    // Reserve the final five seconds of the sealed120second service bound for
    // durable failure provenance instead of letting service timeout kill it.
    let remaining = Duration::from_secs(115).saturating_sub(started.elapsed());
    let result = tokio::time::timeout(remaining, probe.inspect(m, &custody))
        .await
        .unwrap_or_else(|_| Err(anyhow!("whole framing probe115second work deadline")));
    for request in &mut probe.trace.requests {
        if request["outcome"] == "pending" {
            request["outcome"] = json!("cancelled_by_whole_probe_deadline");
        }
    }
    let receipt = json!({"schema":"jetstreamer-private-epoch136-held-framing-probe-v1",
        "host":HOST,"epoch":136,"self_sha256":own,"plan":{"path":spec.path,"sha256":spec.sha256},
        "custody":{"path":p.custody.path,"sha256":p.custody.sha256},
        "mapping":{"path":p.mapping.path,"sha256":p.mapping.sha256},
        "os_admission":{"path":p.os_admission.path,"sha256":p.os_admission.sha256},
        "expected_blob":{"bucket":BUCKET,"key":probe.blob_key,"etag":ETAG,"length":LENGTH,"sha256":SHA},
        "elapsed_millis":started.elapsed().as_millis(),"request_trace":probe.trace,
        "result":match &result {Ok(facts) => json!({"status":"observed","facts":facts}),Err(error) => json!({"status":"failed","error":error.to_string()})},
        "whole_object_integrity_reverified":false,"selected_prefix_integrity_verified":false,
        "complete_bucket_census":false,"prefix_closed":false,"native_checkpoint_verified":false,
        "root_verified":false,"restart_authorized":false,"publication_authorized":false,
        "replay_launch_authorized":false,"remote_mutations":false,"r2_mutations":false});
    write_new_receipt(&p.output_directory.join("receipt.json"), &receipt)?;
    result.map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use jetstreamer_horizon::archive::{
        ArchiveMeta, ArchiveVersion, Compression, MAGIC, PRIME_TABLE_ID,
    };
    use lencode::Encode;
    use std::net::TcpListener;

    fn file_header() -> FileHeader {
        FileHeader {
            format_version: 2,
            bucket_slots: 128,
            epoch: 136,
            slot_start: 58_752_000,
            slot_count: 432_000,
            prime_table_id: *PRIME_TABLE_ID,
            flags: ArchiveVersion::V2.required_flags(),
            meta: ArchiveMeta::default(),
        }
    }
    fn header_bytes(h: &FileHeader) -> Vec<u8> {
        let mut raw = Vec::new();
        h.encode_ext(&mut raw, None).unwrap();
        let mut bytes = MAGIC.to_vec();
        (raw.len() as u64).encode_ext(&mut bytes, None).unwrap();
        bytes.extend(raw);
        bytes
    }
    fn bucket() -> BucketHeader {
        BucketHeader {
            first_slot: 58_752_000,
            slot_count: 128,
            compression: Compression::Zstd,
            uncompressed_len: 1024,
            stored_len: 128,
            xxh64: 1,
            poh_start_hash: Default::default(),
        }
    }
    fn encode_bucket(b: &BucketHeader) -> Vec<u8> {
        let mut raw = Vec::new();
        b.encode_ext(&mut raw, None).unwrap();
        raw
    }
    fn response_headers(length: usize) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("content-length", length.to_string().parse().unwrap());
        h.insert("etag", format!("\"{ETAG}\"").parse().unwrap());
        h.insert(
            "content-range",
            format!("bytes 0-{}/{LENGTH}", length - 1).parse().unwrap(),
        );
        h
    }
    #[test]
    fn framing_rejects_bad_versions_flags_prime_table_and_truncation() {
        let h = file_header();
        assert!(parse_file_header(&header_bytes(&h)).is_ok());
        for changed in [
            FileHeader {
                format_version: 9,
                ..h.clone()
            },
            FileHeader {
                flags: u64::MAX,
                ..h.clone()
            },
            FileHeader {
                prime_table_id: 0,
                ..h.clone()
            },
            FileHeader {
                bucket_slots: 0,
                ..h.clone()
            },
        ] {
            assert!(parse_file_header(&header_bytes(&changed)).is_err());
        }
        assert!(uncompressed_header(&header_bytes(&h)).is_ok());
        let mut compressed = h.clone();
        compressed.meta.writer_version = vec![b'a'; 4096];
        assert!(uncompressed_header(&header_bytes(&compressed)).is_err());
        let raw = header_bytes(&h);
        for cut in 0..raw.len() {
            assert!(parse_file_header(&raw[..cut]).is_err());
        }
        let mut huge = MAGIC.to_vec();
        (u64::MAX).encode_ext(&mut huge, None).unwrap();
        assert!(parse_file_header(&huge).is_err());
    }
    #[test]
    fn bucket_metadata_is_not_payload_or_prefix_integrity() {
        let h = file_header();
        let b = bucket();
        let raw = encode_bucket(&b);
        let facts = first_bucket(&h, 256, &raw).unwrap();
        assert_eq!(facts["complete_bucket_verified"], false);
        assert_eq!(facts["payload_integrity_verified"], false);
        for cut in 0..raw.len() {
            assert!(first_bucket(&h, 256, &raw[..cut]).is_err());
        }
        for changed in [
            BucketHeader {
                first_slot: b.first_slot + 1,
                ..b.clone()
            },
            BucketHeader {
                stored_len: u64::MAX,
                ..b.clone()
            },
            BucketHeader {
                slot_count: 129,
                ..b.clone()
            },
            BucketHeader {
                slot_count: 0,
                ..b.clone()
            },
            BucketHeader {
                compression: Compression::None,
                ..b.clone()
            },
        ] {
            assert!(first_bucket(&h, 256, &encode_bucket(&changed)).is_err());
        }
        let lz4 = BucketHeader {
            compression: Compression::Lz4,
            ..b
        };
        assert!(
            first_bucket(
                &FileHeader {
                    format_version: 1,
                    ..h
                },
                256,
                &encode_bucket(&lz4)
            )
            .is_err()
        );
    }
    #[test]
    fn plausible_footer_keeps_index_unverified_and_missing_footer_is_diagnostic() {
        let f = Footer {
            index_offset: LENGTH - FOOTER_LEN as u64 - 64,
            index_len: 64,
            bucket_count: 2,
            index_xxh64: 0,
        };
        let result = footer_facts(256, &f.to_bytes());
        assert_eq!(result["footer_structure_present"], true);
        assert_eq!(result["index_integrity_verified"], false);
        assert_eq!(result["complete_container_verified"], false);
        assert_eq!(
            footer_facts(256, &[0; FOOTER_LEN])["footer_structure_present"],
            false
        );
        let f = Footer {
            index_len: u64::MAX,
            ..f
        };
        assert_eq!(
            footer_facts(256, &f.to_bytes())["footer_structure_present"],
            false
        );
    }
    #[test]
    fn transport_rejects_ignored_range_412_missing_or_changed_identity() {
        let good = response_headers(64);
        assert_eq!(
            response_bounds(StatusCode::PARTIAL_CONTENT, &good, Some((0, 64))).unwrap(),
            64
        );
        for status in [
            StatusCode::OK,
            StatusCode::PRECONDITION_FAILED,
            StatusCode::MOVED_PERMANENTLY,
        ] {
            assert!(response_bounds(status, &good, Some((0, 64))).is_err());
        }
        for name in ["content-length", "content-range", "etag"] {
            let mut missing = good.clone();
            missing.remove(name);
            assert!(response_bounds(StatusCode::PARTIAL_CONTENT, &missing, Some((0, 64))).is_err());
        }
        let mut changed = good.clone();
        changed.insert("etag", "\"new-owner\"".parse().unwrap());
        assert!(response_bounds(StatusCode::PARTIAL_CONTENT, &changed, Some((0, 64))).is_err());
        let mut changed = good.clone();
        changed.insert("content-range", "bytes 0-63/999".parse().unwrap());
        assert!(response_bounds(StatusCode::PARTIAL_CONTENT, &changed, Some((0, 64))).is_err());
        let mut changed = good;
        changed.insert("content-encoding", "gzip".parse().unwrap());
        assert!(response_bounds(StatusCode::PARTIAL_CONTENT, &changed, Some((0, 64))).is_err());
    }
    #[test]
    fn streaming_checks_limits_before_extending_and_counts_rejected_bytes() {
        let mut t = Trace::default();
        let mut data = vec![];
        t.add_chunk(&mut data, b"abcd", 4).unwrap();
        assert!(t.add_chunk(&mut data, b"EXTRA", 4).is_err());
        assert_eq!(data, b"abcd");
        assert_eq!(t.body_bytes, 9);
        t.body_bytes = BODY_CAP - 1;
        assert!(t.add_chunk(&mut data, b"xx", 100).is_err());
        assert_eq!(data, b"abcd");
        assert_eq!(t.body_bytes, BODY_CAP + 1);
    }
    #[test]
    fn changed_head_is_rejected() {
        let mut h = response_headers(LENGTH as usize);
        h.insert("x-amz-meta-sha256", SHA.parse().unwrap());
        head_identity(&h).unwrap();
        for name in ["content-length", "etag", "x-amz-meta-sha256"] {
            let mut bad = h.clone();
            bad.insert(name, "0".parse().unwrap());
            assert!(head_identity(&bad).is_err());
        }
    }
    fn fixture_scope() -> (Mapping, Plan, Value, String) {
        let m = Mapping {
            schema: "jetstreamer-horizon-host-holding-prefix-v2".into(),
            host: HOST.into(),
            prefix: "node_02/".into(),
            user_provided_prefix: true,
            authorization_reference: "test fixture".into(),
        };
        let own = "a".repeat(64);
        let p = Plan {
            schema: "jetstreamer-private-epoch136-held-framing-plan-v1".into(),
            mapping: Bound {
                path: "/usr/local/lib/jetstreamer/horizon-node02-holding-20261023-v1/mapping.json"
                    .into(),
                sha256: MAP_SHA.into(),
            },
            custody: Bound {
                path: CUSTODY_PATH.into(),
                sha256: CUSTODY_SHA.into(),
            },
            os_admission: Bound {
                path: "/sealed/fixture-admission.json".into(),
                sha256: "b".repeat(64),
            },
            self_sha256: own.clone(),
            output_directory: Path::new(ROOT).join("output"),
            remote_mutations: false,
            r2_mutations: false,
        };
        let key = object_key(&m, SHA).unwrap();
        let manifest = json!({"schema":"jetstreamer-horizon-holding-manifest-v2","host":HOST,
            "prefix":m.prefix,"object_key":key,"length":LENGTH,"sha256":SHA,"name":"epoch-136.jet",
            "uid":1001,"gid":1003,"mode":384,"eligibility_sha256":"52706b06140a65c6495bebce32ecdcb93daa791585a1596133cd09000afa3572",
            "canonical_archive":false,"canonical_publication_authorized":false});
        let ms = hex_lower(&Sha256::digest(serde_json::to_vec(&manifest).unwrap()));
        let c = json!({"schema":"jetstreamer-horizon-holding-custody-v2","host":HOST,"bucket":BUCKET,
            "prefix":m.prefix,"object_key":key,"object_etag":ETAG,"length":LENGTH,"sha256":SHA,
            "mapping":{"path":p.mapping.path,"sha256":MAP_SHA},"manifest":manifest,
            "manifest_key":format!("node_02/manifests/{ms}.json"),"manifest_sha256":ms,
            "remote_sha256_readback":true,"local_source_revalidated":true,"local_retirement_authorized":false,
            "canonical_publication_authorized":false,"runtime_checkpoint_qualified":false,
            "job_resume_authorized":false,"replay_launch_authorized":false});
        (m, p, c, own)
    }
    #[test]
    fn scope_rejects_foreign_custody_identity_and_aliases() {
        let (m, mut p, c, own) = fixture_scope();
        scope(&m, &p, &c, &own).unwrap();
        for (name, value) in [
            ("length", json!(LENGTH - 1)),
            ("sha256", json!("0".repeat(64))),
            ("object_etag", json!("new-etag")),
            ("runtime_checkpoint_qualified", json!(true)),
        ] {
            let mut bad = c.clone();
            bad[name] = value;
            assert!(scope(&m, &p, &bad, &own).is_err());
        }
        p.custody.path = "/unsealed/alias.json".into();
        assert!(scope(&m, &p, &c, &own).is_err());
        p.custody.path = CUSTODY_PATH.into();
        p.remote_mutations = true;
        assert!(scope(&m, &p, &c, &own).is_err());
    }
    fn fixture_admission() -> (AdmissionPlan, Bound, String, Value, StatfsSample, Value) {
        let (_, p, _, own) = fixture_scope();
        let plan = AdmissionPlan {
            schema: "jetstreamer-private-epoch136-held-framing-admission-plan-v1".into(),
            mapping: p.mapping,
            custody: p.custody,
            os_budget: Bound {
                path: BUDGET_PATH.into(),
                sha256: BUDGET_SHA.into(),
            },
            self_sha256: own.clone(),
            receipt: ADMISSION_PATH.into(),
            not_before_unix_seconds: 900,
            not_after_unix_seconds: 1100,
            remote_mutations: false,
            r2_mutations: false,
            replay_launch_authorized: false,
            restore_authorized: false,
        };
        let spec = Bound {
            path: "/sealed/admit-plan.json".into(),
            sha256: "b".repeat(64),
        };
        let budget = json!({"schema":"jetstreamer-v1425-portability-os-experiment-budget-v2","host":HOST,
            "filesystem":"/var/lib","device":OS_DEVICE,"minimum_retained_free_bytes":RETAINED_FLOOR,
            "reservations":{"modern_builder_remaining_bytes":MODERN_RESERVATION,
                "legacy_build_and_artifact_staging_increment_bytes":LEGACY_RESERVATION,
                "fixture_maximum_physical_bytes":FIXTURE_RESERVATION},"required_initial_free_bytes":PROTECTED_OS});
        let sample = StatfsSample {
            device: OS_DEVICE,
            directory_inode: 42,
            bavail: REQUIRED_OS,
            block_size: 1,
            statfs_available_bytes: REQUIRED_OS,
            recorded_unix_seconds: 1000,
        };
        let identities = json!([{"fixture":"admission-plan"},{"fixture":"mapping"},{"fixture":"custody"},{"fixture":"budget"}]);
        (plan, spec, own, budget, sample, identities)
    }
    #[test]
    fn emitter_fixture_is_acyclic_fresh_and_preserves_all_reservations() {
        let (p, spec, own, budget, sample, identities) = fixture_admission();
        validate_budget(&budget).unwrap();
        let receipt = admission_receipt(
            &p,
            &spec,
            &own,
            &"c".repeat(32),
            [&sample, &sample],
            &identities,
            1000,
        )
        .unwrap();
        admission(&receipt, &own, 1000).unwrap();
        assert_eq!(receipt["protected_free_bytes"], 228_833_779_142u64);
        assert_eq!(receipt["required_initial_free_bytes"], 228_842_167_750u64);
        assert_eq!(receipt["statfs_available_bytes"], REQUIRED_OS);
        assert_eq!(receipt["admission_plan"]["sha256"], spec.sha256);
        assert_eq!(receipt["network_access_performed"], false);
        for key in [
            "restore_authorized",
            "replay_launch_authorized",
            "publication_authorized",
            "job_resume_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            assert_eq!(receipt[key], false);
        }
        assert!(admission(&receipt, &own, 2801).is_err());
        assert!(admission(&receipt, &own, 999).is_err());
    }
    #[test]
    fn emitter_rejects_either_low_sample_wrong_device_changed_root_and_stale_plan() {
        let (mut p, spec, own, _, sample, identities) = fixture_admission();
        let iid = "c".repeat(32);
        for bad in [
            StatfsSample {
                statfs_available_bytes: REQUIRED_OS - 1,
                bavail: REQUIRED_OS - 1,
                ..sample.clone()
            },
            StatfsSample {
                device: 64512,
                ..sample.clone()
            },
            StatfsSample {
                block_size: 2,
                ..sample.clone()
            },
            StatfsSample {
                recorded_unix_seconds: 969,
                ..sample.clone()
            },
            StatfsSample {
                directory_inode: 43,
                ..sample.clone()
            },
        ] {
            assert!(
                admission_receipt(&p, &spec, &own, &iid, [&sample, &bad], &identities, 1000)
                    .is_err()
            );
            assert!(
                admission_receipt(&p, &spec, &own, &iid, [&bad, &sample], &identities, 1000)
                    .is_err()
            );
        }
        assert!(
            admission_receipt(
                &p,
                &spec,
                &own,
                &"0".repeat(32),
                [&sample, &sample],
                &identities,
                1000
            )
            .is_err()
        );
        p.not_after_unix_seconds = 999;
        assert!(
            admission_receipt(&p, &spec, &own, &iid, [&sample, &sample], &identities, 1000)
                .is_err()
        );
        p.not_after_unix_seconds = 1100;
        p.receipt = "/var/lib/alias/admission.json".into();
        assert!(
            admission_receipt(&p, &spec, &own, &iid, [&sample, &sample], &identities, 1000)
                .is_err()
        );
    }
    #[test]
    fn emitter_rejects_reservation_release_foreign_budget_and_extra_authority() {
        let (mut p, spec, own, budget, sample, identities) = fixture_admission();
        for field in [
            "modern_builder_remaining_bytes",
            "legacy_build_and_artifact_staging_increment_bytes",
            "fixture_maximum_physical_bytes",
        ] {
            let mut released = budget.clone();
            released["reservations"][field] = json!(0);
            assert!(validate_budget(&released).is_err());
        }
        p.os_budget.sha256 = "0".repeat(64);
        assert!(
            admission_receipt(
                &p,
                &spec,
                &own,
                &"c".repeat(32),
                [&sample, &sample],
                &identities,
                1000
            )
            .is_err()
        );
        p.os_budget.sha256 = BUDGET_SHA.into();
        p.restore_authorized = true;
        assert!(
            admission_receipt(
                &p,
                &spec,
                &own,
                &"c".repeat(32),
                [&sample, &sample],
                &identities,
                1000
            )
            .is_err()
        );
    }
    fn mock_probe(endpoint: String) -> Probe {
        let client = Client::from_conf(
            S3ConfigBuilder::new()
                .behavior_version(BehaviorVersion::latest())
                .region(Region::new("auto"))
                .credentials_provider(SharedCredentialsProvider::new(Credentials::new(
                    "fixture", "fixture", None, None, "test",
                )))
                .retry_config(aws_sdk_s3::config::retry::RetryConfig::disabled())
                .endpoint_url(endpoint)
                .force_path_style(true)
                .build(),
        );
        Probe {
            client,
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never())
                .no_proxy()
                .build()
                .unwrap(),
            trace: Trace::default(),
            blob_key: format!("node_02/objects/{SHA}.blob"),
            manifest_key: "node_02/manifests/fixture.json".into(),
            blob_gets: 0,
            small_gets: 0,
            heads: 0,
        }
    }
    #[tokio::test]
    async fn real_http_preserves_if_match_range_and_records_412_without_retry() {
        let server = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", server.local_addr().unwrap());
        server.set_nonblocking(true).unwrap();
        let worker = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut connection = loop {
                match server.accept() {
                    Ok((stream, _)) => break stream,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "fixture listener deadline");
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(e) => panic!("fixture accept: {e}"),
                }
            };
            connection
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut one = [0];
                connection.read_exact(&mut one).unwrap();
                request.extend(one);
                assert!(request.len() < 16 * 1024);
            }
            let text = String::from_utf8(request).unwrap().to_ascii_lowercase();
            assert!(text.contains("range: bytes=0-65535\r\n"));
            assert!(text.contains(&format!("if-match: \"{ETAG}\"\r\n")));
            connection.write_all(b"HTTP/1.1 412 Precondition Failed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
            drop(connection);
            assert!(server.accept().is_err(), "must not retry412");
        });
        let mut probe = mock_probe(endpoint);
        let key = probe.blob_key.clone();
        assert!(probe.request(&key, false, Some((0, PREFIX))).await.is_err());
        worker.join().unwrap();
        assert_eq!(probe.trace.requests.len(), 1);
        assert_eq!(probe.trace.requests[0]["status"], 412);
        assert_eq!(probe.trace.requests[0]["outcome"], "failure");
        assert_eq!(probe.trace.body_bytes, 0);
    }
    #[tokio::test]
    async fn truncated_http_stream_preserves_partial_body_and_failure() {
        let server = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", server.local_addr().unwrap());
        server.set_nonblocking(true).unwrap();
        let worker = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut connection = loop {
                match server.accept() {
                    Ok((stream, _)) => break stream,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "fixture listener deadline");
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(e) => panic!("fixture accept: {e}"),
                }
            };
            connection
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut one = [0];
                connection.read_exact(&mut one).unwrap();
                request.extend(one);
                assert!(request.len() < 16 * 1024);
            }
            connection
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\npart")
                .unwrap();
            connection.flush().unwrap();
        });
        let mut probe = mock_probe(endpoint);
        assert!(
            probe
                .request("node_02/owner.json", false, None)
                .await
                .is_err()
        );
        worker.join().unwrap();
        assert_eq!(probe.trace.requests.len(), 1);
        assert_eq!(probe.trace.requests[0]["outcome"], "failure");
        // Hyper may return the short bytes with its terminal stream error or
        // expose them first. Both are failures; any exposed bytes are retained.
        assert!(probe.trace.body_bytes <= 4);
        assert!(
            probe.trace.requests[0]["error"]
                .as_str()
                .unwrap()
                .contains("stream")
        );
    }

    #[test]
    fn private_receipt_never_clobbers_or_follows_symlink() {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = temp.path().join("receipt.json");
        write_new_receipt(&path, &json!({"test":true})).unwrap();
        assert!(write_new_receipt(&path, &json!({"different":true})).is_err());
        let alias = temp.path().join("alias.json");
        std::os::unix::fs::symlink(&path, &alias).unwrap();
        assert!(write_new_receipt(&alias, &json!({})).is_err());
        assert!(
            write_new_receipt(
                &temp.path().join("huge.json"),
                &json!({"data":"x".repeat(OUTPUT_CAP)})
            )
            .is_err()
        );
    }
}
