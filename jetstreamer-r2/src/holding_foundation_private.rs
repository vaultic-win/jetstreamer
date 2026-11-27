//! Closed private byte custody only. Canonical archive gates are untouched.
//! Transport is shared with the accepted resumable-readback R2 client.
use super::*;
use jetstreamer_horizon_observe::foundation_holding213_review as host;
use std::os::fd::AsRawFd;
#[path = "holding_foundation_appendvec288.rs"]
mod appendvec288;
#[path = "holding_foundation_appendvec292.rs"]
mod appendvec292;
#[path = "holding_foundation_accounts229.rs"]
mod accounts229;
#[path = "holding_foundation_ext4_228.rs"]
mod ext4_228;
#[path = "holding_foundation_openpgp.rs"]
mod openpgp;
#[path = "holding_foundation_private_checkpoint203.rs"]
mod checkpoint203;
#[path = "holding_foundation_private_closure.rs"]
mod closure;
#[path = "holding_foundation_private_failed234.rs"]
mod failed234;
#[path = "holding_foundation_private_old237.rs"]
mod old237;
#[path = "holding_foundation_private_partial223.rs"]
mod partial223;
#[path = "holding_foundation_private_retire.rs"]
mod retirement;
#[path = "holding_foundation_private_runner.rs"]
mod runner;
#[path = "holding_foundation_private_segment.rs"]
mod segment;

const STATE: &str = "/var/lib/jetstreamer/horizon-foundation-closed-private-holding-v1";
const SUBPREFIX: &str = "foundation_node_01/closed-private-v1/";
const MAX_METADATA: u64 = 1 << 20;
const METADATA_RESERVE: u64 = 64 << 20;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum Artifact {
    Original225,
    ThroughRoot206,
    Singleton207,
    Singleton209,
    #[serde(rename = "old-v2-237")]
    OldV2237,
    #[serde(rename = "checkpoint203")]
    Checkpoint203,
    #[serde(rename = "failed-v5-234")]
    FailedV5234,
    #[serde(rename = "adaptive-223")]
    Adaptive223,
    #[serde(rename = "full-root-223")]
    FullRoot223,
    #[serde(rename = "singleton-223")]
    PartialSingleton223,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Stamp {
    device: u64,
    inode: u64,
    length: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    links: u64,
    mtime_ns: i128,
    ctime_ns: i128,
}
impl Stamp {
    fn of(m: &fs::Metadata) -> Self {
        Self {
            device: m.dev(),
            inode: m.ino(),
            length: m.len(),
            uid: m.uid(),
            gid: m.gid(),
            mode: m.mode() & 0o7777,
            links: m.nlink(),
            mtime_ns: i128::from(m.mtime()) * 1_000_000_000 + i128::from(m.mtime_nsec()),
            ctime_ns: i128::from(m.ctime()) * 1_000_000_000 + i128::from(m.ctime_nsec()),
        }
    }
    fn same_body_identity(&self, other: &Self) -> bool {
        let mut a = self.clone();
        let mut b = other.clone();
        a.ctime_ns = 0;
        b.ctime_ns = 0;
        a == b
    }
}
impl Artifact {
    fn requires_prior_check(self) -> bool {
        matches!(self, Self::OldV2237 | Self::Checkpoint203 | Self::FailedV5234) || partial223::applies(self)
    }
    fn check_label(self) -> &'static str {
        if partial223::applies(self) { return partial223::label(self); }
        match self {
            Self::OldV2237 => "old-v2-237",
            Self::Checkpoint203 => "checkpoint203",
            Self::FailedV5234 => "failed-v5-234",
            _ => unreachable!("prior-check role only for exact registered successors"),
        }
    }
    fn prior_check_field(self) -> &'static str {
        if partial223::applies(self) { return "partial223_prior_check"; }
        match self {
            Self::OldV2237 => "old_v2_237_prior_check",
            Self::Checkpoint203 => "checkpoint203_prior_check",
            Self::FailedV5234 => "failed_v5_234_prior_check",
            _ => unreachable!("prior-check binding only for exact registered successors"),
        }
    }
    fn sha(self) -> &'static str {
        match self {
            Self::Original225 => "77c0f95a020ceb6c45e323f4ce1bb48066fd0b379615bd5c9dbcb67f9082d6f9",
            Self::ThroughRoot206 => {
                "75f050b74b4a9707f9ffa94596eee20da139d3c9f4f1dbef47bdebf8b20b8677"
            }
            Self::Singleton207 => {
                "d969abe600522c964473409059d19fc99ba250c8538e11f4fea456f9333d27ec"
            }
            Self::Singleton209 => {
                "eb9c768b640d5ec2a931bc146e2827a9f9efe801f7c06147fde7966b286dbb36"
            }
            // Not an accepted digest: this variant requires the exact sealed
            // native inspection receipt. No plan can select a digest directly.
            Self::OldV2237 | Self::Adaptive223 | Self::FullRoot223 | Self::PartialSingleton223 => "",
            Self::Checkpoint203 => checkpoint203::SHA,
            Self::FailedV5234 => failed234::SHA,
        }
    }
    fn epoch(self) -> u64 {
        match self {
            Self::Original225 => 225,
            Self::ThroughRoot206 => 206,
            Self::Singleton207 => 207,
            Self::Singleton209 => 209,
            Self::OldV2237 => 237,
            Self::Checkpoint203 => 203,
            Self::FailedV5234 => 234,
            Self::Adaptive223 | Self::FullRoot223 | Self::PartialSingleton223 => 223,
        }
    }
    fn root(self) -> &'static Path {
        if partial223::applies(self) { return &partial223::profile(self).root; }
        Path::new(match self {
            Self::Original225 => {
                "/home/ubuntu/.jetstreamer-private/qualification-225-v1625-natural-root-shrink-budget-2f856bd-v1"
            }
            Self::ThroughRoot206 => {
                "/home/ubuntu/.jetstreamer-private/qualification-206/complete-span-ca2e38b-v1"
            }
            Self::Singleton207 => {
                "/home/ubuntu/.jetstreamer-private/qualification-207-singleton-admitted-v1"
            }
            Self::Singleton209 => {
                "/home/ubuntu/.jetstreamer-private/qualification-209-singleton-capped-v1"
            }
            Self::OldV2237 => old237::ROOT,
            Self::Checkpoint203 => checkpoint203::ROOT,
            Self::FailedV5234 => failed234::ROOT,
            Self::Adaptive223 | Self::FullRoot223 | Self::PartialSingleton223 => unreachable!(),
        })
    }
    fn source(self) -> PathBuf {
        self.root().join(match self {
            Self::ThroughRoot206 => "output/epoch-206-through-89523820.jet",
            Self::Original225 => "output/epoch-225.jet",
            Self::Singleton207 => "output/epoch-207.jet",
            Self::Singleton209 => "output/epoch-209.jet",
            Self::OldV2237 => old237::RELATIVE_SOURCE,
            Self::Checkpoint203 => checkpoint203::RELATIVE_SOURCE,
            Self::FailedV5234 => failed234::RELATIVE_SOURCE,
            Self::Adaptive223 | Self::FullRoot223 | Self::PartialSingleton223 => &partial223::profile(self).relative_source,
        })
    }
    fn expected(self) -> Stamp {
        if partial223::applies(self) { return partial223::profile(self).source_identity.clone(); }
        let (inode, length, mode, mtime, ctime) = match self {
            Self::Original225 => (
                26091623,
                265610094371,
                0o400,
                1793016880237579591,
                1793049675927496349,
            ),
            Self::ThroughRoot206 => (
                93076495,
                134891293990,
                0o600,
                1792369197825741151,
                1792369197825741151,
            ),
            Self::Singleton207 => (
                760381,
                112906309552,
                0o440,
                1793041782222180512,
                1793042233217478599,
            ),
            Self::Singleton209 => (
                2759918,
                111727866952,
                0o440,
                1792957457009602259,
                1792957703275307359,
            ),
            Self::OldV2237 => (
                13547667,
                157334577077,
                0o600,
                1793716861385301224,
                1793716861385301224,
            ),
            Self::Checkpoint203 => (
                1004455,
                103802397352,
                0o600,
                1792746849936499204,
                1792746849936499204,
            ),
            Self::FailedV5234 => (
                15061993,
                53619759409,
                0o600,
                1793951476200348480,
                1793951476200348480,
            ),
            Self::Adaptive223 | Self::FullRoot223 | Self::PartialSingleton223 => unreachable!(),
        };
        Stamp {
            device: 66305,
            inode,
            length,
            uid: 1000,
            gid: 1000,
            mode,
            links: 1,
            mtime_ns: mtime,
            ctime_ns: ctime,
        }
    }
    fn producer(self) -> Option<&'static str> {
        match self {
            Self::Original225 => {
                Some("horizon-qualify-225-natural-root-resource-shrink-budget-2f856bd-v1.service")
            }
            Self::Singleton207 => Some("horizon-qualify-207-singleton-admitted-v1.service"),
            Self::Singleton209 => Some("horizon-singleton-209-capped-4aeca563-v1.service"),
            Self::ThroughRoot206 => Some("horizon-qualify-206-complete-span-ca2e38b-v1.service"),
            Self::OldV2237 => Some(old237::PRODUCER),
            Self::Checkpoint203 => Some(checkpoint203::PRODUCER),
            Self::FailedV5234 => Some(failed234::PRODUCER),
            Self::Adaptive223 | Self::FullRoot223 | Self::PartialSingleton223 => Some(&partial223::profile(self).producer),
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ParkSpec {
    schema: String,
    mapping: Bound,
    artifact: Artifact,
    sha256: String,
    closure: Bound,
    #[serde(default)]
    inspection: Option<Bound>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CustodySpec {
    schema: String,
    mapping: Bound,
    custody: Bound,
    closure: Bound,
    local_private_retirement_authorized: bool,
    #[serde(default)]
    prior_check: Option<Bound>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmitSpec {
    schema: String,
    mapping: Bound,
    custody: Bound,
    resource_basis: Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreSpec {
    schema: String,
    mapping: Bound,
    custody: Bound,
    admission: Bound,
}
fn clock() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn mapping(b: &Bound) -> Result<()> {
    ensure!(
        b.path == Path::new(host::MAPPING) && b.sha256 == host::MAPPING_SHA,
        "foreign host/prefix mapping"
    );
    host::validate_host_mapping()
}
fn owner_bytes() -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(
        &json!({"schema":"jetstreamer-horizon-holding-owner-v2","host":host::HOST,"prefix":host::PREFIX}),
    )?)
}
fn key(sha: &str) -> Result<String> {
    ensure!(digest(sha), "invalid cold-private SHA-256");
    Ok(format!("{SUBPREFIX}objects/{sha}.blob"))
}
fn manifest_key(sha: &str) -> Result<String> {
    ensure!(digest(sha), "invalid manifest SHA-256");
    Ok(format!("{SUBPREFIX}manifests/{sha}.json"))
}
fn receipt(name: &str, value: &Value) -> Result<PathBuf> {
    let path = Path::new(STATE).join("receipts").join(name);
    persist_with_limit(&path, value, 8 << 20)?;
    File::open(&path)?.sync_all()?;
    File::open(path.parent().unwrap())?.sync_all()?;
    Ok(path)
}
fn saved(b: &Bound) -> Result<Value> {
    evidence_with_limit(b, true, 8 << 20)
}
fn source(a: Artifact) -> Result<FileIdentity> {
    let p = a.source();
    ensure!(p.canonicalize()? == p, "aliased private source");
    let m = fs::symlink_metadata(&p)?;
    ensure!(
        m.is_file() && Stamp::of(&m) == a.expected(),
        "private source generation/identity differs"
    );
    canonical_exclusion(a)?;
    regular_identity(&p)
}
fn canonical_exclusion(a: Artifact) -> Result<()> {
    let public = Path::new("/home/ubuntu/horizon").join(format!("epoch-{}.jet", a.epoch()));
    match fs::metadata(public) {
        Ok(m) => ensure!(
            !(m.dev() == a.expected().device && m.ino() == a.expected().inode),
            "canonical archive inode cannot use cold-private retirement"
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    };
    Ok(())
}
fn no_promotion(v: &Value) -> Result<()> {
    for key in [
        "canonical_archive",
        "canonical_publication_authorized",
        "full_plugin_qualified",
        "boundary_qualified",
        "runtime_checkpoint_qualified",
        "job_resume_authorized",
        "replay_launch_authorized",
    ] {
        ensure!(v[key] == false, "cold custody cannot grant {key}");
    }
    Ok(())
}
fn metadata(a: Artifact) -> Result<Value> {
    if partial223::applies(a) { return partial223::metadata(a); }
    if a == Artifact::FailedV5234 {
        return failed234::metadata();
    }
    if a == Artifact::Checkpoint203 {
        return checkpoint203::metadata();
    }
    if a == Artifact::OldV2237 {
        return old237::metadata();
    }
    let mut members = Vec::new();
    for suffix in [".segment.json", ".sha256"] {
        let p = PathBuf::from(format!("{}{suffix}", a.source().display()));
        match fs::symlink_metadata(&p) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
            Ok(m) => {
                ensure!(
                    p.canonicalize()? == p
                        && m.is_file()
                        && m.nlink() == 1
                        && m.mode() & 0o022 == 0
                        && m.len() <= MAX_METADATA,
                    "unsafe private archive metadata"
                );
                let bytes = read_stable_bounded(&p, MAX_METADATA, "cold-private raw metadata")?;
                if suffix == ".segment.json" {
                    segment::validate(&bytes, a, a.sha())?;
                } else {
                    let tokens = std::str::from_utf8(&bytes)?
                        .split_whitespace()
                        .collect::<Vec<_>>();
                    ensure!(
                        tokens.len() == 2
                            && digest(tokens[0])
                            && tokens[1].trim_start_matches('*')
                                == a.source().file_name().unwrap().to_str().unwrap(),
                        "private sidecar must contain only its digest and exact private basename"
                    );
                }
                members.push(json!({"name":p.file_name().unwrap().to_str().unwrap(),"sha256":hex_lower(&Sha256::digest(&bytes)),"length":bytes.len(),
                    "uid":m.uid(),"gid":m.gid(),"mode":m.mode()&0o7777,"raw_base64":BASE64_STANDARD.encode(bytes)}));
            }
        }
    }
    let required = if matches!(a, Artifact::Original225 | Artifact::ThroughRoot206) {
        ".segment.json"
    } else {
        ".sha256"
    };
    ensure!(
        members
            .iter()
            .any(|m| m["name"].as_str().is_some_and(|s| s.ends_with(required))),
        "required original private metadata is missing"
    );
    Ok(json!(members))
}
fn validate_manifest(v: &Value) -> Result<(Artifact, String)> {
    let a: Artifact = serde_json::from_value(v["artifact"].clone())?;
    let sha = v["sha256"]
        .as_str()
        .context("cold-private manifest digest")?;
    ensure!(
        v["schema"] == "jetstreamer-foundation-closed-private-manifest-v1"
            && v["host"] == host::HOST
            && v["prefix"] == SUBPREFIX
            && v["source"].as_str() == a.source().to_str()
            && v["source_identity"] == serde_json::to_value(a.expected())?
            && v["object_key"] == key(sha)?
            && v["length"] == a.expected().length
            && (a == Artifact::OldV2237 || partial223::applies(a) || sha == a.sha())
            && v["restore_before_consumer_reuse"] == true,
        "foreign cold-private manifest"
    );
    no_promotion(v)?;
    if partial223::applies(a) {
        partial223::manifest(v, a, sha)?;
        return Ok((a, sha.to_owned()));
    }
    if a == Artifact::FailedV5234 {
        failed234::manifest(v)?;
        return Ok((a, sha.to_owned()));
    }
    if a == Artifact::Checkpoint203 {
        checkpoint203::manifest(v)?;
        return Ok((a, sha.to_owned()));
    }
    if a == Artifact::OldV2237 {
        old237::manifest_inspection(v, sha)?;
        old237::validate_metadata(&v["raw_metadata"])?;
        return Ok((a, sha.to_owned()));
    }
    let mut names = BTreeSet::new();
    for member in v["raw_metadata"]
        .as_array()
        .context("cold-private raw metadata")?
    {
        let name = member["name"].as_str().context("metadata name")?;
        let base = a
            .source()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        ensure!(
            names.insert(name)
                && [format!("{base}.segment.json"), format!("{base}.sha256")]
                    .contains(&name.to_owned()),
            "foreign raw metadata member"
        );
        let bytes =
            BASE64_STANDARD.decode(member["raw_base64"].as_str().context("metadata bytes")?)?;
        ensure!(
            bytes.len() as u64 <= MAX_METADATA
                && member["length"] == bytes.len()
                && member["sha256"] == hex_lower(&Sha256::digest(&bytes)),
            "raw metadata identity differs"
        );
        if name.ends_with(".sha256") {
            let tokens = std::str::from_utf8(&bytes)?
                .split_whitespace()
                .collect::<Vec<_>>();
            ensure!(
                tokens.len() == 2 && tokens[0] == sha && tokens[1].trim_start_matches('*') == base,
                "private checksum metadata does not bind these exact bytes"
            );
        } else {
            segment::validate(&bytes, a, sha)?;
        }
    }
    let required = if matches!(a, Artifact::Original225 | Artifact::ThroughRoot206) {
        ".segment.json"
    } else {
        ".sha256"
    };
    ensure!(
        names.iter().any(|n| n.ends_with(required)),
        "required restoration metadata omitted"
    );
    Ok((a, sha.to_owned()))
}
fn custody(v: &Value) -> Result<(Artifact, String)> {
    let (a, sha) = validate_manifest(&v["manifest"])?;
    let manifest_sha = hex_lower(&Sha256::digest(serde_json::to_vec(&v["manifest"])?));
    ensure!(
        v["schema"] == "jetstreamer-foundation-closed-private-custody-v1"
            && v["host"] == host::HOST
            && v["bucket"] == BUCKET
            && v["prefix"] == SUBPREFIX
            && v["artifact"] == serde_json::to_value(a)?
            && v["sha256"] == sha
            && v["object_key"] == key(&sha)?
            && v["manifest_sha256"] == manifest_sha
            && v["manifest_key"] == manifest_key(&manifest_sha)?
            && v["remote_sha256_readback"] == true
            && v["local_source_revalidated"] == true
            && v["owner_checked"] == true
            && v["local_retirement_authorized"] == false
            && v["mapping"] == json!({"path":host::MAPPING,"sha256":host::MAPPING_SHA})
            && v["object_etag"].as_str().is_some_and(|x| !x.is_empty()),
        "foreign/incomplete private byte custody"
    );
    no_promotion(v)?;
    Ok((a, sha))
}
async fn remote_custody(client: &Client, c: &Value) -> Result<(Artifact, String)> {
    let (a, sha) = custody(c)?;
    let owner = get_mutable_object(client, BUCKET, &format!("{}owner.json", host::PREFIX))
        .await?
        .context("Foundation owner missing")?;
    ensure!(owner.bytes == owner_bytes()?, "different Foundation owner");
    let remote = head_archive(client, BUCKET, &key(&sha)?)
        .await?
        .context("cold-private blob missing")?;
    remote_matches(
        &remote,
        &key(&sha)?,
        a.expected().length,
        &sha,
        c["object_etag"].as_str(),
    )?;
    let manifest = get_mutable_object(client, BUCKET, c["manifest_key"].as_str().unwrap())
        .await?
        .context("cold-private manifest missing")?;
    ensure!(
        hex_lower(&Sha256::digest(&manifest.bytes)) == c["manifest_sha256"]
            && serde_json::from_slice::<Value>(&manifest.bytes)? == c["manifest"],
        "remote manifest changed"
    );
    Ok((a, sha))
}
struct PreparedPark {
    before: Value,
    id: FileIdentity,
    proof: LocalProof,
    manifest: Value,
    bytes: Vec<u8>,
    key: String,
    manifest_sha: String,
    manifest_key: String,
}
struct NativePark<'a> {
    client: &'a Client,
    p: ParkSpec,
    spec: &'a Bound,
    entry: u64,
    prepared: Option<PreparedPark>,
    remote: Option<RemoteArchive>,
    after: Option<Value>,
    output: Option<PathBuf>,
}
impl runner::ParkOperations for NativePark<'_> {
    async fn step(&mut self, step: runner::ParkStep) -> Result<()> {
        use runner::ParkStep::*;
        let p = &self.p;
        match step {
            Prepare => {
                ensure!(
                    p.schema == "jetstreamer-foundation-closed-private-park-plan-v1",
                    "foreign private park plan"
                );
                old237::park_digest(p)?;
                mapping(&p.mapping)?;
                let before = closure::inspect(p.artifact, &p.closure, self.entry, true)?;
                let id = source(p.artifact)?;
                eprintln!(
                    "{}",
                    json!({"event":"foundation-private-source-hash-start","artifact":p.artifact,"source":p.artifact.source(),"bytes":id.length})
                );
                let proof = hash_and_etag(&p.artifact.source(), id, DEFAULT_PART_SIZE)?;
                ensure!(
                    proof.sha256_hex == p.sha256,
                    "private body digest differs before remote write"
                );
                let raw = metadata(p.artifact)?;
                let key = key(&p.sha256)?;
                let mut manifest = json!({"schema":"jetstreamer-foundation-closed-private-manifest-v1","host":host::HOST,"prefix":SUBPREFIX,
                    "artifact":p.artifact,"source":p.artifact.source(),"source_identity":p.artifact.expected(),"sha256":p.sha256,"length":id.length,
                    "object_key":key,"raw_metadata":raw,"origin_and_closed_consumers":p.closure,"restore_before_consumer_reuse":true,
                    "canonical_archive":false,"canonical_publication_authorized":false,"full_plugin_qualified":false,"boundary_qualified":false,
                    "runtime_checkpoint_qualified":false,"job_resume_authorized":false,"replay_launch_authorized":false});
                if partial223::applies(p.artifact) {
                    manifest["partial223_inspection"] = serde_json::to_value(&p.inspection)?;
                    manifest["partial223_lineage"] = partial223::lineage_bindings(p.artifact);
                }
                if p.artifact == Artifact::OldV2237 {
                    manifest["old_v2_237_inspection"] = serde_json::to_value(&p.inspection)?;
                    manifest["old_v2_237_preservation"] = old237::lineage_bindings();
                }
                if p.artifact == Artifact::Checkpoint203 {
                    manifest["checkpoint203_lineage"] = checkpoint203::lineage_bindings();
                }
                if p.artifact == Artifact::FailedV5234 {
                    manifest["failed_v5_234_lineage"] = failed234::lineage_bindings();
                }
                validate_manifest(&manifest)?;
                let bytes = serde_json::to_vec(&manifest)?;
                ensure!(
                    bytes.len() as u64 <= MAX_STATUS_BYTES,
                    "private raw metadata exceeds shared manifest transport limit"
                );
                let manifest_sha = hex_lower(&Sha256::digest(&bytes));
                let manifest_key = manifest_key(&manifest_sha)?;
                self.prepared = Some(PreparedPark {
                    before,
                    id,
                    proof,
                    manifest,
                    bytes,
                    key,
                    manifest_sha,
                    manifest_key,
                });
            }
            VerifyBlob => {
                let c = self.prepared.as_ref().context("park is not prepared")?;
                claim_owner(self.client, host::PREFIX, &owner_bytes()?).await?;
                let transport = Park {
                    schema: "transport-only".into(),
                    mapping: p.mapping.clone(),
                    eligibility: self.spec.clone(),
                    source: p.artifact.source(),
                    length: c.id.length,
                    sha256: p.sha256.clone(),
                };
                self.remote =
                    Some(verified_blob(self.client, &c.key, &transport, c.id, &c.proof).await?);
            }
            RevalidateSource => {
                let c = self.prepared.as_ref().context("park is not prepared")?;
                eprintln!(
                    "{}",
                    json!({"event":"foundation-private-source-revalidation-start","artifact":p.artifact,"bytes":c.id.length})
                );
                ensure!(
                    source(p.artifact)? == c.id
                        && hash_and_etag(&p.artifact.source(), c.id, DEFAULT_PART_SIZE)?.sha256_hex
                            == p.sha256
                        && metadata(p.artifact)? == c.manifest["raw_metadata"],
                    "private source/metadata changed after authenticated readback"
                );
                self.after = Some(closure::inspect(p.artifact, &p.closure, self.entry, true)?);
            }
            PublishManifest => {
                let c = self.prepared.as_ref().context("park is not prepared")?;
                let remote = self
                    .remote
                    .as_ref()
                    .context("remote readback did not complete")?;
                small_create(self.client, &c.manifest_key, &c.bytes).await?;
                let final_remote = head_archive(self.client, BUCKET, &c.key)
                    .await?
                    .context("cold-private object disappeared before custody")?;
                remote_matches(
                    &final_remote,
                    &c.key,
                    c.id.length,
                    &p.sha256,
                    Some(&remote.etag),
                )?;
                native_checksum(&final_remote, &c.proof, c.id.length)?;
            }
            PersistCustody => {
                let c = self.prepared.as_ref().context("park is not prepared")?;
                let remote = self
                    .remote
                    .as_ref()
                    .context("remote readback did not complete")?;
                let after = self.after.as_ref().context("source was not revalidated")?;
                let result = json!({"schema":"jetstreamer-foundation-closed-private-custody-v1","host":host::HOST,"bucket":BUCKET,"prefix":SUBPREFIX,
                    "mapping":p.mapping,"artifact":p.artifact,"sha256":p.sha256,"object_key":c.key,"object_etag":remote.etag,
                    "manifest_key":c.manifest_key,"manifest_sha256":c.manifest_sha,"manifest":c.manifest,"park_spec":self.spec,
                    "remote_sha256_readback":true,"local_source_revalidated":true,"owner_checked":true,"local_retirement_authorized":false,
                    "reference_census_before":c.before,"reference_census_after":after,"canonical_archive":false,"canonical_publication_authorized":false,
                    "full_plugin_qualified":false,"boundary_qualified":false,"runtime_checkpoint_qualified":false,"job_resume_authorized":false,"replay_launch_authorized":false});
                custody(&result)?;
                self.output = Some(receipt(
                    &format!("custody-{}.json", self.spec.sha256),
                    &result,
                )?);
            }
        }
        Ok(())
    }
}
async fn park(client: &Client, p: ParkSpec, spec: &Bound) -> Result<()> {
    let mut native = NativePark {
        client,
        p,
        spec,
        entry: clock()?,
        prepared: None,
        remote: None,
        after: None,
        output: None,
    };
    runner::park(&mut native).await?;
    println!(
        "{}",
        native
            .output
            .context("custody runner produced no receipt")?
            .display()
    );
    Ok(())
}

fn admit(p: AdmitSpec, spec: &Bound) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-foundation-closed-private-restore-admission-plan-v1",
        "foreign private restore admission"
    );
    mapping(&p.mapping)?;
    let c = saved(&p.custody)?;
    let (a, sha) = custody(&c)?;
    let additional = restore_remaining(a.expected().length, &sha)?
        .checked_add(METADATA_RESERVE)
        .context("restore reserve overflow")?;
    let capacity = horizon_singleton211_launch::foundation_holding_capacity::check(&p.resource_basis, additional)?;
    let value = json!({"schema":"jetstreamer-foundation-closed-private-restore-admission-v1","host":host::HOST,"custody":p.custody,
        "artifact":a,"spec":spec,"resource_basis":p.resource_basis,"capacity":capacity,"recorded_unix_seconds":clock()?,
        "restore_only":true,"admissions_must_be_serialized_until_restore_complete":true,"replay_launch_authorized":false,"local_retirement_authorized":false});
    println!(
        "{}",
        receipt(&format!("restore-admission-{}.json", spec.sha256), &value)?.display()
    );
    Ok(())
}
fn restore_remaining(length: u64, sha: &str) -> Result<u64> {
    let directory = Path::new(STATE).join("restores");
    for name in [format!("{sha}.blob"), format!(".{sha}.partial")] {
        let path = directory.join(name);
        match fs::symlink_metadata(&path) {
            Ok(m) => {
                ensure!(
                    path.canonicalize()? == path
                        && m.is_file()
                        && m.uid() == 0
                        && m.nlink() == 1
                        && m.len() <= length
                        && matches!(m.mode() & 0o777, 0o400 | 0o600),
                    "unsafe existing private restore allocation"
                );
                let physical = m
                    .blocks()
                    .checked_mul(512)
                    .context("restore block overflow")?;
                return remaining_allocation(length, m.len(), physical);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(length)
}
fn remaining_allocation(length: u64, logical: u64, physical: u64) -> Result<u64> {
    ensure!(
        logical <= length,
        "foreign oversized private restore partial"
    );
    Ok(length - logical.min(physical))
}
fn admission_floor(v: &Value, c: &Bound, a: Artifact, entry: u64) -> Result<u64> {
    let at = v["recorded_unix_seconds"]
        .as_u64()
        .context("restore admission clock")?;
    ensure!(
        v["schema"] == "jetstreamer-foundation-closed-private-restore-admission-v1"
            && v["host"] == host::HOST
            && v["custody"] == serde_json::to_value(c)?
            && v["artifact"] == serde_json::to_value(a)?
            && v["restore_only"] == true
            && v["admissions_must_be_serialized_until_restore_complete"] == true
            && at <= entry
            && entry - at <= 900,
        "stale/foreign private restore admission"
    );
    v["capacity"]["minimum_free_bytes"]
        .as_u64()
        .context("restore floor")
}
fn restore_metadata_at(directory: &Path, sha: &str, manifest: &Value) -> Result<()> {
    let (_, bound_sha) = validate_manifest(manifest)?;
    ensure!(
        sha == bound_sha,
        "restoration metadata belongs to different archive bytes"
    );
    for raw in manifest["raw_metadata"]
        .as_array()
        .context("restore metadata")?
    {
        let bytes =
            BASE64_STANDARD.decode(raw["raw_base64"].as_str().context("restore raw metadata")?)?;
        let name = raw["name"].as_str().context("restore metadata name")?;
        let path = directory.join(format!("{sha}-{name}"));
        if path.try_exists()? {
            ensure!(
                read_stable_bounded(&path, MAX_METADATA, "restored cold-private metadata")?
                    == bytes,
                "restored metadata conflict"
            );
        } else {
            let mut tmp = tempfile::Builder::new()
                .prefix(".cold-meta.")
                .tempfile_in(directory)?;
            tmp.as_file_mut().write_all(&bytes)?;
            tmp.as_file_mut()
                .set_permissions(fs::Permissions::from_mode(0o400))?;
            persist_noclobber(tmp, &path)?;
        }
        File::open(&path)?.sync_all()?;
        File::open(directory)?.sync_all()?;
    }
    Ok(())
}
struct PreparedRestore {
    lease: Option<horizon_singleton211_launch::foundation_holding_capacity::RestoreLease>,
    custody: Value,
    artifact: Artifact,
    sha: String,
    admission: Value,
    floor: u64,
    key: String,
    directory: PathBuf,
}
impl PreparedRestore {
    fn checkpoint(&self, force: bool) -> Result<()> {
        let remaining = || {
            restore_remaining(self.artifact.expected().length, &self.sha)?
                .checked_add(METADATA_RESERVE)
                .context("restore reserve overflow")
        };
        if let Some(lease) = &self.lease {
            lease.renew(force, remaining)?;
        } else if force {
            let capacity = horizon_singleton211_launch::foundation_holding_capacity::check(
                &self.admission["resource_basis"],
                remaining()?,
            )?;
            ensure!(
                capacity["minimum_free_bytes"]
                    .as_u64()
                    .is_some_and(|n| n <= self.floor - METADATA_RESERVE),
                "protected growth/floor increased"
            );
        }
        Ok(())
    }
}
struct NativeRestore<'a> {
    client: &'a Client,
    p: RestoreSpec,
    spec: &'a Bound,
    prepared: Option<PreparedRestore>,
    destination: Option<PathBuf>,
    output: Option<PathBuf>,
}
impl runner::RestoreOperations for NativeRestore<'_> {
    async fn step(&mut self, step: runner::RestoreStep) -> Result<()> {
        use runner::RestoreStep::*;
        match step {
            Prepare => {
                ensure!(
                    self.p.schema == "jetstreamer-foundation-closed-private-restore-plan-v1",
                    "foreign private restore plan"
                );
                mapping(&self.p.mapping)?;
                let custody = saved(&self.p.custody)?;
                let (artifact, sha) = remote_custody(self.client, &custody).await?;
                let admission = saved(&self.p.admission)?;
                let entry = clock()?;
                let original_floor = admission_floor(&admission, &self.p.custody, artifact, entry)?;
                let remaining = restore_remaining(artifact.expected().length, &sha)?
                    .checked_add(METADATA_RESERVE)
                    .context("restore reserve overflow")?;
                let lease =
                    horizon_singleton211_launch::foundation_holding_capacity::RestoreLease::start(
                        &admission["resource_basis"],
                        &serde_json::to_value(&self.p.custody)?,
                        remaining,
                        original_floor,
                    )?;
                let floor = original_floor
                    .checked_add(METADATA_RESERVE)
                    .context("metadata floor overflow")?;
                let key = key(&sha)?;
                self.prepared = Some(PreparedRestore {
                    lease,
                    custody,
                    artifact,
                    sha,
                    admission,
                    floor,
                    key,
                    directory: Path::new(STATE).join("restores"),
                });
            }
            Download => {
                let c = self.prepared.as_ref().context("restore is not prepared")?;
                let destination = restore_blob_guarded(
                    self.client,
                    BlobRestore {
                        key: &c.key,
                        etag: c.custody["object_etag"].as_str().context("restore ETag")?,
                        sha: &c.sha,
                        length: c.artifact.expected().length,
                        directory: &c.directory,
                        minimum: c.floor,
                    },
                    || c.checkpoint(false),
                    || c.checkpoint(true),
                )
                .await?;
                self.destination = Some(destination);
            }
            Metadata => {
                let c = self.prepared.as_ref().context("restore is not prepared")?;
                restore_metadata_at(&c.directory, &c.sha, &c.custody["manifest"])?;
            }
            VerifyBody => {
                let c = self.prepared.as_ref().context("restore is not prepared")?;
                let path = self
                    .destination
                    .as_ref()
                    .context("restore body is absent")?;
                let proof = hash_and_etag_checked(
                    path,
                    regular_identity(path)?,
                    DEFAULT_PART_SIZE,
                    |_| c.checkpoint(false),
                )?;
                ensure!(
                    proof.sha256_hex == c.sha,
                    "restored private blob digest differs"
                );
            }
            VerifyRemote => {
                let c = self.prepared.as_ref().context("restore is not prepared")?;
                remote_custody(self.client, &c.custody).await?;
            }
            VerifyCapacity => {
                let c = self.prepared.as_ref().context("restore is not prepared")?;
                c.checkpoint(true)?;
            }
            PersistReceipt => {
                let c = self.prepared.as_ref().context("restore is not prepared")?;
                let destination = self
                    .destination
                    .as_ref()
                    .context("restore body is absent")?;
                let mut value = json!({"schema":"jetstreamer-foundation-closed-private-restoration-v1","host":host::HOST,"artifact":c.artifact,"custody":self.p.custody,
                    "spec":self.spec,"destination":destination,"sha256":c.sha,"length":c.artifact.expected().length,"original_metadata":c.custody["manifest"],
                    "staging_only":true,"complete_byte_restoration_verified":true,"canonical_archive":false,"canonical_publication_authorized":false,
                    "full_plugin_qualified":false,"boundary_qualified":false,"runtime_checkpoint_qualified":false,"job_resume_authorized":false,"replay_launch_authorized":false});
                if let Some(lease) = &c.lease {
                    value["capacity_renewal"] = lease.evidence();
                }
                self.output = Some(receipt(
                    &format!("restore-{}.json", self.spec.sha256),
                    &value,
                )?);
            }
        }
        Ok(())
    }
}
async fn restore(client: &Client, p: RestoreSpec, spec: &Bound) -> Result<()> {
    let mut native = NativeRestore {
        client,
        p,
        spec,
        prepared: None,
        destination: None,
        output: None,
    };
    runner::restore(&mut native).await?;
    println!(
        "{}",
        native
            .output
            .context("restore runner produced no receipt")?
            .display()
    );
    Ok(())
}

pub(super) fn command(s: &str) -> bool {
    matches!(s, accounts229::ACTION | accounts229::RECHECK) || ext4_228::command(s) || appendvec288::command(s) || appendvec292::command(s) || matches!(
        s,
        "holding-foundation-private-inspect"
            | "holding-foundation-private-inspect-old-v2-237"
            | "holding-foundation-private-inspect-partial223"
            | "holding-foundation-private-park"
            | "holding-foundation-private-admit-restore"
            | "holding-foundation-private-restore"
            | "holding-foundation-private-check-retire"
            | "holding-foundation-private-retire"
    )
}

pub(super) async fn run(action: &str, v: Value, spec: &Bound) -> Result<()> {
    ensure!(command(action), "unknown private holding action");
    host::validate_host_mapping()?;
    let supplied_mapping: Bound = serde_json::from_value(v["mapping"].clone())?;
    mapping(&supplied_mapping)?;
    if action == appendvec292::CHECK_TREE {
        return appendvec292::check_tree(v, spec);
    }
    for p in [
        PathBuf::from(STATE),
        Path::new(STATE).join("receipts"),
        Path::new(STATE).join("restores"),
        Path::new(STATE).join("quarantine"),
    ] {
        private(&p)?;
    }
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(Path::new(STATE).join("transition.lock"))?;
    ensure!(
        lock.metadata()?.is_file()
            && lock.metadata()?.uid() == 0
            && lock.metadata()?.nlink() == 1
            && lock.metadata()?.mode() & 0o777 == 0o600
            && unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "unsafe/owned private holding transition lock"
    );
    if appendvec292::command(action) {
        return appendvec292::run(action, v, spec).await;
    }
    if action == accounts229::ACTION {
        return accounts229::run(v, spec).await;
    }
    if action == accounts229::RECHECK {
        return accounts229::recheck(v, spec).await;
    }
    if appendvec288::command(action) {
        return appendvec288::run(action, v, spec).await;
    }
    if ext4_228::command(action) {
        return ext4_228::run(action, v, spec).await;
    }
    if action == "holding-foundation-private-inspect-partial223" {
        return partial223::inspect(v, spec);
    }
    if action == "holding-foundation-private-inspect-old-v2-237" {
        return old237::inspect(v, spec);
    }
    if action == "holding-foundation-private-inspect" {
        let p: ParkSpec = serde_json::from_value(v)?;
        mapping(&p.mapping)?;
        ensure!(
            p.schema == "jetstreamer-foundation-closed-private-park-plan-v1"
                && p.artifact != Artifact::OldV2237 && !partial223::applies(p.artifact),
            "foreign inspect plan"
        );
        old237::park_digest(&p)?;
        source(p.artifact)?;
        println!(
            "{}",
            closure::inspect(p.artifact, &p.closure, clock()?, true)?
        );
        return Ok(());
    }
    if action == "holding-foundation-private-admit-restore" {
        return admit(serde_json::from_value(v)?, spec);
    }
    let r2 = r2_config_from_env()?;
    ensure!(r2.bucket == BUCKET, "foreign holding bucket");
    let client = s3_client(&r2);
    match action {
        "holding-foundation-private-park" => park(&client, serde_json::from_value(v)?, spec).await,
        "holding-foundation-private-restore" => {
            restore(&client, serde_json::from_value(v)?, spec).await
        }
        _ => {
            retirement::run(
                &client,
                serde_json::from_value(v)?,
                spec,
                action.ends_with("check-retire"),
            )
            .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn manifest(a: Artifact) -> Value {
        let sha = a.sha().to_owned();
        let base = a
            .source()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let (name, raw) = if matches!(a, Artifact::Original225 | Artifact::ThroughRoot206) {
            (format!("{base}.segment.json"), segment::fixture(a).to_vec())
        } else {
            (
                format!("{base}.sha256"),
                format!("{sha}  {base}\n").into_bytes(),
            )
        };
        json!({"schema":"jetstreamer-foundation-closed-private-manifest-v1","host":host::HOST,"prefix":SUBPREFIX,
            "artifact":a,"source":a.source(),"source_identity":a.expected(),"sha256":sha,"length":a.expected().length,"object_key":key(&sha).unwrap(),
            "raw_metadata":[{"name":name,"length":raw.len(),"sha256":hex_lower(&Sha256::digest(&raw)),"raw_base64":BASE64_STANDARD.encode(raw)}],
            "restore_before_consumer_reuse":true,"canonical_archive":false,"canonical_publication_authorized":false,"full_plugin_qualified":false,
            "boundary_qualified":false,"runtime_checkpoint_qualified":false,"job_resume_authorized":false,"replay_launch_authorized":false})
    }
    #[test]
    fn private_profiles_are_four_exact_generations_and_never_canonical_paths() {
        for a in [
            Artifact::Original225,
            Artifact::ThroughRoot206,
            Artifact::Singleton207,
            Artifact::Singleton209,
        ] {
            assert!(a.source().starts_with("/home/ubuntu/.jetstreamer-private"));
            assert!(!a.source().starts_with("/home/ubuntu/horizon"));
            assert_eq!(a.expected().links, 1);
            validate_manifest(&manifest(a)).unwrap();
        }
        assert!(serde_json::from_value::<Artifact>(json!("prefix213")).is_err());
        assert!(serde_json::from_value::<Artifact>(json!("canonical207")).is_err());
    }
    #[test]
    fn namespaces_cannot_borrow_prefix213_or_escape_the_user_prefix() {
        assert_eq!(
            key(&"a".repeat(64)).unwrap(),
            format!("{SUBPREFIX}objects/{}.blob", "a".repeat(64))
        );
        assert!(key("../other").is_err());
        let mut v = manifest(Artifact::ThroughRoot206);
        v["object_key"] = json!(format!(
            "foundation_node_01/objects/{}.blob",
            "a".repeat(64)
        ));
        assert!(validate_manifest(&v).is_err());
        let mut v = manifest(Artifact::Singleton207);
        v["source"] = json!("/home/ubuntu/horizon/epoch-207.jet");
        assert!(validate_manifest(&v).is_err());
    }
    #[test]
    fn cold_bytes_never_grant_publication_verification_or_resume_authority() {
        for field in [
            "canonical_archive",
            "canonical_publication_authorized",
            "full_plugin_qualified",
            "boundary_qualified",
            "runtime_checkpoint_qualified",
            "job_resume_authorized",
            "replay_launch_authorized",
        ] {
            let mut v = manifest(Artifact::Original225);
            v[field] = json!(true);
            assert!(validate_manifest(&v).is_err());
        }
    }
    #[test]
    fn raw_metadata_must_remain_complete_exact_and_bound_to_private_bytes() {
        let mut v = manifest(Artifact::Original225);
        v["raw_metadata"] = json!([]);
        assert!(validate_manifest(&v).is_err());
        let mut v = manifest(Artifact::Singleton209);
        v["raw_metadata"][0]["name"] = json!("credentials.json");
        assert!(validate_manifest(&v).is_err());
        let mut v = manifest(Artifact::Singleton207);
        v["raw_metadata"][0]["raw_base64"] = json!(BASE64_STANDARD.encode(b"different bytes"));
        assert!(validate_manifest(&v).is_err());
        let mut v = manifest(Artifact::Singleton207);
        v["source_identity"]["inode"] = json!(123);
        assert!(validate_manifest(&v).is_err());
    }
    #[test]
    fn restore_credit_uses_only_existing_physical_allocation_and_never_logical_size_alone() {
        assert_eq!(remaining_allocation(1000, 900, 100).unwrap(), 900);
        assert_eq!(remaining_allocation(1000, 900, 950).unwrap(), 100);
        assert_eq!(remaining_allocation(1000, 1000, 1000).unwrap(), 0);
        assert!(remaining_allocation(1000, 1001, 1001).is_err());
    }
    #[test]
    fn typed_segment_validation_preserves_original_raw_whitespace() {
        let a = Artifact::ThroughRoot206;
        let mut v = manifest(a);
        let mut raw = b" \n\t".to_vec();
        raw.extend_from_slice(segment::fixture(a));
        raw.extend_from_slice(b"\n \t");
        v["raw_metadata"][0]["length"] = json!(raw.len());
        v["raw_metadata"][0]["sha256"] = json!(hex_lower(&Sha256::digest(&raw)));
        v["raw_metadata"][0]["raw_base64"] = json!(BASE64_STANDARD.encode(&raw));
        validate_manifest(&v).unwrap();
        let encoded = serde_json::to_vec(&v).unwrap();
        let read: Value = serde_json::from_slice(&encoded).unwrap();
        validate_manifest(&read).unwrap();
        assert_eq!(
            BASE64_STANDARD
                .decode(read["raw_metadata"][0]["raw_base64"].as_str().unwrap())
                .unwrap(),
            raw
        );
    }
    #[test]
    fn park_has_no_arbitrary_path_or_prefix_overrides() {
        let b = json!({"path":"/bound/plan.json","sha256":"b".repeat(64)});
        let p = json!({"schema":"jetstreamer-foundation-closed-private-park-plan-v1","mapping":b,"artifact":"through-root206","sha256":"a".repeat(64),"closure":b});
        assert!(serde_json::from_value::<ParkSpec>(p.clone()).is_ok());
        for field in ["source", "prefix", "delete_local", "overwrite", "epoch"] {
            let mut bad = p.clone();
            bad[field] = json!("arbitrary");
            assert!(serde_json::from_value::<ParkSpec>(bad).is_err());
        }
    }
    struct ParkHarness {
        root: tempfile::TempDir,
        fault: Option<runner::ParkStep>,
        uploads: usize,
        readbacks: usize,
        revalidations: usize,
        source_changed: bool,
    }
    impl ParkHarness {
        fn new() -> Result<Self> {
            let root = tempfile::tempdir()?;
            fs::write(root.path().join("source"), b"closed fixture bytes")?;
            Ok(Self {
                root,
                fault: None,
                uploads: 0,
                readbacks: 0,
                revalidations: 0,
                source_changed: false,
            })
        }
        fn path(&self, n: &str) -> PathBuf {
            self.root.path().join(n)
        }
    }
    impl runner::ParkOperations for ParkHarness {
        async fn step(&mut self, s: runner::ParkStep) -> Result<()> {
            use runner::ParkStep::*;
            match s {
                Prepare => {
                    validate_manifest(&manifest(Artifact::ThroughRoot206))?;
                    ensure!(self.path("source").is_file(), "source disappeared");
                }
                VerifyBlob => {
                    if !self.path("remote.blob").exists() {
                        let mut tmp = tempfile::Builder::new().tempfile_in(self.root.path())?;
                        tmp.as_file_mut().write_all(b"closed fixture bytes")?;
                        persist_noclobber(tmp, &self.path("remote.blob"))?;
                        self.uploads += 1;
                    }
                    ensure!(
                        fs::read(self.path("remote.blob"))? == b"closed fixture bytes",
                        "conflicting remote bytes"
                    );
                    self.readbacks += 1;
                }
                RevalidateSource => {
                    self.revalidations += 1;
                    ensure!(
                        !self.source_changed
                            && fs::read(self.path("source"))? == b"closed fixture bytes",
                        "source changed after readback"
                    );
                }
                PublishManifest => {
                    persist(
                        &self.path("remote-manifest.json"),
                        &manifest(Artifact::ThroughRoot206),
                    )?;
                }
                PersistCustody => {
                    ensure!(
                        self.path("remote-manifest.json").exists()
                            && self.readbacks > 0
                            && self.revalidations > 0,
                        "custody prerequisites missing"
                    );
                    persist(
                        &self.path("custody.json"),
                        &json!({"authenticated_remote_readback":true,"source_revalidated":true,"local_retirement_authorized":false}),
                    )?;
                }
            }
            Ok(())
        }
        fn checkpoint(&mut self, s: runner::ParkStep) -> Result<()> {
            if self.fault == Some(s) {
                self.fault = None;
                bail!("injected park interruption");
            }
            Ok(())
        }
    }
    #[tokio::test]
    async fn production_park_runner_reuses_remote_completion_before_custody() -> Result<()> {
        for point in [
            runner::ParkStep::VerifyBlob,
            runner::ParkStep::PublishManifest,
            runner::ParkStep::PersistCustody,
        ] {
            let mut h = ParkHarness::new()?;
            h.fault = Some(point);
            assert!(runner::park(&mut h).await.is_err());
            assert!(h.path("source").exists());
            if point != runner::ParkStep::PersistCustody {
                assert!(!h.path("custody.json").exists());
            }
            runner::park(&mut h).await?;
            assert_eq!(h.uploads, 1);
            assert_eq!(h.readbacks, 2);
            assert!(h.path("custody.json").exists() && h.path("source").exists());
        }
        Ok(())
    }
    #[tokio::test]
    async fn production_park_runner_denies_custody_when_source_or_remote_conflicts() -> Result<()> {
        let mut h = ParkHarness::new()?;
        h.fault = Some(runner::ParkStep::VerifyBlob);
        assert!(runner::park(&mut h).await.is_err());
        h.source_changed = true;
        assert!(runner::park(&mut h).await.is_err());
        assert!(!h.path("custody.json").exists());
        assert!(h.path("source").exists());
        let mut h = ParkHarness::new()?;
        fs::write(h.path("remote.blob"), b"foreign remote bytes")?;
        assert!(runner::park(&mut h).await.is_err());
        assert_eq!(fs::read(h.path("remote.blob"))?, b"foreign remote bytes");
        assert_eq!(h.uploads, 0);
        Ok(())
    }
    struct RestoreHarness {
        root: tempfile::TempDir,
        fault: Option<runner::RestoreStep>,
        expire_after: Option<runner::RestoreStep>,
        capacity_valid: bool,
        commit_allowed: bool,
        downloads: usize,
        manifest: Value,
        sha: String,
    }
    impl RestoreHarness {
        fn new() -> Result<Self> {
            Ok(Self {
                root: tempfile::tempdir()?,
                fault: None,
                expire_after: None,
                capacity_valid: true,
                commit_allowed: true,
                downloads: 0,
                manifest: manifest(Artifact::ThroughRoot206),
                sha: Artifact::ThroughRoot206.sha().into(),
            })
        }
        fn blob(&self) -> PathBuf {
            self.root.path().join(format!("{}.blob", self.sha))
        }
        fn partial(&self) -> PathBuf {
            self.root.path().join(format!(".{}.partial", self.sha))
        }
        fn receipt(&self) -> PathBuf {
            self.root.path().join("restore.json")
        }
    }
    impl runner::RestoreOperations for RestoreHarness {
        async fn step(&mut self, s: runner::RestoreStep) -> Result<()> {
            use runner::RestoreStep::*;
            match s {
                Prepare => {
                    validate_manifest(&self.manifest)?;
                    ensure!(self.capacity_valid, "fresh capacity admission required");
                }
                Download => {
                    if !self.blob().exists() {
                        if !self.partial().exists() {
                            fs::write(self.partial(), b"downloaded fixture bytes")?;
                            File::open(self.partial())?.sync_all()?;
                            fs::set_permissions(self.partial(), fs::Permissions::from_mode(0o400))?;
                            File::open(self.partial())?.sync_all()?;
                            self.downloads += 1;
                        }
                        ensure!(
                            fs::read(self.partial())? == b"downloaded fixture bytes",
                            "conflicting restore partial"
                        );
                        ensure!(
                            self.commit_allowed,
                            "injected expiry at the real pre-commit capacity callback"
                        );
                        rename_noreplace(&self.partial(), &self.blob())?;
                    }
                }
                Metadata => {
                    restore_metadata_at(self.root.path(), &self.sha, &self.manifest)?;
                }
                VerifyBody => {
                    ensure!(
                        fs::read(self.blob())? == b"downloaded fixture bytes",
                        "restored bytes changed"
                    );
                }
                VerifyRemote => {
                    validate_manifest(&self.manifest)?;
                }
                VerifyCapacity => {
                    ensure!(self.capacity_valid, "injected expired accepted capacity");
                }
                PersistReceipt => {
                    persist(
                        &self.receipt(),
                        &json!({"complete_byte_restoration_verified":true,"staging_only":true}),
                    )?;
                }
            }
            Ok(())
        }
        fn checkpoint(&mut self, s: runner::RestoreStep) -> Result<()> {
            if self.expire_after == Some(s) {
                self.expire_after = None;
                self.capacity_valid = false;
            }
            if self.fault == Some(s) {
                self.fault = None;
                bail!("injected restore interruption");
            }
            Ok(())
        }
    }
    #[tokio::test]
    async fn production_restore_runner_reenters_after_download_metadata_and_receipt() -> Result<()>
    {
        for point in [
            runner::RestoreStep::Download,
            runner::RestoreStep::Metadata,
            runner::RestoreStep::VerifyCapacity,
            runner::RestoreStep::PersistReceipt,
        ] {
            let mut h = RestoreHarness::new()?;
            h.fault = Some(point);
            assert!(runner::restore(&mut h).await.is_err());
            assert!(h.blob().exists());
            runner::restore(&mut h).await?;
            runner::restore(&mut h).await?;
            assert_eq!(h.downloads, 1);
            assert!(h.receipt().exists());
        }
        Ok(())
    }
    #[tokio::test]
    async fn production_restore_runner_preserves_bytes_on_capacity_expiry_and_metadata_conflict()
    -> Result<()> {
        let mut h = RestoreHarness::new()?;
        h.expire_after = Some(runner::RestoreStep::Metadata);
        assert!(runner::restore(&mut h).await.is_err());
        assert!(h.blob().exists());
        assert!(!h.receipt().exists());
        h.capacity_valid = true;
        runner::restore(&mut h).await?;
        assert_eq!(h.downloads, 1);
        let mut h = RestoreHarness::new()?;
        h.commit_allowed = false;
        assert!(runner::restore(&mut h).await.is_err());
        assert!(h.partial().exists() && !h.blob().exists() && !h.receipt().exists());
        h.commit_allowed = true;
        runner::restore(&mut h).await?;
        assert_eq!(h.downloads, 1);
        let mut h = RestoreHarness::new()?;
        h.fault = Some(runner::RestoreStep::Metadata);
        assert!(runner::restore(&mut h).await.is_err());
        let raw_name = h.manifest["raw_metadata"][0]["name"].as_str().unwrap();
        let path = h.root.path().join(format!("{}-{raw_name}", h.sha));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        fs::write(&path, b"conflicting metadata")?;
        assert!(runner::restore(&mut h).await.is_err());
        assert_eq!(fs::read(&path)?, b"conflicting metadata");
        assert!(h.blob().exists());
        assert!(!h.receipt().exists());
        Ok(())
    }
}
