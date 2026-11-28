//! Retire the exact stopped epoch 288 partial once encrypted restore is proved.
use super::super::{retirement, runner};
use super::*;
use std::process::Command;

const CHECK: &str = "holding-foundation-288-partial-check-retire";
const APPLY: &str = "holding-foundation-288-partial-retire";
const PARK_INVOCATION: &str = "5a9f1cb128a34cb0a3367558cd3d6dc8";
const PARK_LAUNCH_SHA: &str = "e8659e9a068435ade757c1b8a3db3c3eb28e491b2be5e1b892a075ae9fbd78aa";
const KEY_PROOF_SHA: &str = "7fd6ec95aa3bf2116628d279765c5fd2f18668e6766e2a8bb47892567a6035df";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RetirePlan {
    schema: String,
    mapping: Bound,
    custody: Bound,
    local_private_retirement_authorized: bool,
}

pub(super) fn command(action: &str) -> bool {
    matches!(action, CHECK | APPLY)
}

fn park_launch() -> Bound {
    Bound {
        path: Path::new(ROOT).join("park-launch.json"),
        sha256: PARK_LAUNCH_SHA.into(),
    }
}

fn key_proof() -> Bound {
    Bound {
        path: Path::new(ROOT).join("park-key-identity-v1.json"),
        sha256: KEY_PROOF_SHA.into(),
    }
}

fn verify_park_exit() -> Result<Value> {
    let service = closure::properties(UNIT, PARK_INVOCATION, true)?;
    ensure!(
        service["ActiveState"] == "inactive"
            && service["SubState"] == "dead"
            && service["Result"] == "success"
            && service["ExecMainStatus"] == "0"
            && !Path::new("/sys/fs/cgroup/system.slice")
                .join(UNIT)
                .try_exists()?,
        "epoch 288 park has not cleanly drained"
    );
    let event = Command::new("/usr/bin/journalctl")
        .args([
            "-b",
            "--no-pager",
            "--quiet",
            "-o",
            "json",
            "_PID=1",
            "_UID=0",
            &format!("UNIT={UNIT}"),
            &format!("INVOCATION_ID={PARK_INVOCATION}"),
            "MESSAGE_ID=7ad2d189f7e94e70a38c781354912448",
        ])
        .output()?;
    ensure!(
        event.status.success(),
        "could not read the exact park terminal event"
    );
    let event: Value =
        serde_json::from_slice(&event.stdout).context("missing exact park PID 1 success")?;
    ensure!(
        event["UNIT"] == UNIT
            && event["INVOCATION_ID"] == PARK_INVOCATION
            && event["_PID"] == "1"
            && event["_UID"] == "0",
        "epoch 288 park terminal event differs"
    );
    Ok(event)
}

fn verify_key(launch: &Value) -> Result<()> {
    let evidence = saved(&key_proof())?;
    let key = openpgp::key_file(Path::new(ROOT), KEY, false)?;
    let raw = read_stable_bounded(&key, 65, "retained 288 custody key")?;
    let stamp = Stamp::of(&key.symlink_metadata()?);
    ensure!(
        evidence["schema"] == "foundation-288-partial-park-key-identity-v1"
            && evidence["launch"] == json!(park_launch())
            && evidence["actual"]["InvocationID"] == PARK_INVOCATION
            && evidence["actual"]["MainPID"] == launch["actual"]["MainPID"]
            && evidence["actual"]["Id"] == UNIT
            && evidence["path"] == json!(key)
            && evidence["identity"] == json!(stamp)
            && evidence["sha256"] == hex_lower(&Sha256::digest(&raw)),
        "epoch 288 park key identity differs from the live custody observation"
    );
    Ok(())
}

fn manifest_scope(custody: &Value, launch: &Value) -> Result<()> {
    let manifest = &custody["manifest"];
    let wire_sha = manifest["ciphertext_sha256"]
        .as_str()
        .context("missing 288 ciphertext digest")?;
    let length = manifest["ciphertext_length"]
        .as_u64()
        .context("missing 288 ciphertext length")?;
    let etag = manifest["object_etag"]
        .as_str()
        .context("missing 288 ciphertext ETag")?;
    let (part_digest, part_count) = etag
        .split_once('-')
        .context("invalid 288 ciphertext multipart ETag")?;
    ensure!(
        custody["schema"] == "foundation-epoch288-encrypted-partial-custody-v1"
            && custody["epoch"] == 288
            && custody["plan"] == launch["spec"]
            && custody["admission"] == launch["admission"]
            && custody["remote_bucket"] == BUCKET
            && custody["invocation_id"] == PARK_INVOCATION
            && custody["remote_ciphertext_sha256_verified"] == true
            && custody["remote_authenticated_decryption_verified"] == true
            && custody["restored_plaintext_reread_verified"] == true
            && custody["local_source_revalidated"] == true
            && custody["publication_authorized"] == false
            && custody["local_retirement_authorized"] == false
            && manifest["schema"] == "foundation-epoch288-encrypted-partial-manifest-v1"
            && manifest["epoch"] == 288
            && manifest["object_key"] == object_key()
            && manifest["format"] == FORMAT
            && manifest["plaintext_length"] == CLEAR_BYTES
            && manifest["plaintext_sha256"] == CLEAR_SHA
            && manifest["source"] == json!(source_proof())
            && manifest["archive_complete"] == false
            && manifest["resumable_checkpoint"] == false
            && digest(wire_sha)
            && (CLEAR_BYTES..=CLEAR_BYTES + WIRE_OVERHEAD).contains(&length)
            && is_lower_hex(part_digest, 32)
            && part_count == length.div_ceil(DEFAULT_PART_SIZE).to_string(),
        "epoch 288 custody lacks exact authenticated restore evidence"
    );
    Ok(())
}

async fn authenticate(client: &Client, custody: &Value, launch: &Value) -> Result<()> {
    verify_key(launch)?;
    let manifest = &custody["manifest"];
    let wire_sha = manifest["ciphertext_sha256"]
        .as_str()
        .context("missing ciphertext SHA-256")?;
    let length = manifest["ciphertext_length"]
        .as_u64()
        .context("missing ciphertext length")?;
    let etag = manifest["object_etag"]
        .as_str()
        .context("missing ciphertext ETag")?;
    let payload = serde_json::to_vec(manifest)?;
    let sha = hex_lower(&Sha256::digest(&payload));
    let marker = manifest_key(&sha)?;
    let key = object_key();
    ensure!(
        custody["manifest_key"] == marker && custody["manifest_sha256"] == sha,
        "epoch 288 manifest address differs from the exact receipt"
    );
    let (intent_name, intent_body) = intent(&key, wire_sha, length)?;
    let mut intent_bytes = serde_json::to_vec_pretty(&intent_body)?;
    intent_bytes.push(b'\n');
    saved(&Bound {
        path: Path::new(STATE).join("receipts").join(intent_name),
        sha256: hex_lower(&Sha256::digest(&intent_bytes)),
    })?;
    let owner = get_mutable_object(client, BUCKET, &format!("{}owner.json", host::PREFIX))
        .await?
        .context("missing Foundation holding owner")?;
    ensure!(
        owner.bytes == owner_bytes()?,
        "foreign Foundation holding owner"
    );
    let observed = get_mutable_object(client, BUCKET, &marker)
        .await?
        .context("missing epoch 288 holding manifest")?;
    ensure!(
        observed.bytes == payload,
        "authenticated epoch 288 manifest differs"
    );
    let head = head_archive(client, BUCKET, &key)
        .await?
        .context("missing epoch 288 ciphertext")?;
    remote_matches(&head, &key, length, wire_sha, Some(etag))
}

fn original_identity(closed: &Value) -> Result<(PathBuf, Stamp, u64)> {
    let path: PathBuf = serde_json::from_value(closed["source"]["path"].clone())?;
    let mut body = closed["source"]["identity"].clone();
    let fields = body
        .as_object_mut()
        .context("invalid retained epoch 288 identity")?;
    let length = fields
        .remove("bytes")
        .context("missing retained 288 length")?;
    let blocks = fields
        .remove("blocks")
        .and_then(|v| v.as_u64())
        .context("missing retained 288 blocks")?;
    let mode = fields
        .remove("mode")
        .and_then(|v| v.as_u64())
        .context("missing retained 288 mode")?;
    fields.insert("length".into(), length);
    fields.insert("mode".into(), json!(mode & 0o7777));
    let stamp: Stamp = serde_json::from_value(body)?;
    ensure!(
        closed["epoch"] == 288
            && closed["archive_complete"] == false
            && closed["source"]["sha256"] == CLEAR_SHA
            && path.is_absolute()
            && path.file_name().and_then(|n| n.to_str()) == Some("epoch-288.jet")
            && (stamp.length, stamp.uid, stamp.gid, stamp.mode, stamp.links)
                == (CLEAR_BYTES, 1000, 1000, 0o600, 1),
        "epoch 288 stopped partial source scope differs"
    );
    Ok((
        path,
        stamp,
        blocks
            .checked_mul(512)
            .context("288 allocated bytes overflow")?,
    ))
}

fn phase_name(phase: &str) -> String {
    format!("partial288-retire-{CLEAR_SHA}-{phase}.json")
}

struct Native<'a> {
    client: Client,
    spec: &'a Bound,
    custody: Value,
    launch: Value,
    closed: Value,
    source: PathBuf,
    quarantine: PathBuf,
    expected: Stamp,
    stamp: Option<Stamp>,
    operation: Value,
}

impl Native<'_> {
    fn phase_exists(&self, phase: &str) -> Result<bool> {
        Ok(!retirement::absent(&self.phase_path(phase))?)
    }

    fn phase_path(&self, phase: &str) -> PathBuf {
        Path::new(STATE).join("receipts").join(phase_name(phase))
    }

    fn phase(&self, phase: &str) -> Result<Value> {
        retirement::record_at(&self.phase_path(phase), &self.operation, 0)
    }

    fn save(&self, phase: &str, extra: Value) -> Result<PathBuf> {
        let mut fields = extra
            .as_object()
            .context("retirement receipt shape")?
            .clone();
        fields.insert("operation".into(), self.operation.clone());
        fields.insert("recorded_unix_seconds".into(), json!(clock()?));
        receipt(&phase_name(phase), &Value::Object(fields))
    }

    fn verify_chain(&self) -> Result<()> {
        self.phase("intent")?;
        retirement::validate_chain(
            &self.expected,
            &self.phase("quarantine-verified")?,
            &self.phase("unlink-intent")?,
        )?;
        ensure!(
            retirement::absent(&self.source)?,
            "original 288 name reappeared"
        );
        Ok(())
    }

    fn inspect(&self) -> Result<()> {
        verify_stopped(&self.closed, &self.source)?;
        verify_park_exit()?;
        ensure!(
            retirement::absent(&self.source.with_extension("jet.sha256"))?,
            "epoch 288 local archive now has a canonical sidecar"
        );
        for path in [&self.source, &self.quarantine] {
            if !retirement::absent(path)? {
                no_references(path)?;
            }
        }
        Ok(())
    }

    fn hash_body(&mut self, original: bool) -> Result<()> {
        let path = if original {
            &self.source
        } else {
            &self.quarantine
        };
        self.stamp = Some(retirement::body_at(
            path,
            &self.expected,
            CLEAR_SHA,
            original,
        )?);
        Ok(())
    }

    fn stamp(&self) -> Result<&Stamp> {
        self.stamp
            .as_ref()
            .context("missing verified epoch 288 inode")
    }

    fn directory(path: &Path) -> Result<File> {
        let parent = path.parent().context("unknown epoch 288 file parent")?;
        ensure!(
            parent.canonicalize()? == parent,
            "aliased epoch 288 directory"
        );
        Ok(OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(parent)?)
    }
}

impl runner::RetireOperations for Native<'_> {
    fn state(&self) -> Result<runner::RetireState> {
        Ok(runner::RetireState {
            source: !retirement::absent(&self.source)?,
            quarantine: !retirement::absent(&self.quarantine)?,
            intent: self.phase_exists("intent")?,
            verified: self.phase_exists("quarantine-verified")?,
            unlink: self.phase_exists("unlink-intent")?,
            complete: self.phase_exists("completion")?,
        })
    }

    async fn step(&mut self, step: runner::RetireStep) -> Result<()> {
        use runner::RetireStep::*;
        match step {
            VerifyComplete | Complete => {
                self.verify_chain()?;
                ensure!(
                    retirement::absent(&self.quarantine)?,
                    "quarantined epoch 288 bytes remain"
                );
                if step == Complete {
                    self.save(
                        "completion",
                        json!({
                            "source_and_quarantine_absent":true,
                            "requires_fresh_capacity_observation":true,
                            "publication_authorized":false,"remote_mutations":false
                        }),
                    )?;
                }
                ensure!(
                    self.phase("completion")?["source_and_quarantine_absent"] == true,
                    "epoch 288 retirement completion differs"
                );
                println!("{}", self.phase_path("completion").display());
            }
            Inspect => self.inspect()?,
            HashOriginal => self.hash_body(true)?,
            CheckOnly => println!(
                "{}",
                json!({
                    "epoch":288,"status":"retirement-check-passed","operation":self.operation,
                    "source_sha256_verified_this_check":self.stamp.is_some(),
                    "mutation_performed":false,"disk_credit_bytes":0
                })
            ),
            Intent => {
                self.save(
                    "intent",
                    json!({"spec":self.spec,"source_stamp":self.stamp()?}),
                )?;
            }
            ReconcileIntent => {
                let intent = self.phase("intent")?;
                ensure!(
                    intent["source_stamp"] == json!(self.expected),
                    "epoch 288 unlink lineage differs"
                );
            }
            BeforeRename | BeforeUnlink => {
                self.inspect()?;
                authenticate(&self.client, &self.custody, &self.launch).await?;
            }
            Rename => {
                let from = Self::directory(&self.source)?;
                let to = Self::directory(&self.quarantine)?;
                ensure!(
                    from.metadata()?.dev() == to.metadata()?.dev()
                        && Stamp::of(&self.source.symlink_metadata()?) == self.expected,
                    "epoch 288 source identity or quarantine filesystem differs"
                );
                retirement::rename_child(
                    &from,
                    self.source.file_name().unwrap(),
                    &to,
                    self.quarantine.file_name().unwrap(),
                )?;
                ensure!(
                    retirement::absent(&self.source)?,
                    "original epoch 288 name remains after rename"
                );
            }
            HashQuarantine => self.hash_body(false)?,
            QuarantineProof => {
                let stamp = self.stamp()?;
                if self.phase_exists("quarantine-verified")? {
                    ensure!(
                        self.phase("quarantine-verified")?["quarantine_stamp"] == json!(stamp),
                        "verified epoch 288 quarantine inode changed"
                    );
                } else {
                    self.save(
                        "quarantine-verified",
                        json!({
                            "source_body_identity":self.expected,"quarantine_stamp":stamp,
                            "complete_local_sha256_verified":true
                        }),
                    )?;
                }
            }
            UnlinkIntent => {
                if !self.phase_exists("unlink-intent")? {
                    self.save(
                        "unlink-intent",
                        json!({"quarantine_verification":self.stamp()?}),
                    )?;
                }
                self.verify_chain()?;
            }
            Unlink => {
                self.verify_chain()?;
                let dir = Self::directory(&self.quarantine)?;
                ensure!(
                    Stamp::of(&self.quarantine.symlink_metadata()?) == *self.stamp()?,
                    "epoch 288 quarantine identity changed before unlink"
                );
                retirement::unlink_child(&dir, self.quarantine.file_name().unwrap())?;
            }
            VerifyChain => self.verify_chain()?,
        }
        Ok(())
    }
}

pub(super) async fn run(action: &str, value: Value, spec: &Bound) -> Result<()> {
    let plan: RetirePlan = serde_json::from_value(value)?;
    let check = action == CHECK;
    ensure!(
        plan.schema == "foundation-epoch288-encrypted-partial-retirement-plan-v1"
            && (check || plan.local_private_retirement_authorized),
        "epoch 288 partial retirement lacks an exact local plan"
    );
    mapping(&plan.mapping)?;
    let launch = saved(&park_launch())?;
    ensure!(
        launch["schema"] == "foundation-epoch288-partial-custody-launch-v1"
            && launch["actual"]["Id"] == UNIT
            && launch["actual"]["InvocationID"] == PARK_INVOCATION
            && launch["retirement_authorized"] == false,
        "foreign epoch 288 park launch"
    );
    let park_spec: Bound = serde_json::from_value(launch["spec"].clone())?;
    let parked: Plan = serde_json::from_value(saved(&park_spec)?)?;
    ensure!(
        parked.schema == "foundation-epoch288-partial-custody-plan-v1"
            && json!(parked.mapping) == json!(plan.mapping)
            && json!(parked.admission) == launch["admission"]
            && plan.custody.path
                == Path::new(STATE)
                    .join("receipts")
                    .join(format!("partial288-custody-{}.json", park_spec.sha256)),
        "foreign epoch 288 park plan or custody receipt address"
    );
    let terminal = verify_park_exit()?;
    let custody = saved(&plan.custody)?;
    manifest_scope(&custody, &launch)?;
    let config = r2_config_from_env()?;
    ensure!(config.bucket == BUCKET, "foreign epoch 288 custody bucket");
    let client = s3_client(&config);
    authenticate(&client, &custody, &launch).await?;

    let closed = saved(&source_proof())?;
    let (source, expected, allocated) = original_identity(&closed)?;
    let quarantine = Path::new(STATE)
        .join("quarantine")
        .join(format!("partial288-{CLEAR_SHA}.blob"));
    let operation = json!({
        "schema":"foundation-epoch288-partial-retirement-operation-v1","epoch":288,
        "source":source,"source_identity":expected,"source_closure":source_proof(),
        "sha256":CLEAR_SHA,"source_allocated_bytes":allocated,"quarantine":quarantine,
        "custody":plan.custody,"park_launch":park_launch(),"park_key":key_proof(),
        "park_pid1_exit":terminal["__CURSOR"],"archive_complete":false
    });
    runner::retire(
        &mut Native {
            client,
            spec,
            custody,
            launch,
            closed,
            source,
            quarantine,
            expected,
            stamp: None,
            operation,
        },
        check,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_retirement_requires_the_exact_park_and_authenticated_restore() -> Result<()> {
        let launch = json!({
            "spec":{"path": "park.json", "sha256":"a".repeat(64)},
            "admission":{"path":"park-admission.json","sha256":"b".repeat(64)}
        });
        let base = json!({
            "schema":"foundation-epoch288-encrypted-partial-custody-v1","epoch":288,
            "plan":launch["spec"],"admission":launch["admission"],"remote_bucket":BUCKET,
            "invocation_id":PARK_INVOCATION,"remote_ciphertext_sha256_verified":true,
            "remote_authenticated_decryption_verified":true,"restored_plaintext_reread_verified":true,
            "local_source_revalidated":true,"publication_authorized":false,"local_retirement_authorized":false,
            "manifest":{
                "schema":"foundation-epoch288-encrypted-partial-manifest-v1","epoch":288,
                "object_key":object_key(),"format":FORMAT,"plaintext_length":CLEAR_BYTES,
                "plaintext_sha256":CLEAR_SHA,"source":source_proof(),"archive_complete":false,
                "resumable_checkpoint":false,"ciphertext_sha256":"c".repeat(64),
                "ciphertext_length":CLEAR_BYTES + 65536,
                "object_etag":format!("{}-{}", "d".repeat(32), (CLEAR_BYTES + 65536).div_ceil(DEFAULT_PART_SIZE))
            }
        });
        manifest_scope(&base, &launch)?;
        for (pointer, wrong) in [
            ("/invocation_id", json!("0".repeat(32))),
            ("/remote_authenticated_decryption_verified", json!(false)),
            ("/restored_plaintext_reread_verified", json!(false)),
            ("/manifest/archive_complete", json!(true)),
            (
                "/manifest/object_etag",
                json!(format!("{}-1", "d".repeat(32))),
            ),
            ("/manifest/object_key", json!("epoch-288.jet")),
        ] {
            let mut changed = base.clone();
            *changed.pointer_mut(pointer).unwrap() = wrong;
            assert!(manifest_scope(&changed, &launch).is_err(), "{pointer}");
        }
        Ok(())
    }
}
