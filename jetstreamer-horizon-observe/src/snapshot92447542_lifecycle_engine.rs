//! Shared complete slot92447542 lifecycle state machines.
//!
//! Production constructs only ProductionEnvironment after the unchanged fixed
//! Plan gates. Isolated constructors/fixtures exist only in test builds. The
//! engine never selects another generation and owns all durable transitions,
//! hash/size/floor/timeout gates and transport shutdown/cleanup ordering.
use super::*;

#[derive(Clone)]
pub(super) struct RestoreRequest {
    pub attempt: String,
    pub maximum_runtime_seconds: u64,
    pub admission_sha256: String,
}
pub(super) struct Booking {
    pub protected_floor_bytes: u64,
    pub owner: Owner,
    pub protected_owners: Vec<Owner>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Phase {
    CheckDurable,
    EvictionIntentDurable,
    QuarantineRenameDurable,
    MovedProofDurable,
    UnlinkIntentDurable,
    UnlinkDurable,
    EvictedDurable,
    RestoreIntentDurable,
    RestoreStageDurable,
    RestoreStageOwnedDurable,
    RestoreChildSpawned,
    RestoreStageFrozen,
    RestorePayloadFrozen,
    RestorePublishIntentDurable,
    RestorePublishRenameDurable,
    RestoreReceiptDurable,
    RestoreStageCleaned,
    RestoreFailureIntentDurable,
    RestoreFailureStageCleaned,
    RestoreFailureCompletionDurable,
    RestoreRecoveryIntentDurable,
    RestoreRecoveryStageCleaned,
    RestoreRecoveryCompletionDurable,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Scope {
    Production,
    #[cfg(test)]
    Isolated,
    #[cfg(test)]
    Fixture,
}

pub(super) struct Bindings {
    scope: Scope,
    pub operation_sha256: String,
    pub self_sha256: String,
    pub consumer_sha256: String,
    pub authority_sha256: String,
}
impl Bindings {
    pub(super) fn production(p: &Plan, plan: &str, image: &str) -> Self {
        Self {
            scope: Scope::Production,
            operation_sha256: plan.into(),
            self_sha256: image.into(),
            consumer_sha256: p.consumer_review.sha256.clone(),
            authority_sha256: p.qualification.sha256.clone(),
        }
    }
    #[cfg(test)]
    pub(super) fn isolated(
        session: &str,
        image: &str,
        reference_policy: &str,
        lineage: &str,
    ) -> Result<Self> {
        ensure!(
            [session, image, reference_policy, lineage]
                .iter()
                .all(|s| is_sha(s)),
            "invalid isolated authority bindings"
        );
        Ok(Self {
            scope: Scope::Isolated,
            operation_sha256: session.into(),
            self_sha256: image.into(),
            consumer_sha256: reference_policy.into(),
            authority_sha256: lineage.into(),
        })
    }
    #[cfg(test)]
    fn fixture(session: &str, image: &str, policy: &str, acquisition: &str) -> Result<Self> {
        let mut b = Self::isolated(session, image, policy, acquisition)?;
        b.scope = Scope::Fixture;
        Ok(b)
    }
    fn key(&self, production: &str) -> String {
        #[cfg(test)]
        if self.scope != Scope::Production {
            let fixture = self.scope == Scope::Fixture;
            return match production {
                "plan_sha256" => {
                    if fixture {
                        "fixture_session_sha256"
                    } else {
                        "native_session_sha256"
                    }
                }
                "consumer_review_sha256" => {
                    if fixture {
                        "fixture_reference_policy_sha256"
                    } else {
                        "isolated_reference_policy_sha256"
                    }
                }
                "qualification_sha256" => {
                    if fixture {
                        "fixture_acquisition_sha256"
                    } else {
                        "normal_helper_lineage_sha256"
                    }
                }
                "historical_receipt" => "isolated_acquisition_receipt",
                "historical_receipt_unchanged" => "isolated_acquisition_receipt_unchanged",
                "original_historical_receipt_preserved" => "isolated_acquisition_receipt_preserved",
                "authenticated_generation_metadata" => "isolated_object_metadata",
                "authenticated_generation_metadata_sha256" => "isolated_object_metadata_sha256",
                _ => production,
            }
            .into();
        }
        production.into()
    }
    fn get(&self, value: &Value, key: &str) -> Value {
        value[self.key(key)].clone()
    }
    fn schema(&self, production: &str) -> String {
        #[cfg(test)]
        if self.scope != Scope::Production {
            return production.replacen(
                "jetstreamer-snapshot92447542-",
                if self.scope == Scope::Fixture {
                    "jetstreamer-snapshot92447542-ordinary-fixture-"
                } else {
                    "jetstreamer-snapshot92447542-isolated-"
                },
                1,
            );
        }
        production.into()
    }
    fn encode(&self, mut value: Value) -> Value {
        #[cfg(test)]
        if self.scope != Scope::Production {
            if let Some(map) = value.as_object_mut() {
                for key in [
                    "plan_sha256",
                    "consumer_review_sha256",
                    "qualification_sha256",
                    "historical_receipt",
                    "historical_receipt_unchanged",
                    "original_historical_receipt_preserved",
                    "authenticated_generation_metadata",
                    "authenticated_generation_metadata_sha256",
                ] {
                    if let Some(v) = map.remove(key) {
                        map.insert(self.key(key), v);
                    }
                }
                if let Some(schema) = map.get("schema").and_then(Value::as_str) {
                    if !schema.starts_with(&self.schema("jetstreamer-snapshot92447542-")) {
                        let schema = self.schema(schema);
                        map.insert("schema".into(), json!(schema));
                    }
                }
            }
        }
        value
    }
}

pub(super) struct ObjectSpec {
    bytes: u64,
    crc32c: String,
    md5: String,
    fixed: bool,
}
impl ObjectSpec {
    pub(super) fn fixed_generation() -> Self {
        Self {
            bytes: SIZE,
            crc32c: CRC.into(),
            md5: MD5.into(),
            fixed: true,
        }
    }
    #[cfg(test)]
    pub(super) fn fixture(bytes: &[u8]) -> Result<Self> {
        let d = digest_reader(bytes, bytes.len() as u64, || Ok(()))?;
        Ok(Self {
            bytes: d.bytes,
            crc32c: d.crc32c,
            md5: d.md5,
            fixed: false,
        })
    }
    pub(super) fn is_fixed_generation(&self) -> bool {
        self.fixed
    }
    pub(super) fn bytes(&self) -> u64 {
        self.bytes
    }
    fn verify(&self, d: &Digests, wanted: Option<&str>) -> Result<()> {
        if self.fixed {
            return validate_digests(d, wanted);
        }
        #[cfg(test)]
        {
            ensure!(
                d.bytes == self.bytes
                    && d.crc32c == self.crc32c
                    && d.md5 == self.md5
                    && is_sha(&d.sha256)
                    && wanted.is_none_or(|s| s == d.sha256),
                "isolated fixture integrity mismatch"
            );
            return Ok(());
        }
        #[cfg(not(test))]
        bail!("non-generation production object refused")
    }
}

/// Implementations are private source-owned adapters, never deserialized code.
/// Production methods re-enter the unchanged historical/consumer/SDK/admission
/// gates. Native implementations must independently authenticate isolated paths,
/// actual service identity and normal source lineage before constructing them.
pub(super) trait Environment {
    fn cache(&self) -> &Directory;
    fn state(&self) -> &Directory;
    fn source_identity(&self) -> &Identity;
    fn available_bytes(&self, path: &Path) -> Result<u64> {
        free_bytes(path)
    }
    fn bindings(&self) -> &Bindings;
    fn object(&self) -> &ObjectSpec;
    fn history(&self) -> Result<Value>;
    fn consumers(&self) -> Result<Value>;
    fn metadata(&self) -> Result<Vec<u8>>;
    fn validate_metadata(&self, value: &Value) -> Result<()> {
        super::validate_metadata(value)
    }
    fn restore_request(&self) -> Option<RestoreRequest>;
    fn restore_admission(&self, verified: &str) -> Result<Booking>;
    fn guard_owners(&self, booking: &Booking) -> Result<()>;
    fn spawn_download(&self, destination: &Path) -> Result<OwnedSdk>;
    /// The production default supplies no fault or interruption behavior.
    fn after_phase(&self, _phase: Phase) -> Result<()> {
        Ok(())
    }
    /// Authenticate a fresh recovery capability and original attempt-owner
    /// closure. The caller never derives cleanup authority from PID absence.
    /// Return actual sealed ownership/disposition evidence for the journal.
    fn authorize_recovery(
        &self,
        prior_intent: &Value,
        current_stage: Option<&DirectoryIdentity>,
    ) -> Result<Value>;
}
fn encoded<E: Environment>(e: &E, value: &Value) -> Value {
    let mut value = e.bindings().encode(value.clone());
    #[cfg(test)]
    if !e.object().fixed {
        if let Some(m) = value.as_object_mut() {
            m.remove("uri");
            m.remove("generation");
            m.insert("fixture_object".into(), json!(true));
        }
    }
    value
}
fn put<E: Environment>(e: &E, path: &Path, value: &Value) -> Result<()> {
    persist(path, &encoded(e, value))
}
fn put_same<E: Environment>(e: &E, path: &Path, value: &Value) -> Result<()> {
    persist_same(path, &encoded(e, value))
}
fn hash_object<E: Environment>(
    e: &E,
    dir: &Directory,
    name: &str,
    identity: Option<&Identity>,
    wanted: Option<&str>,
    guard: impl FnMut() -> Result<()>,
) -> Result<(Identity, Digests, u64)> {
    digest_at(
        dir,
        name,
        identity,
        e.object().bytes(),
        |d| e.object().verify(d, wanted),
        guard,
    )
}
fn guard<E: Environment>(
    e: &E,
    d: &Directory,
    booking: &Booking,
    start: Instant,
    maximum: u64,
) -> Result<()> {
    ensure!(
        start.elapsed().as_secs() < maximum,
        "restore runtime exhausted"
    );
    ensure!(
        e.available_bytes(&d.path)? >= booking.protected_floor_bytes,
        "protected free-space floor crossed"
    );
    ensure!(
        staged_bytes(d)?
            <= e.object()
                .bytes()
                .checked_add(SLACK)
                .context("staging bound overflow")?,
        "restore staging bound exceeded"
    );
    e.guard_owners(booking)
}

// Cleanup freezes an owned UID1000 stage to Root before unlinking its members.
// An interruption can therefore change custody while preserving its exact inode.
fn same_recovery_stage(before: &DirectoryIdentity, after: &DirectoryIdentity) -> bool {
    before.device == after.device
        && before.inode == after.inode
        && before.mode & 0o7777 == 0o700
        && after.mode & 0o7777 == 0o700
        && before.uid == before.gid
        && after.uid == after.gid
        && matches!((before.uid, after.uid), (0, 0) | (1000, 1000) | (1000, 0))
}
#[cfg(test)]
mod recovery_identity_tests {
    use super::*;
    #[test]
    fn only_the_same_stage_may_complete_the_custody_freeze() {
        let original = DirectoryIdentity {
            device: 1,
            inode: 2,
            uid: 1000,
            gid: 1000,
            mode: 0o40700,
        };
        let mut frozen = original.clone();
        frozen.uid = 0;
        frozen.gid = 0;
        assert!(same_recovery_stage(&original, &frozen));
        assert!(same_recovery_stage(&frozen, &frozen));
        assert!(!same_recovery_stage(&frozen, &original));
        let mut replaced = frozen.clone();
        replaced.inode += 1;
        assert!(!same_recovery_stage(&original, &replaced));
        replaced = frozen.clone();
        replaced.mode = 0o40755;
        assert!(!same_recovery_stage(&original, &replaced));
        replaced = frozen;
        replaced.uid = 42;
        replaced.gid = 42;
        assert!(!same_recovery_stage(&original, &replaced));
    }
}

/// Recovery may touch only an admitted, exact attempt below this cache. A durable
/// stage-owned record binds the inode before transport starts. If interruption
/// precedes that record, only an empty directory can be retired under a fresh
/// explicit recovery capability. A nonempty unregistered directory is retained.
fn recover_attempt<E: Environment>(e: &E, request: &RestoreRequest, published: bool) -> Result<()> {
    let cache = e.cache();
    let state = e.state();
    let b = e.bindings();
    let attempt = cache.path.join(format!(".{}", request.attempt));
    let intent_path = state.path.join(format!("{}-intent.json", request.attempt));
    let intent = load(&intent_path)?;
    ensure!(
        intent["schema"] == b.schema("jetstreamer-snapshot92447542-restore-attempt-intent-v1")
            && intent["self_sha256"] == b.self_sha256
            && b.get(&intent, "plan_sha256") == b.operation_sha256
            && intent["attempt"] == json!(attempt),
        "foreign prior attempt intent"
    );
    let owned_path = state
        .path
        .join(format!("{}-stage-owned.json", request.attempt));
    let mut stage = if absent(&attempt)? {
        None
    } else {
        let m = fs::symlink_metadata(&attempt)?;
        ensure!(
            m.is_dir()
                && m.dev() == cache.identity.device
                && matches!(m.uid(), 0 | 1000)
                && m.uid() == m.gid()
                && m.mode() & 0o7777 == 0o700,
            "foreign recovery stage custody"
        );
        let current = DirectoryIdentity::of(&m);
        if !absent(&owned_path)? {
            let owned = load(&owned_path)?;
            let original: DirectoryIdentity = serde_json::from_value(owned["identity"].clone())?;
            ensure!(
                owned["schema"] == b.schema("jetstreamer-snapshot92447542-restore-stage-owned-v1")
                    && owned["attempt_intent"] == reference(&intent_path)?
                    && owned["attempt"] == json!(attempt)
                    && owned["original_owner"] == intent["original_owner"]
                    && original.device == current.device
                    && original.inode == current.inode
                    && original.mode & 0o7777 == 0o700,
                "unbound or substituted prior stage"
            );
        } else {
            ensure!(
                fs::read_dir(&attempt)?.next().is_none(),
                "nonempty unregistered stage preserved"
            );
        }
        Some(Directory::open(&attempt, &current)?)
    };
    e.history()?;
    e.consumers()?;
    let authority = e.authorize_recovery(&intent, stage.as_ref().map(|d| &d.identity))?;
    ensure!(
        load(&intent_path)? == intent,
        "prior intent changed during recovery admission"
    );
    if let Some(d) = &stage {
        d.validate()?;
        ensure!(
            inode_references(Path::new("/proc"), d.identity.device, d.identity.inode)?.is_empty(),
            "prior stage inode is still referenced"
        );
    }
    let ri = state
        .path
        .join(format!("{}-recovery-intent.json", request.attempt));
    let rc = state
        .path
        .join(format!("{}-recovery-completion.json", request.attempt));
    let current_intent = encoded(
        e,
        &json!({"schema":"jetstreamer-snapshot92447542-restore-recovery-intent-v1", "self_sha256":b.self_sha256,"plan_sha256":b.operation_sha256,"attempt_intent":reference(&intent_path)?,"attempt":attempt,"attempt_identity":stage.as_ref().map(|d| &d.identity),"published_destination_reconciled":published,"fresh_recovery_authority":authority}),
    );
    if absent(&ri)? {
        put(e, &ri, &current_intent)?;
    } else {
        let old = load(&ri)?;
        ensure!(
            old["schema"] == b.schema("jetstreamer-snapshot92447542-restore-recovery-intent-v1")
                && old["self_sha256"] == b.self_sha256
                && b.get(&old, "plan_sha256") == b.operation_sha256
                && old["attempt_intent"] == reference(&intent_path)?
                && old["attempt"] == json!(attempt)
                && old["published_destination_reconciled"] == published,
            "conflicting recovery intent"
        );
        if stage.is_some() {
            let prior: DirectoryIdentity = serde_json::from_value(old["attempt_identity"].clone())?;
            let current: DirectoryIdentity =
                serde_json::from_value(current_intent["attempt_identity"].clone())?;
            ensure!(
                same_recovery_stage(&prior, &current),
                "recovery stage changed"
            );
        }
    }
    e.after_phase(Phase::RestoreRecoveryIntentDurable)?;
    if let Some(d) = &mut stage {
        cleanup_attempt(d)?;
    }
    ensure!(absent(&attempt)?, "recovery stage remains");
    e.history()?;
    e.consumers()?;
    e.after_phase(Phase::RestoreRecoveryStageCleaned)?;
    put_same(
        e,
        &rc,
        &json!({"schema":"jetstreamer-snapshot92447542-restore-recovery-completion-v1","self_sha256":b.self_sha256,"plan_sha256":b.operation_sha256,"recovery_intent":reference(&ri)?,"attempt_intent":reference(&intent_path)?,"attempt_absent":true,"published_destination_reconciled":published,"fresh_attempt_required":!published}),
    )?;
    e.after_phase(Phase::RestoreRecoveryCompletionDurable)?;
    Ok(())
}

pub(super) fn run_check<E: Environment>(e: &E) -> Result<()> {
    let cache = e.cache();
    let state = e.state();
    let _lock = lock(&state.path)?;
    let b = e.bindings();
    let plan_sha = b.operation_sha256.as_str();
    let self_sha = b.self_sha256.as_str();
    ensure!(
        e.restore_request().is_none(),
        "check cannot carry restore admission"
    );
    for n in [
        "eviction-intent",
        "moved",
        "unlink-intent",
        "evicted",
        "restored",
    ] {
        ensure!(state.absent(&state_name(n))?, "lifecycle already started");
    }
    let history = e.history()?;
    let before = e.consumers()?;
    let current_metadata = e.metadata()?;
    println!(
        "slot92447542 check hash started bytes={}",
        e.object().bytes()
    );
    let (identity, digests, physical) =
        hash_object(e, cache, NAME, Some(&*e.source_identity()), None, || Ok(()))?;
    let after = e.consumers()?;
    ensure!(
        before["consumers"] == after["consumers"],
        "consumer owner changed during hash"
    );
    e.history()?;
    put(
        e,
        &state.path.join(state_name("check")),
        &json!({"schema":"jetstreamer-snapshot92447542-check-v1","self_sha256":self_sha,"plan_sha256":plan_sha,"source_identity":identity,"digests":digests,"physical_bytes":physical,"historical_receipt":history,"authenticated_generation_metadata":serde_json::from_slice::<Value>(&current_metadata)?,"authenticated_generation_metadata_sha256":sha(&current_metadata),"consumer_review_sha256":b.consumer_sha256,"qualification_sha256":b.authority_sha256,"proof":after,"local_retirement_authorized":false,"remote_mutations":false,"r2_mutations":false}),
    )?;
    e.after_phase(Phase::CheckDurable)?;
    println!("slot92447542 independent check receipt durable");
    Ok(())
}

fn checked<E: Environment>(
    e: &E,
    state: &Directory,
    check_sha: &str,
    self_sha: &str,
) -> Result<Value> {
    let b = e.bindings();
    let c = evidence::bound_json(&Bound {
        path: state.path.join(state_name("check")),
        sha256: check_sha.into(),
    })?;
    ensure!(
        c["schema"] == b.schema("jetstreamer-snapshot92447542-check-v1")
            && c["self_sha256"] == self_sha
            && c["remote_mutations"] == false
            && c["r2_mutations"] == false,
        "wrong check receipt"
    );
    let d: Digests = serde_json::from_value(c["digests"].clone())?;
    e.object().verify(&d, None)?;
    Ok(c)
}
// The only accepted missing-file recovery frontier is a durable unlink intent
// bound to a prior moved proof. Absence after a mere move/eviction intent fails.

pub(super) fn run_evict<E: Environment>(e: &E, check_sha: &str) -> Result<()> {
    let cache = e.cache();
    let state = e.state();
    let _lock = lock(&state.path)?;
    let b = e.bindings();
    let plan_sha = b.operation_sha256.as_str();
    let self_sha = b.self_sha256.as_str();
    ensure!(
        e.restore_request().is_none(),
        "evict cannot carry restore admission"
    );
    let c = checked(e, state, check_sha, self_sha)?;
    ensure!(
        b.get(&c, "plan_sha256") == plan_sha
            && c["source_identity"] == serde_json::to_value(&*e.source_identity())?
            && b.get(&c, "consumer_review_sha256") == b.consumer_sha256
            && b.get(&c, "qualification_sha256") == b.authority_sha256,
        "check/evidence/plan changed"
    );
    let wanted = c["digests"]["sha256"]
        .as_str()
        .context("verified SHA missing")?;
    let q = format!("{PREFIX}-quarantine");
    let intent = state.path.join(state_name("eviction-intent"));
    let moved = state.path.join(state_name("moved"));
    let unlink = state.path.join(state_name("unlink-intent"));
    let done = state.path.join(state_name("evicted"));
    e.history()?;
    e.consumers()?;
    let fresh_metadata = e.metadata()?;
    let auth = encoded(
        e,
        &json!({"schema":"jetstreamer-snapshot92447542-eviction-intent-v1","self_sha256":self_sha,"plan_sha256":plan_sha,"check_sha256":check_sha,"source_identity":*e.source_identity(),"verified_sha256":wanted,"quarantine":state.path.join(&q),"cache_directory":cache.identity,"receipt_directory":state.identity}),
    );
    if !absent(&done)? {
        ensure!(
            load(&done)?["intent"] == auth
                && cache.absent(NAME)?
                && state.absent(&q)?
                && state.absent(&state_name("restored"))?,
            "completed eviction state conflicts"
        );
        println!("slot92447542 eviction already complete");
        return Ok(());
    }
    let source = !cache.absent(NAME)?;
    let quarantined = !state.absent(&q)?;
    let has_moved = !absent(&moved)?;
    let has_unlink = !absent(&unlink)?;
    if absent(&intent)? {
        ensure!(
            source && !quarantined && !has_moved && !has_unlink,
            "foreign markers/unknown initial state"
        );
        hash_object(
            e,
            cache,
            NAME,
            Some(&*e.source_identity()),
            Some(wanted),
            || Ok(()),
        )?;
        e.history()?;
        e.consumers()?;
        put(e, &intent, &auth)?;
        e.after_phase(Phase::EvictionIntentDurable)?;
    } else {
        ensure!(load(&intent)? == auth, "conflicting eviction intent");
    }
    recovery_frontier(source, quarantined, has_moved, has_unlink)?;
    if source {
        hash_object(
            e,
            cache,
            NAME,
            Some(&*e.source_identity()),
            Some(wanted),
            || Ok(()),
        )?;
        e.consumers()?;
        rename_noreplace(cache, NAME, state, &q)?;
        e.after_phase(Phase::QuarantineRenameDurable)?;
    }
    if !state.absent(&q)? {
        ensure!(cache.absent(NAME)?, "source reappeared after quarantine");
        let (i, d, physical) = hash_object(e, state, &q, None, Some(wanted), || Ok(()))?;
        ensure!(
            i.renamed_from(&*e.source_identity()),
            "substituted quarantine preserved; original identity differs"
        );
        let proof = encoded(
            e,
            &json!({"schema":"jetstreamer-snapshot92447542-moved-v1","intent":reference(&intent)?,"source_identity":*e.source_identity(),"quarantine_identity":i,"digests":d,"physical_bytes":physical}),
        );
        put_same(e, &moved, &proof)?;
        e.after_phase(Phase::MovedProofDurable)?;
        let permission = encoded(
            e,
            &json!({"schema":"jetstreamer-snapshot92447542-unlink-intent-v1","intent":reference(&intent)?,"moved":reference(&moved)?,"quarantine_identity":i,"verified_sha256":wanted}),
        );
        put_same(e, &unlink, &permission)?;
        e.after_phase(Phase::UnlinkIntentDurable)?;
        e.history()?;
        e.consumers()?;
        e.metadata()?;
        cache.validate()?;
        state.validate()?;
        ensure!(cache.absent(NAME)?, "source reappeared before unlink");
        unlink_at(state, &q, &i)?;
        e.after_phase(Phase::UnlinkDurable)?;
    }
    let mp = load(&moved)?;
    let up = load(&unlink)?;
    ensure!(
        mp["intent"] == reference(&intent)?
            && up["moved"] == reference(&moved)?
            && up["intent"] == reference(&intent)?
            && up["quarantine_identity"] == mp["quarantine_identity"]
            && up["verified_sha256"] == wanted,
        "unbound moved/unlink recovery proof"
    );
    e.history()?;
    e.consumers()?;
    ensure!(
        cache.absent(NAME)? && state.absent(&q)?,
        "retirement absence failed"
    );
    put(
        e,
        &done,
        &json!({"schema":"jetstreamer-snapshot92447542-evicted-v1","self_sha256":self_sha,"plan_sha256":plan_sha,"check_sha256":check_sha,"intent":auth,"moved":reference(&moved)?,"unlink_intent":reference(&unlink)?,"source_absent":true,"quarantine_absent":true,"removed_logical_bytes":e.object().bytes(),"removed_original_st_blocks_bytes":c["physical_bytes"],"filesystem_available_bytes_after":free_bytes(&cache.path)?,"fresh_generation_metadata_sha256":sha(&fresh_metadata),"historical_receipt_unchanged":true,"restore_requires_fresh_admission":true,"remote_mutations":false,"r2_mutations":false}),
    )?;
    e.after_phase(Phase::EvictedDurable)?;
    println!("slot92447542 exact quarantine retirement complete");
    Ok(())
}

pub(super) fn run_restore<E: Environment>(e: &E, check_sha: &str) -> Result<()> {
    run_restore_inner(e, check_sha, false)
}
pub(super) fn run_recover_restore<E: Environment>(e: &E, check_sha: &str) -> Result<()> {
    run_restore_inner(e, check_sha, true)
}
fn run_restore_inner<E: Environment>(e: &E, check_sha: &str, recovery_only: bool) -> Result<()> {
    let cache = e.cache();
    let state = e.state();
    let _lock = lock(&state.path)?;
    let b = e.bindings();
    let plan_sha = b.operation_sha256.as_str();
    let self_sha = b.self_sha256.as_str();
    let r = e.restore_request().context("restore admission required")?;
    let c = checked(e, state, check_sha, self_sha)?;
    let verified = c["digests"]["sha256"]
        .as_str()
        .context("verified SHA missing")?;
    let evicted = load(&state.path.join(state_name("evicted")))?;
    ensure!(
        evicted["schema"] == b.schema("jetstreamer-snapshot92447542-evicted-v1")
            && evicted["check_sha256"] == check_sha
            && evicted["self_sha256"] == self_sha
            && state.absent(&format!("{PREFIX}-quarantine"))?,
        "matching eviction proof missing"
    );
    e.history()?;
    let completed = state.path.join(state_name("restored"));
    let publish_intent = state
        .path
        .join(format!("{}-publish-intent.json", r.attempt));
    if !cache.absent(NAME)? {
        ensure!(
            !absent(&publish_intent)?,
            "canonical destination collision without this restore publication intent"
        );
        let pi = load(&publish_intent)?;
        ensure!(
            pi["self_sha256"] == self_sha
                && b.get(&pi, "plan_sha256") == plan_sha
                && pi["check_sha256"] == check_sha
                && pi["verified_sha256"] == verified,
            "foreign publication intent"
        );
        let (i, d, _) = hash_object(e, cache, NAME, None, Some(verified), || Ok(()))?;
        let before: Identity = serde_json::from_value(pi["identity"].clone())?;
        ensure!(
            i.renamed_from(&before) && i.uid == 0 && i.gid == 0 && i.mode & 0o7777 == 0o444,
            "restored destination identity differs"
        );
        let receipt = encoded(
            e,
            &json!({"schema":"jetstreamer-snapshot92447542-restored-v1","self_sha256":self_sha,"plan_sha256":plan_sha,"check_sha256":check_sha,"uri":URI,"generation":GENERATION,"new_identity":i,"digests":d,"publication_intent":reference(&publish_intent)?,"original_historical_receipt_preserved":true,"consumers_must_bind_new_receipt":true,"remote_mutations":false,"r2_mutations":false}),
        );
        put_same(e, &completed, &receipt)?;
        let prior = state.path.join(format!("{}-intent.json", r.attempt));
        if !absent(&cache.path.join(format!(".{}", r.attempt)))? {
            ensure!(
                !absent(&prior)?,
                "published orphan lacks its original attempt intent"
            );
            ensure!(
                recovery_only,
                "published payload reconciled but prior stage retained; fresh restore-recover authority required"
            );
            recover_attempt(e, &r, true)?;
        }
        println!("slot92447542 matching restored destination reconciled");
        return Ok(());
    }
    ensure!(
        absent(&completed)?,
        "restore receipt exists but destination disappeared"
    );
    let attempt = cache.path.join(format!(".{}", r.attempt));
    let intent = state.path.join(format!("{}-intent.json", r.attempt));
    if !absent(&intent)? {
        ensure!(
            recovery_only,
            "prior attempt retained; separately admitted restore-recover is required"
        );
        recover_attempt(e, &r, false)?;
        println!("slot92447542 prior attempt reconciled; fresh restore attempt still required");
        return Ok(());
    }
    ensure!(
        !recovery_only,
        "no prior attempt intent exists for recovery"
    );
    let a = e.restore_admission(verified)?;
    ensure!(
        e.available_bytes(&cache.path)?
            >= a.protected_floor_bytes
                .checked_add(
                    e.object()
                        .bytes()
                        .checked_add(SLACK)
                        .context("restore size overflow")?
                )
                .context("restore reservation overflow")?,
        "full restore does not fit above protected floor"
    );
    e.consumers()?;
    let before_metadata = e.metadata()?;
    ensure!(
        absent(&attempt)?,
        "attempt without its original intent is retained"
    );
    let intent_value = encoded(
        e,
        &json!({"schema":"jetstreamer-snapshot92447542-restore-attempt-intent-v1","self_sha256":self_sha,"plan_sha256":plan_sha,"check_sha256":check_sha,"attempt":attempt,"verified_sha256":verified,"admission_sha256":r.admission_sha256,"metadata_before_sha256":sha(&before_metadata),"original_owner":{"unit":a.owner.unit,"invocation_id":a.owner.invocation_id,"exec_start":a.owner.exec_start}}),
    );
    put(e, &intent, &intent_value)?;
    e.after_phase(Phase::RestoreIntentDurable)?;
    fs::create_dir(&attempt)?;
    fs::set_permissions(&attempt, fs::Permissions::from_mode(0o700))?;
    let adir = File::open(&attempt)?;
    chown(&adir, 1000, 1000)?;
    adir.sync_all()?;
    cache.sync()?;
    e.after_phase(Phase::RestoreStageDurable)?;
    let aid = DirectoryIdentity::of(&adir.metadata()?);
    let mut dir = Directory::open(&attempt, &aid)?;
    let owned = state.path.join(format!("{}-stage-owned.json", r.attempt));
    put(
        e,
        &owned,
        &json!({"schema":"jetstreamer-snapshot92447542-restore-stage-owned-v1","attempt_intent":reference(&intent)?,"attempt":attempt,"identity":aid,"original_owner":{"unit":a.owner.unit,"invocation_id":a.owner.invocation_id,"exec_start":a.owner.exec_start}}),
    )?;
    e.after_phase(Phase::RestoreStageOwnedDurable)?;
    let start = Instant::now();
    let mut owned_sdk: Option<OwnedSdk> = None;
    let transfer = (|| -> Result<(Identity, Digests)> {
        guard(e, &dir, &a, start, r.maximum_runtime_seconds)?;
        owned_sdk = Some(e.spawn_download(&attempt.join(NAME))?);
        e.after_phase(Phase::RestoreChildSpawned)?;
        let child = owned_sdk.as_mut().context("owned SDK missing")?;
        let mut heartbeat = Instant::now();
        loop {
            guard(e, &dir, &a, start, r.maximum_runtime_seconds)?;
            if child.exited()? {
                break;
            }
            if heartbeat.elapsed() >= Duration::from_secs(60) {
                println!(
                    "slot92447542 transfer heartbeat staged_bytes={}",
                    staged_bytes(&dir)?
                );
                heartbeat = Instant::now();
            }
            thread::sleep(Duration::from_secs(1));
        }
        ensure!(
            child.finish()?.success(),
            "exact-generation transfer failed"
        );
        let remaining = process_references::scan(Path::new("/proc"), &attempt)?;
        ensure!(
            remaining.references.is_empty(),
            "SDK descendant remains after leader reap"
        );
        freeze_stage(&mut dir)?;
        e.after_phase(Phase::RestoreStageFrozen)?;
        let file = dir.open_file(NAME)?;
        let m = file.metadata()?;
        ensure!(
            m.is_file()
                && m.uid() == 1000
                && m.gid() == 1000
                && m.nlink() == 1
                && m.len() == e.object().bytes(),
            "unsafe SDK output"
        );
        chown(&file, 0, 0)?;
        file.set_permissions(fs::Permissions::from_mode(0o444))?;
        file.sync_all()?;
        dir.sync()?;
        e.after_phase(Phase::RestorePayloadFrozen)?;
        let (i, d, _) = hash_object(e, &dir, NAME, None, Some(verified), || {
            guard(e, &dir, &a, start, r.maximum_runtime_seconds)
        })?;
        let after_metadata = e.metadata()?;
        e.validate_metadata(&serde_json::from_slice::<Value>(&after_metadata)?)?;
        guard(e, &dir, &a, start, r.maximum_runtime_seconds)?;
        e.history()?;
        e.consumers()?;
        let pi = encoded(
            e,
            &json!({"schema":"jetstreamer-snapshot92447542-restore-publish-intent-v1","self_sha256":self_sha,"plan_sha256":plan_sha,"check_sha256":check_sha,"attempt_intent":reference(&intent)?,"identity":i,"verified_sha256":verified,"metadata_before_sha256":sha(&before_metadata),"metadata_after_sha256":sha(&after_metadata),"admission_sha256":r.admission_sha256}),
        );
        put(e, &publish_intent, &pi)?;
        e.after_phase(Phase::RestorePublishIntentDurable)?;
        ensure!(cache.absent(NAME)?, "destination appeared during transfer");
        rename_noreplace(&dir, NAME, cache, NAME)?;
        e.after_phase(Phase::RestorePublishRenameDurable)?;
        Ok((i, d))
    })();
    match transfer {
        Ok((i, d)) => {
            let after = Identity::of(&fs::symlink_metadata(cache.path.join(NAME))?);
            ensure!(after.renamed_from(&i), "published inode differs");
            let receipt = encoded(
                e,
                &json!({"schema":"jetstreamer-snapshot92447542-restored-v1","self_sha256":self_sha,"plan_sha256":plan_sha,"check_sha256":check_sha,"uri":URI,"generation":GENERATION,"new_identity":after,"digests":d,"publication_intent":reference(&publish_intent)?,"original_historical_receipt_preserved":true,"consumers_must_bind_new_receipt":true,"remote_mutations":false,"r2_mutations":false}),
            );
            put(e, &completed, &receipt)?;
            e.after_phase(Phase::RestoreReceiptDurable)?;
            cleanup_attempt(&mut dir)?;
            e.after_phase(Phase::RestoreStageCleaned)?;
            println!("slot92447542 restore committed with new inode receipt");
            Ok(())
        }
        Err(error) => {
            #[cfg(test)]
            if error.downcast_ref::<FixtureInterruption>().is_some() {
                stop_owned_sdk(&mut owned_sdk)?;
                return Err(error);
            }
            // The transport owner lives outside the transfer closure. Drop is
            // too late here: it would run only after recording and cleaning the
            // failed attempt. Reap its exact group before claiming shutdown.
            stop_owned_sdk(&mut owned_sdk)?;
            let refs = process_references::scan(Path::new("/proc"), &attempt)?;
            ensure!(
                refs.references.is_empty(),
                "SDK descendant still references failed attempt; preserve it"
            );
            let failed = state
                .path
                .join(format!("{}-failure-intent.json", r.attempt));
            put(
                e,
                &failed,
                &json!({"schema":"jetstreamer-snapshot92447542-restore-failure-intent-v1","attempt_intent":reference(&intent)?,"owned_SDK_group_checked_stopped_and_leader_reaped_before_cleanup":true,"attempt_identity":dir.identity,"canonical_destination_absent":cache.absent(NAME)?,"new_receipt_absent":absent(&completed)?,"error_class":"transfer-or-integrity-or-capacity-gate-failed"}),
            )?;
            e.after_phase(Phase::RestoreFailureIntentDurable)?;
            ensure!(
                cache.absent(NAME)? && absent(&completed)?,
                "publication boundary crossed; preserve stage for receipt recovery"
            );
            cleanup_attempt(&mut dir)?;
            e.after_phase(Phase::RestoreFailureStageCleaned)?;
            put(
                e,
                &state
                    .path
                    .join(format!("{}-failure-completion.json", r.attempt)),
                &json!({"schema":"jetstreamer-snapshot92447542-restore-failure-cleaned-v1","failure_intent":reference(&failed)?,"owned_temporary_absent":absent(&attempt)?,"canonical_destination_absent":true,"new_receipt_absent":true}),
            )?;
            e.after_phase(Phase::RestoreFailureCompletionDurable)?;
            Err(error)
        }
    }
}

#[cfg(test)]
#[derive(Debug)]
pub(super) struct FixtureInterruption(pub Phase);
#[cfg(test)]
impl std::fmt::Display for FixtureInterruption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ordinary fixture interrupted at {:?}", self.0)
    }
}
#[cfg(test)]
impl std::error::Error for FixtureInterruption {}

/// These are Root filesystem state-machine fixtures, not native lifecycle
/// receipts. They are opt-in because default ordinary module tests must remain
/// unprivileged and must not launch any child transport.
#[cfg(all(test, feature = "snapshot92447542-native-lifecycle-tests"))]
mod full_engine_fixtures {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::io::Write;
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Fault {
        None,
        TransferExit,
        Truncated,
        Oversized,
        BadDigest,
        StageSize,
        Timeout,
        LiveFloor,
        ReceiptCollision,
        DestinationCollision,
    }
    struct Fixture {
        _root: PathBuf,
        cache: Directory,
        state: Directory,
        source: Identity,
        object: ObjectSpec,
        bindings: Bindings,
        body: Vec<u8>,
        history: Bound,
        request: RefCell<Option<RestoreRequest>>,
        interrupt: Cell<Option<Phase>>,
        fault: Cell<Fault>,
        child_started: Cell<bool>,
        children: RefCell<Vec<u32>>,
        calls: RefCell<Vec<&'static str>>,
    }
    fn dir(path: &Path) -> Result<Directory> {
        Directory::open(path, &DirectoryIdentity::of(&fs::symlink_metadata(path)?))
    }
    impl Fixture {
        fn new() -> Result<Self> {
            ensure!(
                unsafe { libc::geteuid() } == 0,
                "full-engine filesystem fixtures require a separately admitted Root job"
            );
            let admitted_root = super::super::native_engine::fixture_gate()?;
            let root = tempfile::tempdir_in(admitted_root)?.keep();
            chown(&File::open(root.as_path())?, 1000, 1000)?;
            for (leaf, uid) in [("cache", 1000), ("state", 0)] {
                let p = root.as_path().join(leaf);
                fs::create_dir(&p)?;
                fs::set_permissions(&p, fs::Permissions::from_mode(0o700))?;
                chown(&File::open(&p)?, uid, uid)?;
            }
            let cache = dir(&root.as_path().join("cache"))?;
            let state = dir(&root.as_path().join("state"))?;
            let body = vec![b'X'; 8192];
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(cache.path.join(NAME))?;
            file.write_all(&body)?;
            chown(&file, 1000, 1000)?;
            file.sync_all()?;
            cache.sync()?;
            let source = Identity::of(&file.metadata()?);
            let history_path = state.path.join("ordinary-fixture-acquisition.json");
            persist(
                &history_path,
                &json!({"schema":"ordinary-fixture-acquisition-not-generation-evidence-v1","identity":source,"fixture_sha256":sha(&body),"fixture_bytes":body.len()}),
            )?;
            let h = reference(&history_path)?;
            let history = Bound {
                path: history_path,
                sha256: h["sha256"].as_str().context("history hash")?.into(),
            };
            let self_path = fs::canonicalize("/proc/self/exe")?;
            let (image, _) = evidence::hash_file(&self_path, 256 << 20)?;
            let session_path = state.path.join("ordinary-fixture-session.json");
            persist(
                &session_path,
                &json!({"schema":"ordinary-full-engine-fixture-session-v1","root":root.as_path(),"source":source,"actual_test_image_sha256":image,"native_lifecycle_qualified":false}),
            )?;
            let session = reference(&session_path)?;
            let policy_path = state.path.join("ordinary-fixture-reference-policy.json");
            persist(
                &policy_path,
                &json!({"schema":"ordinary-fixture-reference-policy-v1","root":root.as_path(),"production_scope":false}),
            )?;
            let policy = reference(&policy_path)?;
            let object = ObjectSpec::fixture(&body)?;
            let bindings = Bindings::fixture(
                session["sha256"].as_str().context("session hash")?,
                &image,
                policy["sha256"].as_str().context("policy hash")?,
                history.sha256.as_str(),
            )?;
            Ok(Self {
                _root: root,
                cache,
                state,
                source,
                object,
                bindings,
                body,
                history,
                request: RefCell::new(None),
                interrupt: Cell::new(None),
                fault: Cell::new(Fault::None),
                child_started: Cell::new(false),
                children: RefCell::new(vec![]),
                calls: RefCell::new(vec![]),
            })
        }
        fn check_and_evict(&self) -> Result<String> {
            run_check(self)?;
            let c = reference(&self.state.path.join(state_name("check")))?;
            let sha = c["sha256"].as_str().context("check hash")?.to_owned();
            run_evict(self, &sha)?;
            Ok(sha)
        }
        fn prepare_restore(&self) {
            self.request.replace(Some(RestoreRequest {
                attempt: "slot92447542-restore-ordinary-fixture".into(),
                maximum_runtime_seconds: if self.fault.get() == Fault::Timeout {
                    1
                } else {
                    30
                },
                admission_sha256: self.history.sha256.clone(),
            }));
        }
        fn assert_children_reaped(&self) -> Result<()> {
            for pid in self.children.borrow().iter() {
                let mut status = 0;
                ensure!(
                    unsafe { libc::waitpid(*pid as i32, &mut status, libc::WNOHANG) } == -1
                        && std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD),
                    "fixture child not reaped before completion"
                );
            }
            Ok(())
        }
    }
    impl Environment for Fixture {
        fn cache(&self) -> &Directory {
            &self.cache
        }
        fn state(&self) -> &Directory {
            &self.state
        }
        fn source_identity(&self) -> &Identity {
            &self.source
        }
        fn bindings(&self) -> &Bindings {
            &self.bindings
        }
        fn object(&self) -> &ObjectSpec {
            &self.object
        }
        fn history(&self) -> Result<Value> {
            self.calls.borrow_mut().push("history");
            evidence::bound_json(&self.history)
        }
        fn consumers(&self) -> Result<Value> {
            self.calls.borrow_mut().push("consumers");
            Ok(
                json!({"scope":"ordinary-fixture-boundary-not-native-consumer-evidence","root":self._root.as_path()}),
            )
        }
        fn metadata(&self) -> Result<Vec<u8>> {
            self.calls.borrow_mut().push("metadata");
            Ok(serde_json::to_vec(
                &json!({"schema":"ordinary-fixture-metadata-not-cloud-evidence-v1","bytes":self.body.len(),"sha256":sha(&self.body)}),
            )?)
        }
        fn validate_metadata(&self, v: &Value) -> Result<()> {
            ensure!(
                v["schema"] == "ordinary-fixture-metadata-not-cloud-evidence-v1"
                    && v["bytes"] == self.body.len()
                    && v["sha256"] == sha(&self.body),
                "fixture metadata changed"
            );
            Ok(())
        }
        fn restore_request(&self) -> Option<RestoreRequest> {
            self.request.borrow().clone()
        }
        fn restore_admission(&self, _: &str) -> Result<Booking> {
            self.calls.borrow_mut().push("admission");
            Ok(Booking {
                protected_floor_bytes: 1,
                owner: Owner {
                    unit: "ordinary-fixture-not-a-native-service.service".into(),
                    invocation_id: "0".repeat(32),
                    exec_start: "ordinary full-engine fixture transport".into(),
                },
                protected_owners: vec![],
            })
        }
        fn guard_owners(&self, _: &Booking) -> Result<()> {
            self.calls.borrow_mut().push("guard-owner");
            Ok(())
        }
        fn available_bytes(&self, p: &Path) -> Result<u64> {
            if self.fault.get() == Fault::LiveFloor && self.child_started.get() {
                Ok(0)
            } else {
                free_bytes(p)
            }
        }
        fn spawn_download(&self, destination: &Path) -> Result<OwnedSdk> {
            let payload = match self.fault.get() {
                Fault::Truncated => "short".into(),
                Fault::Oversized => "X".repeat(self.body.len() + 1),
                Fault::BadDigest => "Y".repeat(self.body.len()),
                Fault::StageSize => (self.object.bytes() + SLACK + 1).to_string(),
                _ => String::from_utf8(self.body.clone())?,
            };
            let script = match self.fault.get() {
                Fault::TransferExit => "printf '%s' \"$2\" >\"$1\"; exit 17",
                Fault::StageSize => r#"/usr/bin/truncate -s "$2" "$1"; exec /usr/bin/sleep 30"#,
                Fault::Timeout | Fault::LiveFloor => {
                    "exec 3>\"$1\"; printf '%s' \"$2\" >&3; exec /usr/bin/sleep 30"
                }
                _ => "printf '%s' \"$2\" >\"$1\"",
            };
            let mut c = Command::new("/bin/sh");
            c.env_clear()
                .args(["-c", script, "ordinary-fixture"])
                .arg(destination)
                .arg(payload)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            unsafe {
                c.pre_exec(|| {
                    if libc::setpgid(0, 0) != 0
                        || libc::setgroups(0, std::ptr::null()) != 0
                        || libc::setgid(1000) != 0
                        || libc::setuid(1000) != 0
                    {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let child = c.spawn()?;
            self.children.borrow_mut().push(child.id());
            self.child_started.set(true);
            Ok(OwnedSdk(Some(child)))
        }
        fn after_phase(&self, p: Phase) -> Result<()> {
            if p == Phase::RestorePublishIntentDurable {
                if self.fault.get() == Fault::ReceiptCollision {
                    persist(
                        &self.state.path.join(state_name("restored")),
                        &json!({"foreign":true}),
                    )?;
                }
                if self.fault.get() == Fault::DestinationCollision {
                    let mut f = OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(self.cache.path.join(NAME))?;
                    f.write_all(b"foreign destination")?;
                    f.sync_all()?;
                    self.cache.sync()?;
                }
            }
            if self.interrupt.get() == Some(p) {
                self.interrupt.set(None);
                return Err(FixtureInterruption(p).into());
            }
            Ok(())
        }
        fn authorize_recovery(
            &self,
            intent: &Value,
            stage: Option<&DirectoryIdentity>,
        ) -> Result<Value> {
            self.assert_children_reaped()?;
            ensure!(
                intent["attempt"]
                    .as_str()
                    .is_some_and(|p| Path::new(p).parent() == Some(self.cache.path.as_path())),
                "fixture recovery escaped cache"
            );
            Ok(
                json!({"scope":"ordinary simulated-interruption fixture; not native owner-terminal evidence","fixture_root":self._root.as_path(),"stage_identity":stage,"actual_transport_children_reaped":self.children.borrow().clone()}),
            )
        }
    }
    #[test]
    fn ordinary_full_engine_roundtrip_uses_shared_transactions_and_new_inode() -> Result<()> {
        let f = Fixture::new()?;
        let check = f.check_and_evict()?;
        f.prepare_restore();
        run_restore(&f, &check)?;
        f.assert_children_reaped()?;
        let restored = load(&f.state.path.join(state_name("restored")))?;
        ensure!(
            restored["schema"]
                == f.bindings
                    .schema("jetstreamer-snapshot92447542-restored-v1")
                && restored.get("plan_sha256").is_none()
                && restored.get("qualification_sha256").is_none()
                && restored["fixture_object"] == true,
            "fixture crossed production journal authority"
        );
        let after = Identity::of(&fs::symlink_metadata(f.cache.path.join(NAME))?);
        ensure!(
            after.inode != f.source.inode
                && after.uid == 0
                && after.gid == 0
                && after.mode & 0o7777 == 0o444,
            "full fixture restore did not create a new frozen inode"
        );
        let (_, d, _) = hash_object(
            &f,
            &f.cache,
            NAME,
            Some(&after),
            Some(&sha(&f.body)),
            || Ok(()),
        )?;
        ensure!(
            d.bytes == f.body.len() as u64,
            "restored fixture bytes differ"
        );
        Ok(())
    }
    #[test]
    fn ordinary_complete_eviction_replays_every_durable_frontier() -> Result<()> {
        for phase in [
            Phase::EvictionIntentDurable,
            Phase::QuarantineRenameDurable,
            Phase::MovedProofDurable,
            Phase::UnlinkIntentDurable,
            Phase::UnlinkDurable,
            Phase::EvictedDurable,
        ] {
            let f = Fixture::new()?;
            run_check(&f)?;
            let c = reference(&f.state.path.join(state_name("check")))?;
            let h = c["sha256"].as_str().context("check")?;
            f.interrupt.set(Some(phase));
            ensure!(
                run_evict(&f, h).is_err() && f.interrupt.get().is_none(),
                "requested eviction phase was never reached"
            );
            run_evict(&f, h)?;
            ensure!(
                f.cache.absent(NAME)? && f.state.absent(&format!("{PREFIX}-quarantine"))?,
                "recovered eviction retained payload"
            );
        }
        Ok(())
    }
    #[test]
    fn ordinary_complete_restore_reconciles_registered_durable_frontiers() -> Result<()> {
        for phase in [
            Phase::RestoreIntentDurable,
            Phase::RestoreStageDurable,
            Phase::RestoreStageOwnedDurable,
            Phase::RestoreChildSpawned,
            Phase::RestoreStageFrozen,
            Phase::RestorePayloadFrozen,
            Phase::RestorePublishIntentDurable,
            Phase::RestorePublishRenameDurable,
            Phase::RestoreReceiptDurable,
            Phase::RestoreStageCleaned,
        ] {
            let f = Fixture::new()?;
            let h = f.check_and_evict()?;
            f.prepare_restore();
            f.interrupt.set(Some(phase));
            ensure!(
                run_restore(&f, &h).is_err() && f.interrupt.get().is_none(),
                "requested restore phase was never reached"
            );
            run_recover_restore(&f, &h)?;
            f.assert_children_reaped()?;
            let attempt = f.cache.path.join(".slot92447542-restore-ordinary-fixture");
            ensure!(absent(&attempt)?, "recovery left an owned stage");
            if matches!(
                phase,
                Phase::RestorePublishRenameDurable
                    | Phase::RestoreReceiptDurable
                    | Phase::RestoreStageCleaned
            ) {
                ensure!(
                    !f.cache.absent(NAME)? && !absent(&f.state.path.join(state_name("restored")))?,
                    "published restore was lost"
                );
            } else {
                ensure!(
                    f.cache.absent(NAME)? && absent(&f.state.path.join(state_name("restored")))?,
                    "unpublished attempt was promoted"
                );
            }
        }
        Ok(())
    }
    #[test]
    fn ordinary_full_transfer_failures_shutdown_before_durable_cleanup() -> Result<()> {
        for fault in [
            Fault::TransferExit,
            Fault::Truncated,
            Fault::Oversized,
            Fault::BadDigest,
            Fault::StageSize,
            Fault::Timeout,
            Fault::LiveFloor,
        ] {
            let f = Fixture::new()?;
            let h = f.check_and_evict()?;
            f.fault.set(fault);
            f.prepare_restore();
            ensure!(run_restore(&f, &h).is_err(), "full transfer fault accepted");
            f.assert_children_reaped()?;
            ensure!(
                f.cache.absent(NAME)?
                    && absent(&f.state.path.join(state_name("restored")))?
                    && absent(&f.cache.path.join(".slot92447542-restore-ordinary-fixture"))?,
                "failed transfer published or retained owned stage"
            );
            let completed = load(
                &f.state
                    .path
                    .join("slot92447542-restore-ordinary-fixture-failure-completion.json"),
            )?;
            ensure!(
                completed["owned_temporary_absent"] == true,
                "cleanup receipt absent"
            );
        }
        Ok(())
    }
    #[test]
    fn ordinary_complete_restore_preserves_destination_and_receipt_collisions() -> Result<()> {
        for fault in [Fault::DestinationCollision, Fault::ReceiptCollision] {
            let f = Fixture::new()?;
            let h = f.check_and_evict()?;
            f.fault.set(fault);
            f.prepare_restore();
            ensure!(run_restore(&f, &h).is_err(), "collision accepted");
            f.assert_children_reaped()?;
            if fault == Fault::DestinationCollision {
                ensure!(
                    fs::read(f.cache.path.join(NAME))? == b"foreign destination",
                    "foreign destination changed"
                );
            } else {
                ensure!(
                    load(&f.state.path.join(state_name("restored")))? == json!({"foreign":true}),
                    "foreign receipt changed"
                );
            }
        }
        Ok(())
    }
    #[test]
    fn ordinary_failure_and_recovery_journals_replay_every_durable_frontier() -> Result<()> {
        for phase in [
            Phase::RestoreFailureIntentDurable,
            Phase::RestoreFailureStageCleaned,
            Phase::RestoreFailureCompletionDurable,
        ] {
            let f = Fixture::new()?;
            let h = f.check_and_evict()?;
            f.fault.set(Fault::TransferExit);
            f.prepare_restore();
            f.interrupt.set(Some(phase));
            ensure!(
                run_restore(&f, &h).is_err() && f.interrupt.get().is_none(),
                "failure frontier was never reached"
            );
            run_recover_restore(&f, &h)?;
            f.assert_children_reaped()?;
            ensure!(
                f.cache.absent(NAME)?
                    && absent(&f.cache.path.join(".slot92447542-restore-ordinary-fixture"))?,
                "failure recovery retained owned stage"
            );
        }
        for phase in [
            Phase::RestoreRecoveryIntentDurable,
            Phase::RestoreRecoveryStageCleaned,
            Phase::RestoreRecoveryCompletionDurable,
        ] {
            let f = Fixture::new()?;
            let h = f.check_and_evict()?;
            f.prepare_restore();
            f.interrupt.set(Some(Phase::RestoreStageOwnedDurable));
            ensure!(
                run_restore(&f, &h).is_err() && f.interrupt.get().is_none(),
                "initial fixture interruption was never reached"
            );
            f.interrupt.set(Some(phase));
            ensure!(
                run_recover_restore(&f, &h).is_err() && f.interrupt.get().is_none(),
                "recovery frontier was never reached"
            );
            run_recover_restore(&f, &h)?;
            f.assert_children_reaped()?;
            ensure!(
                f.cache.absent(NAME)?
                    && absent(&f.cache.path.join(".slot92447542-restore-ordinary-fixture"))?,
                "recovery replay retained owned stage"
            );
        }
        Ok(())
    }
    #[test]
    fn ordinary_complete_eviction_preserves_a_substituted_quarantine_inode() -> Result<()> {
        let f = Fixture::new()?;
        run_check(&f)?;
        let c = reference(&f.state.path.join(state_name("check")))?;
        let h = c["sha256"].as_str().context("check hash")?;
        f.interrupt.set(Some(Phase::QuarantineRenameDurable));
        ensure!(
            run_evict(&f, h).is_err() && f.interrupt.get().is_none(),
            "quarantine boundary not reached"
        );
        let q = format!("{PREFIX}-quarantine");
        rename_noreplace(&f.state, &q, &f.state, "preserved-source")?;
        let mut replacement = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(f.state.path.join(&q))?;
        replacement.write_all(&f.body)?;
        chown(&replacement, 1000, 1000)?;
        replacement.sync_all()?;
        f.state.sync()?;
        let replaced = Identity::of(&replacement.metadata()?);
        ensure!(run_evict(&f, h).is_err(), "substituted inode admitted");
        ensure!(
            Identity::of(&fs::symlink_metadata(f.state.path.join(&q))?) == replaced
                && fs::read(f.state.path.join("preserved-source"))? == f.body,
            "quarantine substitution removed a protected inode"
        );
        Ok(())
    }
}
