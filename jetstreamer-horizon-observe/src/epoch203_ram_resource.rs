//! Dormant private RAM entry benchmark. No imports, sidecars or remote writes.
//! Its auxiliary observer/fleet contract must be independently qualified before
//! a launch; no report is fabricated by this executable.
mod profile {
    pub const NATURAL_ROOT_FINISH: bool = false;
    pub const ARCHIVE_NAME: &str = "epoch-203-canary.jet";
    pub const PARENT_SHA: &str = "025757b9b337abf05435c427f143f590d9bfa542b5e4493aae783c158b4f2d3d";
    pub const RAYON_THREADS: u32 = 16;
    pub const EPOCH: u64 = 203;
    pub const TARGET: u64 = 87_720_000;
    pub const TERMINAL: u64 = 88_127_580;
    pub const INITIAL_REPLAY: u64 = 87_695_516;
    // This applies to the independently authenticated RAM volume, not root
    // disk headroom or an older producer's unbounded remaining-growth claim.
    pub const MINIMUM_FREE: u64 = 231_874_716_783 + (320 << 30);
    pub const MAX_SCRATCH: u64 = 192 << 30;
    pub const MAX_RUNTIME: u64 = 21600;
    pub const SNAPSHOT_SIZE: u64 = 8_142_103_526;
    pub const PLAN_SCHEMA: &str = "jetstreamer-private-epoch203-ram-bounded-runner-plan-v1";
    pub const RESULT_SCHEMA: &str = "jetstreamer-private-epoch203-ram-bounded-resource-v1";
    pub const STOP_SCHEMA: &str = "jetstreamer-private-epoch203-canary-target-stop-v1";
    pub const UNIT_PREFIX: &str = if cfg!(feature = "epoch203-ram-shrink-candidate") {
        "horizon-203-ram-resource-shrink-"
    } else {
        "horizon-203-ram-resource-baseline-"
    };
    pub const ROOT_PREFIX: &str = if cfg!(feature = "epoch203-ram-shrink-candidate") {
        "ram-resource-203-shrink-"
    } else {
        "ram-resource-203-baseline-"
    };
    pub const SNAPSHOT_NAME: &str =
        "snapshot-87695515-CYEr1vEwJyh2d4SSmnmYPYYj6EPhrDWTAJJCuzF2VhLX.tar.zst";
    pub const TERMINAL_NAME: &str =
        "snapshot-88127580-4SeHmKHQrHot4gwifo1bnvDKXZwGELk2vSenotTx9oqf.tar.zst";
    pub const CHECKPOINT_NAMES: &[&str] = &[SNAPSHOT_NAME, TERMINAL_NAME];
    pub const WORKER: &str = if cfg!(feature = "epoch203-ram-shrink-candidate") {
        "4aeca56378a4bb2c55d0e590c1e334c4afa6a375a2c0d94894b412bea261f1cc"
    } else {
        "3f5e8efec328b3e00dd9ce5ae396fc4067e6be6554e4da8831a13273186a748a"
    };
    pub const WORKER_ENV: &str = "JETSTREAMER_HISTORICAL_WORKER_V1_6_16";
    pub const SNAPSHOT: &str = "e45584858d0c825f095a43ff5e5909e62a68d197d39c042a76727454525228c4";
}
mod bounded_resource_runner {
    include!("../../jetstreamer-utils/src/bounded_resource_runner.rs");
    #[cfg(test)]
    legacy_profile_tests!();
}

use {
    anyhow::{Context, Result, ensure},
    bounded_resource_runner::{Plan, StorageHooks},
    jetstreamer_horizon_observe::{
        ram_replay_guard::{Binding, OwnedRamGuard},
        ram_replay_sandbox::{ReplayPhase, authenticate_replay},
    },
    serde::Deserialize,
    serde_json::{Value, json},
    sha2::{Digest, Sha256},
    std::{
        cell::RefCell,
        fs::{self, OpenOptions},
        io::Read,
        os::unix::fs::{MetadataExt, OpenOptionsExt},
        path::PathBuf,
        process::Command,
        time::{Duration, SystemTime, UNIX_EPOCH},
    },
};

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema: String,
    runner: Plan,
    sandbox: Value,
    observer: Bound,
    fleet: Bound,
    snapshot_success: Bound,
    cpu_stop: Bound,
    cpu_launch: Bound,
    auxiliary_contract: Bound,
}

#[derive(Clone)]
struct Evidence {
    observer: Value,
    fleet: Value,
    snapshot: Value,
    stop: Value,
    launch: Value,
    contract: Value,
}
impl Evidence {
    fn load(e: &Envelope) -> Result<Self> {
        let value = Self {
            observer: bound_json(&e.observer)?,
            fleet: bound_json(&e.fleet)?,
            snapshot: bound_json(&e.snapshot_success)?,
            stop: bound_json(&e.cpu_stop)?,
            launch: bound_json(&e.cpu_launch)?,
            contract: bound_json(&e.auxiliary_contract)?,
        };
        verify_contract_attestations(&value.contract)?;
        Ok(value)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Attestation {
    role: String,
    receipt: Bound,
    verifier_binary: Bound,
}

fn verify_contract_attestations(contract: &Value) -> Result<()> {
    let rows: Vec<Attestation> = serde_json::from_value(contract["attestations"].clone())?;
    ensure!(
        rows.len() == 3,
        "missing observer/fleet/retention attestations"
    );
    let mut roles = std::collections::BTreeSet::new();
    for a in rows {
        ensure!(
            ["observer", "fleet", "retention"].contains(&a.role.as_str())
                && roles.insert(a.role.clone()),
            "unknown/duplicate auxiliary attestation role"
        );
        bounded_resource_runner::bound_file(
            &a.verifier_binary.path,
            &a.verifier_binary.sha256,
            256 << 20,
        )?;
        let receipt = bound_json(&a.receipt)?;
        ensure!(
            receipt["schema"]
                == format!("jetstreamer-private-epoch203-ram-{}-capability-v1", a.role)
                && receipt["self_sha256"] == a.verifier_binary.sha256
                && receipt["passed"] == true
                && receipt["simulated"] == false
                && receipt["supervisor_profile"] == profile::PLAN_SCHEMA
                && receipt["worker_sha256"] == profile::WORKER
                && receipt["maximum_entry_replays"] == 4,
            "auxiliary capability tool/receipt binding differs"
        );
        for key in [
            "ordinary_replay_authorized",
            "runtime_promotion_authorized",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            ensure!(
                receipt[key] == false,
                "capability attestation grants unrelated authority"
            );
        }
    }
    Ok(())
}

fn bound_json(b: &Bound) -> Result<Value> {
    ensure!(
        b.sha256.len() == 64
            && b.sha256
                .bytes()
                .all(|n| n.is_ascii_digit() || (b'a'..=b'f').contains(&n))
            && b.path.is_absolute()
            && b.path.canonicalize()? == b.path,
        "invalid readable evidence binding"
    );
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&b.path)?;
    let before = f.metadata()?;
    ensure!(
        before.is_file()
            && before.uid() == 0
            && before.nlink() == 1
            && before.mode() & 0o222 == 0
            && before.len() <= 32 << 20,
        "evidence must be an immutable readable root-owned copy"
    );
    let mut bytes = Vec::new();
    (&mut f).take((32 << 20) + 1).read_to_end(&mut bytes)?;
    let id = |m: &fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.len(),
            m.uid(),
            m.gid(),
            m.mode(),
            m.nlink(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    };
    ensure!(
        bytes.len() as u64 == before.len()
            && id(&before) == id(&f.metadata()?)
            && id(&before) == id(&fs::symlink_metadata(&b.path)?)
            && format!("{:x}", Sha256::digest(&bytes)) == b.sha256,
        "readable evidence changed"
    );
    Ok(serde_json::from_slice(&bytes)?)
}

fn utc(s: &str) -> Result<u64> {
    ensure!(s.len() == 20 && s.is_ascii(), "noncanonical sample time");
    for (i, c) in s.bytes().enumerate() {
        let d = match i {
            4 | 7 => Some(b'-'),
            10 => Some(b'T'),
            13 | 16 => Some(b':'),
            19 => Some(b'Z'),
            _ => None,
        };
        ensure!(
            d.map_or_else(|| c.is_ascii_digit(), |d| c == d),
            "invalid sample time"
        );
    }
    let n = |a, b| s[a..b].parse::<i32>();
    let mut t: libc::tm = unsafe { std::mem::zeroed() };
    t.tm_year = n(0, 4)? - 1900;
    t.tm_mon = n(5, 7)? - 1;
    t.tm_mday = n(8, 10)?;
    t.tm_hour = n(11, 13)?;
    t.tm_min = n(14, 16)?;
    t.tm_sec = n(17, 19)?;
    let fields = (
        t.tm_year, t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec,
    );
    let seconds = unsafe { libc::timegm(&mut t) };
    ensure!(
        fields
            == (
                t.tm_year, t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec
            ),
        "normalized sample time"
    );
    Ok(u64::try_from(seconds)?)
}

const PRIMARY: [(&str, &str, &str, &str, &str); 3] = [
    (
        "216-219",
        "horizon-controller-216-219-cached-v5.service",
        "2b6ded8d8baf4f72a5c8a91385f7c278",
        "jetstreamer-root-sweep-horizon-216-219-cached-v5-e216-219-lane-b-1.service",
        "95fb05d1b78349bcb907c1e930e7682e",
    ),
    (
        "220-223",
        "horizon-controller-220-223-current-v1.service",
        "0b69b5009dc74bbda94b94d059a3daa7",
        "jetstreamer-root-sweep-horizon-220-223-current-v1-e220-223-lane-a-1.service",
        "c2adebaad0cb42b385156631156813fe",
    ),
    (
        "203-203",
        "horizon-qualify-203-root-prefix-resource-v1.service",
        "92e367eb7cf944a1825fe5a20d9243ca",
        "horizon-qualify-203-root-prefix-resource-v1.service",
        "92e367eb7cf944a1825fe5a20d9243ca",
    ),
];

fn validate_evidence(e: &Envelope, inputs: &Evidence, now: u64) -> Result<()> {
    let Evidence {
        observer: o,
        fleet: f,
        snapshot,
        stop,
        launch,
        contract,
    } = inputs;
    ensure!(
        e.schema == "jetstreamer-private-epoch203-ram-supervisor-plan-v1",
        "wrong RAM envelope"
    );
    ensure!(
        o["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && o["cadence"]["observation_reason"] == "routine"
            && o["cadence"]["minimum_interval_seconds"] == 1800
            && o["cadence"]["routine_minimum_interval_enforced"] == true,
        "not a routine v2 sample"
    );
    let at = utc(o["recorded_at_utc"]
        .as_str()
        .context("sample timestamp missing")?)?;
    ensure!(at <= now && now - at <= 1800, "stale/future RAM admission");
    for key in [
        "producer_or_controller_signals_sent",
        "service_state_changed",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(o["mutation"][key] == false, "mutating sample");
    }
    ensure!(
        o["host_memory"]["conservative_available_kib"]
            .as_u64()
            .and_then(|n| n.checked_mul(1024))
            .is_some_and(|n| n >= 864 << 30),
        "sample cannot reserve complete 320 GiB above 544 GiB"
    );
    let ordinary = o["replays"].as_array().context("ordinary census")?;
    let diagnostic = o["diagnostic_replays"]
        .as_array()
        .context("diagnostic census")?;
    ensure!(
        ordinary.len() == 2 && diagnostic.len() == 2,
        "primary census changed"
    );
    for (range, _, controller, _, producer) in PRIMARY {
        let matches: Vec<_> = ordinary
            .iter()
            .chain(diagnostic)
            .filter(|r| r["range"] == range)
            .collect();
        ensure!(matches.len() == 1, "missing/duplicate primary");
        let r = if matches[0].get("observation").is_some() {
            &matches[0]["observation"]
        } else {
            matches[0]
        };
        ensure!(r["invocation_binding_stable"] == true, "unstable primary");
        for point in ["before", "after"] {
            for (kind, id) in [("controller", controller), ("producer", producer)] {
                let v = &r[format!("{kind}_{point}")];
                ensure!(
                    v["invocation_id"] == id && v["restarts"] == 0 && v["active_state"] == "active",
                    "primary identity/state changed"
                );
            }
        }
    }
    let stopped: Vec<_> = diagnostic
        .iter()
        .filter(|r| r["range"] == "225-226")
        .collect();
    ensure!(
        stopped.len() == 1
            && stopped[0]["status"] == "unavailable"
            && stopped[0]["observation"].is_null()
            && stopped[0]["expected_producer_invocation_id"] == "ac9aee3d47eb41e483a5e008ed43d030",
        "225 is not stopped in sample"
    );
    ensure!(
        f["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
            && f["observer_sha256"] == e.observer.sha256
            && f["sampled_at_utc"] == o["recorded_at_utc"]
            && f["first_epoch"] == 201
            && f["last_epoch"] == 300
            && f["producer_mutations"] == false
            && f["remote_mutations"] == false,
        "unbound full fleet"
    );
    let active = f["active"].as_array().context("active claims")?;
    let mut counts = [0u64; 3];
    ensure!(active.len() == 9, "changed entry claim count");
    for a in active {
        let id = a["producer"]["InvocationID"]
            .as_str()
            .context("producer ID")?;
        let index = PRIMARY
            .iter()
            .position(|r| r.4 == id)
            .context("foreign primary claim")?;
        counts[index] += 1;
        ensure!(
            a["producer"]["ActiveState"] == "active" && a["producer"]["NRestarts"] == "0",
            "inactive/restarted claim"
        );
    }
    ensure!(counts == [4, 4, 1], "primary claim multiplicity changed");
    let ready: Vec<_> = f["inventory"]["entries"]
        .as_array()
        .context("inventory")?
        .iter()
        .filter(|e| e["state"] == "ready-pair")
        .collect();
    ensure!(
        f["inventory"]["anomalies"] == 0
            && f["inventory"]["ready_pairs"] == 6
            && ready
                .iter()
                .filter_map(|r| r["epoch"].as_u64())
                .collect::<Vec<_>>()
                == [201, 202, 206, 213, 214, 215],
        "century census changed"
    );
    let sum = ready
        .iter()
        .try_fold(0u64, |n, r| n.checked_add(r["archive_length"].as_u64()?))
        .context("century sum")?;
    ensure!(
        sum == 695_624_150_347
            && sum.checked_mul(2).context("floor overflow")?.div_ceil(6) == 231_874_716_783,
        "century floor changed"
    );
    ensure!(
        e.snapshot_success.sha256
            == "d0a18133eec2b9413d61ece231514cc023c0570f222a95503e6156777ffe7b91"
            && snapshot["schema"] == "jetstreamer-private-v1616-real-snapshot-tests-success-v1"
            && snapshot["passed"] == 2
            && snapshot["failed"] == 0
            && snapshot["child_exit_code"] == 0
            && snapshot["guard_trip"].is_null()
            && snapshot["entry_replay"] == false,
        "real snapshot gate absent"
    );
    ensure!(
        e.cpu_stop.sha256 == "407169f6ef6da54c5ffdab36a3664f7c7a21cba25bec489e73f0857bc2aaffa0"
            && e.cpu_launch.sha256
                == "66b9ce5c324bcf5cc2ffb3c56330809b6b831262133d4f4bccdcc1b030ca39e3"
            && stop["producer_invocation_id"] == "ac9aee3d47eb41e483a5e008ed43d030"
            && stop["terminal"]["active"] == "failed"
            && stop["terminal"]["pid"] == 0
            && stop["terminal"]["restarts"] == 0
            && launch["hard_limits"]["cpu_quota_cores"] == 16
            && launch["launched"] == true,
        "CPU release proof differs"
    );
    ensure!(
        contract["schema"] == "jetstreamer-private-epoch203-ram-auxiliary-capability-v1"
            && contract["passed"] == true
            && contract["simulated"] == false
            && contract["supervisor_profile"] == profile::PLAN_SCHEMA
            && contract["worker_sha256"] == profile::WORKER
            && contract["parent_sha256"] == profile::PARENT_SHA
            && contract["snapshot_sha256"] == profile::SNAPSHOT
            && contract["solana_rayon_threads"] == 16
            && contract["filesystem_backend"] == "persistent-tmpfs"
            && contract["root_archive_scratch_increment_bytes"] == 0
            && contract["private_epoch"] == 203
            && contract["target_slot"] == profile::TARGET
            && contract["terminal_root_slot"] == profile::TERMINAL
            && contract["maximum_entry_replays"] == 4
            && contract["maximum_auxiliary_diagnostics"] == 1
            && contract["ordinary_overlap_rejected"] == true
            && contract["existing_diagnostic_overlap_rejected"] == true
            && contract["same_epoch_private_auxiliary_census_verified"] == true
            && contract["persistent_artifact_lifecycle_verified"] == true,
        "auxiliary census/retention capability is unqualified"
    );
    for key in [
        "ordinary_replay_authorized",
        "runtime_promotion_authorized",
        "publication_authorized",
        "r2_mutations",
    ] {
        ensure!(
            contract[key] == false,
            "auxiliary capability grants unrelated authority"
        );
    }
    Ok(())
}

fn unit_check(unit: &str, id: &str, active: &str) -> Result<()> {
    let out = Command::new("/usr/bin/systemctl")
        .args([
            "show",
            unit,
            "--no-pager",
            "--no-ask-password",
            "--property=Id,InvocationID,ActiveState,MainPID,NRestarts,ControlGroup",
        ])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 65536,
        "unit inspection failed"
    );
    let raw = std::str::from_utf8(&out.stdout)?;
    for (k, v) in [
        ("Id", unit),
        ("InvocationID", id),
        ("ActiveState", active),
        ("NRestarts", "0"),
    ] {
        ensure!(
            raw.lines().filter(|l| *l == format!("{k}={v}")).count() == 1,
            "live unit binding changed"
        );
    }
    if active == "failed" {
        for expected in ["MainPID=0", "ControlGroup="] {
            ensure!(
                raw.lines().any(|l| l == expected),
                "stopped 225 has live resources"
            );
        }
    } else {
        let pid = raw
            .lines()
            .find_map(|l| l.strip_prefix("MainPID="))
            .context("MainPID missing")?
            .parse::<u64>()?;
        ensure!(
            pid > 1
                && raw
                    .lines()
                    .any(|l| l == format!("ControlGroup=/system.slice/{unit}")),
            "active primary has no bound process/cgroup"
        );
    }
    Ok(())
}

fn validate_live_census(units: &[Value], own: &str) -> Result<Vec<String>> {
    let mut allowed = std::collections::BTreeSet::new();
    allowed.insert(own.to_string());
    for (_, cu, _, pu, _) in PRIMARY {
        allowed.insert(cu.into());
        allowed.insert(pu.into());
    }
    let mut seen = std::collections::BTreeSet::new();
    for row in units {
        let name = row["unit"]
            .as_str()
            .context("discovered service lacks name")?;
        if allowed.contains(name) {
            ensure!(seen.insert(name.to_string()), "duplicate discovered owner");
            continue;
        }
        let entry_prefix = [
            "jetstreamer-root-sweep-",
            "horizon-controller-",
            "horizon-qualify-",
            "horizon-perf-epoch",
            "horizon-203-ram-resource-",
            "horizon-v1616-snapshot-test-",
            "horizon-203-ram-storage-probe-",
        ];
        ensure!(
            !entry_prefix.iter().any(|prefix| name.starts_with(prefix)),
            "unbound live entry/CPU owner {name}"
        );
        // Delivery of finished data takes precedence over a discretionary canary.
        ensure!(
            ![
                "horizon-publish-",
                "horizon-upload-",
                "horizon-full-verify-",
                "horizon-plugin-verify-"
            ]
            .iter()
            .any(|prefix| name.starts_with(prefix)),
            "delivery work takes priority over canary"
        );
    }
    ensure!(
        seen == allowed,
        "fresh live service census differs from exact 3 primary-plus-supervisor set"
    );
    Ok(seen.into_iter().collect())
}

fn live_census(own: &str) -> Result<Vec<String>> {
    let out = Command::new("/usr/bin/systemctl")
        .args([
            "list-units",
            "--type=service",
            "--state=running,activating",
            "--output=json",
            "--no-pager",
            "--no-ask-password",
        ])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 4 << 20,
        "fresh admission discovery failed"
    );
    validate_live_census(&serde_json::from_slice::<Vec<Value>>(&out.stdout)?, own)
}

#[derive(Default)]
struct RamStorage {
    storage_capability: bool,
    envelope: RefCell<Option<Envelope>>,
    guard: RefCell<Option<OwnedRamGuard>>,
}
impl StorageHooks for RamStorage {
    fn capability_only(&self) -> bool {
        self.storage_capability
    }
    fn decode_plan(&self, bytes: &[u8]) -> Result<Plan> {
        let envelope: Envelope = serde_json::from_slice(bytes)?;
        ensure!(
            envelope.schema == "jetstreamer-private-epoch203-ram-supervisor-plan-v1",
            "wrong envelope"
        );
        // Reject missing qualification before hashing multi-GiB replay inputs.
        // Repeat immediately before fork after all input/sandbox checks.
        if self.storage_capability {
            // Early actual sandbox authentication, before large input reads.
            // The shared runner will return from capability_result before its
            // only child-spawn/measurement call site, regardless of reports.
            authenticate_replay(
                &serde_json::to_vec(&envelope.sandbox)?,
                &envelope.runner.unit,
                &envelope.runner.run_root,
                ReplayPhase::BeforePreparation,
            )?;
        } else {
            let evidence = Evidence::load(&envelope)?;
            validate_evidence(
                &envelope,
                &evidence,
                SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            )?;
        }
        let p = envelope.runner.clone();
        *self.envelope.borrow_mut() = Some(envelope);
        Ok(p)
    }
    fn prepare(&self, p: &Plan) -> Result<()> {
        let borrow = self.envelope.borrow();
        let e = borrow.as_ref().context("RAM envelope absent")?;
        authenticate_replay(
            &serde_json::to_vec(&e.sandbox)?,
            &p.unit,
            &p.run_root,
            ReplayPhase::BeforePreparation,
        )?;
        Ok(())
    }
    fn configure_command(&self, p: &Plan, c: &mut Command) -> Result<()> {
        c.env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("TMPDIR", p.run_root.join("tmp"))
            .env("JETSTREAMER_ALLOW_CANDIDATE_RUNTIME", "1")
            .env("JETSTREAMER_HISTORICAL_TRACE", "1")
            .env("RUST_LOG", "info")
            .env("SOLANA_RAYON_THREADS", "16")
            .env(profile::WORKER_ENV, &p.worker);
        Ok(())
    }
    fn before_spawn(&self, p: &Plan, inv: &str) -> Result<Value> {
        let census_before = live_census(&p.unit)?;
        let borrow = self.envelope.borrow();
        let e = borrow.as_ref().context("RAM envelope absent")?;
        let evidence = Evidence::load(e)?;
        validate_evidence(
            e,
            &evidence,
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        )?;
        for (_, cu, ci, pu, pi) in PRIMARY {
            unit_check(cu, ci, "active")?;
            unit_check(pu, pi, "active")?;
        }
        unit_check(
            "horizon-qualify-225-natural-root-resource-63a2717-v1.service",
            "ac9aee3d47eb41e483a5e008ed43d030",
            "failed",
        )?;
        let sandbox = authenticate_replay(
            &serde_json::to_vec(&e.sandbox)?,
            &p.unit,
            &p.run_root,
            ReplayPhase::BeforeSpawn,
        )?;
        let census_after = live_census(&p.unit)?;
        ensure!(
            census_after == census_before,
            "entry owner census changed during admission"
        );
        *self.guard.borrow_mut() = Some(OwnedRamGuard::start(Binding {
            unit: p.unit.clone(),
            invocation_id: inv.into(),
            run_root: p.run_root.clone(),
            node: p.node.path.clone(),
            worker_sha256: profile::WORKER.into(),
        })?);
        Ok(
            json!({"sandbox":sandbox,"live_service_census":census_after,"observer_sha256":e.observer.sha256,"fleet_sha256":e.fleet.sha256,
            "auxiliary_contract_sha256":e.auxiliary_contract.sha256,"root_archive_scratch_increment_bytes":0,
            "full_cold_epoch_peak_qualified":false,"ordinary_replay_authorized":false,"publication_authorized":false}),
        )
    }
    fn guard(
        &self,
        _p: &Plan,
        _inv: &str,
        child: u32,
        elapsed: Duration,
        draining: bool,
    ) -> Result<()> {
        self.guard
            .borrow_mut()
            .as_mut()
            .context("RAM guard not armed")?
            .check(child, elapsed, draining)?;
        Ok(())
    }
    fn capability_result(
        &self,
        p: &Plan,
        inv: &str,
        bindings: &Value,
        command: &Command,
    ) -> Result<()> {
        ensure!(self.storage_capability, "not the no-entry capability path");
        let borrow = self.envelope.borrow();
        let e = borrow.as_ref().context("RAM envelope absent")?;
        let sandbox = authenticate_replay(
            &serde_json::to_vec(&e.sandbox)?,
            &p.unit,
            &p.run_root,
            ReplayPhase::BeforeSpawn,
        )?;
        let report = json!({"schema":"jetstreamer-private-epoch203-ram-supervisor-storage-capability-v1",
            "unit":p.unit,"invocation_id":inv,"self_sha256":bindings["self_sha256"],"plan":bindings,
            "profile":profile::PLAN_SCHEMA,"worker_sha256":profile::WORKER,"parent_sha256":profile::PARENT_SHA,
            "snapshot_sha256":profile::SNAPSHOT,"sandbox":sandbox,
            "command_program":command.get_program().to_string_lossy(),
            "command_args":command.get_args().map(|s|s.to_string_lossy().into_owned()).collect::<Vec<_>>(),
            "command_environment":command.get_envs().map(|(k,v)|(k.to_string_lossy().into_owned(),v.map(|s|s.to_string_lossy().into_owned())))
                .collect::<std::collections::BTreeMap<_,_>>(),
            "input_file_hashes_verified":true,"genesis_copy_verified":true,
            "auxiliary_contract_loaded":false,"host_memory_sample_taken":false,"live_fleet_inspected":false,
            "node_arguments_executed":false,"worker_ipc_qualified":false,"entry_replay":false,
            "guard_started":false,"fresh_admission_passed":false,"replay_launch_authorized":false,
            "full_cold_epoch_peak_qualified":false,"runtime_promotion_authorized":false,"publication_authorized":false,
            "retirement_authorized":false,"remote_mutations":false,"r2_mutations":false});
        let path = p
            .run_root
            .join("receipts/supervisor-storage-capability.json");
        bounded_resource_runner::persist(&path, &report)?;
        println!("{}", path.display());
        Ok(())
    }
}
fn main() {
    let storage_capability =
        std::env::args().next_back().as_deref() == Some("--storage-capability");
    bounded_resource_runner::main_with_storage(&RamStorage {
        storage_capability,
        ..RamStorage::default()
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Envelope, Evidence, u64) {
        let b = |sha: &str| Bound {
            path: "/sealed/receipt.json".into(),
            sha256: sha.into(),
        };
        let e = Envelope {
            schema: "jetstreamer-private-epoch203-ram-supervisor-plan-v1".into(),
            runner: Plan {
                schema: profile::PLAN_SCHEMA.into(),
                unit: format!("{}test.service", profile::UNIT_PREFIX),
                node: bounded_resource_runner::BoundFile {
                    path: "/sealed/node".into(),
                    sha256: profile::PARENT_SHA.into(),
                },
                worker: "/sealed/worker".into(),
                snapshot: format!("/sealed/{}", profile::SNAPSHOT_NAME).into(),
                ledger_directory: "/sealed".into(),
                epoch_hashes: bounded_resource_runner::BoundFile {
                    path: "/sealed/hashes".into(),
                    sha256: "b".repeat(64),
                },
                run_root: format!(
                    "/home/ubuntu/.jetstreamer-private/{}test",
                    profile::ROOT_PREFIX
                )
                .into(),
                target_slot: profile::TARGET,
                terminal_slot: profile::TERMINAL,
                minimum_free_bytes: profile::MINIMUM_FREE,
                maximum_runtime_seconds: profile::MAX_RUNTIME,
            },
            sandbox: json!({}),
            observer: b(&"a".repeat(64)),
            fleet: b(&"b".repeat(64)),
            snapshot_success: b("d0a18133eec2b9413d61ece231514cc023c0570f222a95503e6156777ffe7b91"),
            cpu_stop: b("407169f6ef6da54c5ffdab36a3664f7c7a21cba25bec489e73f0857bc2aaffa0"),
            cpu_launch: b("66b9ce5c324bcf5cc2ffb3c56330809b6b831262133d4f4bccdcc1b030ca39e3"),
            auxiliary_contract: b(&"c".repeat(64)),
        };
        let row = |(range, _, ci, _, pi): (&str, &str, &str, &str, &str)| {
            let mut v = json!({"range":range,"invocation_binding_stable":true});
            for at in ["before", "after"] {
                for (kind, id) in [("controller", ci), ("producer", pi)] {
                    v[format!("{kind}_{at}")] =
                        json!({"invocation_id":id,"active_state":"active","restarts":0});
                }
            }
            v
        };
        let ordinary = vec![row(PRIMARY[0]), row(PRIMARY[1])];
        let diagnostic = vec![
            json!({"range":"203-203","observation":row(PRIMARY[2])}),
            json!({"range":"225-226","status":"unavailable","observation":null,
                "expected_producer_invocation_id":"ac9aee3d47eb41e483a5e008ed43d030"}),
        ];
        let mut active = Vec::new();
        for (i, count) in [4, 4, 1].into_iter().enumerate() {
            for _ in 0..count {
                active.push(json!({"producer":{"InvocationID":PRIMARY[i].4,"ActiveState":"active","NRestarts":"0"}}));
            }
        }
        let ready = [
            (201, 102605729507u64),
            (202, 101842225683),
            (206, 108774749680),
            (213, 125368013231),
            (214, 128213350837),
            (215, 128820081409),
        ]
        .into_iter()
        .map(|(epoch, n)| json!({"epoch":epoch,"state":"ready-pair","archive_length":n}))
        .collect::<Vec<_>>();
        let o = json!({"schema":"jetstreamer-horizon-live-resource-sample-v2","recorded_at_utc":"2026-10-21T04:29:36Z",
            "cadence":{"observation_reason":"routine","minimum_interval_seconds":1800,"routine_minimum_interval_enforced":true},
            "mutation":{"producer_or_controller_signals_sent":false,"service_state_changed":false,"remote_mutations":false,"r2_mutations":false},
            "host_memory":{"conservative_available_kib":(864u64<<30)/1024},"replays":ordinary,"diagnostic_replays":diagnostic});
        let f = json!({"schema":"jetstreamer-horizon-campaign-fleet-v1","observer_sha256":e.observer.sha256,
            "sampled_at_utc":o["recorded_at_utc"],"first_epoch":201,"last_epoch":300,"producer_mutations":false,
            "remote_mutations":false,"active":active,"inventory":{"anomalies":0,"ready_pairs":6,"entries":ready}});
        let inputs = Evidence {
            observer: o,
            fleet: f,
            snapshot: json!({"schema":"jetstreamer-private-v1616-real-snapshot-tests-success-v1","passed":2,"failed":0,"child_exit_code":0,"guard_trip":null,"entry_replay":false}),
            stop: json!({"producer_invocation_id":"ac9aee3d47eb41e483a5e008ed43d030","terminal":{"active":"failed","pid":0,"restarts":0}}),
            launch: json!({"hard_limits":{"cpu_quota_cores":16},"launched":true}),
            // Synthetic shape only. This in-memory fixture is never a sealed
            // capability receipt or permission to launch the production canary.
            contract: json!({"schema":"jetstreamer-private-epoch203-ram-auxiliary-capability-v1","passed":true,
                "simulated":false,"supervisor_profile":profile::PLAN_SCHEMA,"private_epoch":203,"target_slot":profile::TARGET,
                "terminal_root_slot":profile::TERMINAL,"worker_sha256":profile::WORKER,"parent_sha256":profile::PARENT_SHA,
                "snapshot_sha256":profile::SNAPSHOT,"solana_rayon_threads":16,"filesystem_backend":"persistent-tmpfs",
                "root_archive_scratch_increment_bytes":0,"maximum_entry_replays":4,"maximum_auxiliary_diagnostics":1,
                "ordinary_overlap_rejected":true,"existing_diagnostic_overlap_rejected":true,
                "same_epoch_private_auxiliary_census_verified":true,"persistent_artifact_lifecycle_verified":true,
                "ordinary_replay_authorized":false,"runtime_promotion_authorized":false,"publication_authorized":false,"r2_mutations":false}),
        };
        (e, inputs, utc("2026-10-21T04:29:36Z").unwrap())
    }
    #[test]
    fn all_prerequisite_shapes_are_required_and_grant_no_publication() {
        let (e, inputs, at) = fixture();
        validate_evidence(&e, &inputs, at).unwrap();
        assert!(validate_evidence(&e, &inputs, at + 1801).is_err());
        assert!(validate_evidence(&e, &inputs, at - 1).is_err());
        for case in 0..12 {
            let mut i = inputs.clone();
            match case {
                0 => {
                    i.observer["host_memory"]["conservative_available_kib"] =
                        json!((864u64 << 30) / 1024 - 1)
                }
                1 => i.observer["replays"][0]["producer_after"]["invocation_id"] = json!("foreign"),
                2 => i.observer["diagnostic_replays"][1]["status"] = json!("observed"),
                3 => i.fleet["active"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"producer":{"InvocationID":"foreign"}})),
                4 => i.fleet["inventory"]["entries"][0]["archive_length"] = json!(1),
                5 => i.snapshot["passed"] = json!(1),
                6 => i.launch["hard_limits"]["cpu_quota_cores"] = json!(32),
                7 => i.contract["simulated"] = json!(true),
                8 => i.contract["same_epoch_private_auxiliary_census_verified"] = json!(false),
                9 => i.contract["persistent_artifact_lifecycle_verified"] = json!(false),
                10 => i.contract["publication_authorized"] = json!(true),
                _ => i.contract["worker_sha256"] = json!("foreign"),
            }
            assert!(
                validate_evidence(&e, &i, at).is_err(),
                "accepted case{case}"
            );
        }
    }
    #[test]
    fn fresh_service_census_detects_foreign_and_fifth_entry_owners() {
        let (e, _, _) = fixture();
        let mut names = std::collections::BTreeSet::new();
        names.insert(e.runner.unit.clone());
        for (_, cu, _, pu, _) in PRIMARY {
            names.insert(cu.into());
            names.insert(pu.into());
        }
        let rows = names
            .into_iter()
            .map(|n| json!({"unit":n}))
            .collect::<Vec<_>>();
        validate_live_census(&rows, &e.runner.unit).unwrap();
        assert!(validate_live_census(&rows[1..], &e.runner.unit).is_err());
        for name in [
            "horizon-203-ram-resource-foreign.service",
            "jetstreamer-root-sweep-unknown.service",
            "horizon-qualify-225-retry.service",
            "horizon-upload-216-live.service",
            "horizon-v1616-snapshot-test-other.service",
        ] {
            let mut bad = rows.clone();
            bad.push(json!({"unit":name}));
            assert!(
                validate_live_census(&bad, &e.runner.unit).is_err(),
                "accepted{name}"
            );
        }
    }
    #[test]
    fn child_environment_has_only_explicit_runtime_and_ram_paths() {
        let (e, _, _) = fixture();
        let mut cmd = Command::new("/sealed/node");
        cmd.env("HORIZON_ACCESS_KEY_ID", "fixture-never-production")
            .env("TMPDIR", "/unbound");
        RamStorage::default()
            .configure_command(&e.runner, &mut cmd)
            .unwrap();
        let env = cmd
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_str().unwrap().to_string(),
                    v.map(|s| s.to_string_lossy().into_owned()),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        assert!(!env.contains_key("HORIZON_ACCESS_KEY_ID"));
        assert_eq!(
            env["TMPDIR"],
            Some(e.runner.run_root.join("tmp").display().to_string())
        );
        assert_eq!(
            env[profile::WORKER_ENV],
            Some(e.runner.worker.display().to_string())
        );
        assert_eq!(env["SOLANA_RAYON_THREADS"], Some("16".into()));
    }
    #[test]
    fn capability_boolean_alone_cannot_substitute_for_qualified_tools() {
        let (_, i, _) = fixture();
        assert!(verify_contract_attestations(&i.contract).is_err());
        let mut value = i.contract;
        value["attestations"] = json!([]);
        assert!(verify_contract_attestations(&value).is_err());
        value["attestations"] = json!([{"role":"observer","receipt":{"path":"/missing/receipt","sha256":"a".repeat(64)},
            "verifier_binary":{"path":"/missing/tool","sha256":"b".repeat(64)}}]);
        assert!(verify_contract_attestations(&value).is_err());
    }
}
