//! Closed original-prefix terminal proofs, distinct from continuation success.
//! Cleared PID 1 display fields are accepted only with the exact six preserved
//! primary inputs. No archive/snapshot body or asserted future proof is used.
use super::*;

const NODE: &str = "025757b9b337abf05435c427f143f590d9bfa542b5e4493aae783c158b4f2d3d";
const WORKER: &str = "4aeca56378a4bb2c55d0e590c1e334c4afa6a375a2c0d94894b412bea261f1cc";
const SCHEMA: &str = "jetstreamer-capped204205-original-terminal-evidence-v1";

#[derive(Clone, Copy)]
struct Profile {
    epoch: u64,
    unit: &'static str,
    iid: &'static str,
    root: &'static str,
    pid: u64,
    bootstrap: u64,
    start: u64,
    restart: u64,
    bytes: u64,
    archive: &'static str,
    runner: &'static str,
    resource: &'static str,
    snapshot: &'static str,
    hashes: [&'static str; 6],
}
fn profile(epoch: u64) -> Result<Profile> {
    Ok(match epoch {
        204 => Profile {
            epoch,
            unit: "horizon-qualify-204-shrink-root-prefix-resource-fcbf3992-v1.service",
            iid: "448da7f2a3a34217afe7e115120b3cea",
            root: "/home/ubuntu/.jetstreamer-private/shrink-root-prefix-resource-204-fcbf3992-v1",
            pid: 3_822_861,
            bootstrap: 88_127_580,
            start: 88_128_000,
            restart: 88_559_361,
            bytes: 103_318_151_802,
            archive: "08351adefb3ef0d693f12bb9c978f48caa1c56d32456d335a2ae52a1969b27c2",
            runner: "1cd9bfe3418616add2319802adc4caf66b86e3f6fdf6c903c4be2648b10c0baa",
            resource: "cc5109ed54c4b5cdc7db99a7e839708753b677cee11b7ca867c30e7a198911ba",
            snapshot: "d3114597ce25c3efaa4a96899ab3e9437c51cb9086d4166639f0ad2ae0613ee6",
            hashes: [
                "a1b38f09bb1314c9280ca924602bab1523d28755146919912f604c1ee9bbfdfb",
                "a650179aadb678475386b680b49147f73e89cfd824226eba5cf4c1e2b1f21818",
                "1d9e76ecd887a532c1e74bff1ad1e122920c5f82ee4740729f61a1d0d23ebb3c",
                "90d8963d050ce5399d31dfba54bb8b587eabda73145f4f6f2483e7d77a40a33a",
                "997219e44a8150938b817539bf9569df27691f0d4713e64d30c2bdeb4399d90a",
                "0389850c8ca279e75e82599eca63417f39951bfbd55a5bd7c57f2a8152fb1bd8",
            ],
        },
        205 => Profile {
            epoch,
            unit: "horizon-qualify-205-shrink-root-prefix-resource-5c01bf93-v1.service",
            iid: "373359a11aef4993a1a949e19ff617c3",
            root: "/home/ubuntu/.jetstreamer-private/shrink-root-prefix-resource-205-5c01bf93-v1",
            pid: 3_730_044,
            bootstrap: 88_559_361,
            start: 88_560_000,
            restart: 88_991_050,
            bytes: 104_571_676_001,
            archive: "3188ea5552b65b0ef7ef0de7876b04b98b7bd31c1c1bb2f73667e61050fac138",
            runner: "fb41a1193c86749db27ef609f487a25de334a7e58b3440093288aecc75ae4801",
            resource: "7dd71710d60017224fd1f6fabd97f228642b687802da98a11f8927aea67b6485",
            snapshot: "24b722b37fa87462876dc05916bafa98da13f095c95aaed7159e9008efa7352e",
            hashes: [
                "febbbb44b1d2b16afc3511e171dbb1f1aab732890893be1ce2f72239bc01ca9e",
                "1298a50d00ca349bae8328b640718d601c37692071ea5c3cf53ba072386418fb",
                "fc4db348159b76d87aac5600bfd15cad52db98ee8cfc9e9f365fd9130863211c",
                "d39320d8f233113a93129ae7dc5d9bace6868b57ec0859f6e6f10375c26a2a69",
                "072f491c13dc7082d4715ac515dcb8203449e0d42b9e86a11ee198eb9d03cd85",
                "f6a3256c86833bc4e7e606556cac40b270f796c9bdd88ee4df78e640c9df0375",
            ],
        },
        _ => bail!("original terminal proof is closed to exact epochs 204 and 205"),
    })
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    original_launch: BoundFile,
    producer_result: BoundFile,
    terminal_properties: BoundFile,
    manager_journal: BoundFile,
    prefix_manifest: BoundFile,
    prefix_validation: BoundFile,
}
impl Metadata {
    fn bounds(&self) -> [&BoundFile; 6] {
        [
            &self.original_launch,
            &self.producer_result,
            &self.terminal_properties,
            &self.manager_journal,
            &self.prefix_manifest,
            &self.prefix_validation,
        ]
    }
    fn check(&self, p: Profile) -> Result<()> {
        for (b, sha) in self.bounds().into_iter().zip(p.hashes) {
            ensure!(
                b.sha256 == sha && b.path.is_absolute(),
                "original terminal primary binding differs"
            );
        }
        Ok(())
    }
}
struct Sources {
    launch: Value,
    result: Value,
    terminal: Value,
    manifest: Value,
    reader: Value,
    journal: Vec<u8>,
}
struct Proof {
    p: Profile,
    launch: Value,
    started_ms: u64,
    ended_seconds: u64,
}
fn string<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key]
        .as_str()
        .with_context(|| format!("original terminal missing string: {key}"))
}
fn bytes(b: &BoundFile) -> Result<Vec<u8>> {
    let m = fs::symlink_metadata(&b.path)?;
    ensure!(
        b.path.canonicalize()? == b.path
            && m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0,
        "original primary is not immutable root-owned regular evidence"
    );
    let raw = read_stable_bounded(&b.path, 4 << 20, "original capped primary metadata")?;
    let after = fs::symlink_metadata(&b.path)?;
    ensure!(
        hex_lower(&Sha256::digest(&raw)) == b.sha256
            && identity(&m) == identity(&after)
            && m.uid() == after.uid()
            && m.mode() == after.mode()
            && after.nlink() == 1,
        "original primary changed or digest differs"
    );
    Ok(raw)
}
fn authenticate(epoch: u64, metadata: &Value) -> Result<Proof> {
    let p = profile(epoch)?;
    let m: Metadata = serde_json::from_value(metadata.clone())?;
    m.check(p)?;
    let read = |b: &BoundFile| -> Result<Value> { Ok(serde_json::from_slice(&bytes(b)?)?) };
    verify(
        p,
        Sources {
            launch: read(&m.original_launch)?,
            result: read(&m.producer_result)?,
            terminal: read(&m.terminal_properties)?,
            manifest: read(&m.prefix_manifest)?,
            reader: read(&m.prefix_validation)?,
            journal: bytes(&m.manager_journal)?,
        },
    )
}
fn command_identity(command: &str) -> Option<&str> {
    let (identity, display) = command.split_once(" ; start_time=")?;
    (identity.starts_with("{ path=")
        && identity.matches(" ; argv[]=").count() == 1
        && identity.ends_with(" ; ignore_errors=no")
        && display.ends_with(" }"))
    .then_some(identity)
}
fn terminal_shape(p: Profile, launch: &Value, u: &Value, full: bool) -> Result<()> {
    ensure!(
        u["Id"] == p.unit
            && u["MainPID"] == "0"
            && u["NRestarts"] == "0"
            && u["ActiveState"] == "inactive"
            && u["SubState"] == "dead"
            && u["ControlGroup"] == "",
        "original owner is active, pending, replaced or ambiguous"
    );
    if u["LoadState"] == "not-found" {
        ensure!(
            u["InvocationID"] == "" && u["ExecStart"] == "",
            "collected original retains identity or command"
        );
        return Ok(());
    }
    ensure!(
        u["LoadState"] == "loaded"
            && u["Type"] == "exec"
            && u["Result"] == "success"
            && u["ExecMainStatus"] == "0",
        "original owner did not naturally succeed"
    );
    ensure!(
        command_identity(string(u, "ExecStart")?)
            .zip(command_identity(string(launch, "expected_exec_start")?))
            .is_some_and(|(a, b)| a == b),
        "original owner command changed"
    );
    if u["InvocationID"] == "" {
        ensure!(
            string(u, "ExecStart")?.ends_with(
                " ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }"
            ),
            "cleared original has non-collected execution display"
        );
        if full {
            ensure!(
                u["ExecMainPID"] == "0" && u["ExecMainCode"] == "0",
                "original collected counters differ"
            );
        }
    } else {
        ensure!(
            u["InvocationID"] == p.iid,
            "another original invocation owns the unit"
        );
        if full {
            let expected_pid = p.pid.to_string();
            ensure!(
                u["ExecMainPID"].as_str() == Some(expected_pid.as_str())
                    && u["ExecMainCode"] == "1",
                "original retained exit differs"
            );
        }
    }
    if full {
        ensure!(
            u["Restart"] == "no" && u["Triggers"] == "" && u["TriggeredBy"] == "",
            "original has restart or trigger authority"
        );
    }
    Ok(())
}
fn journal(p: Profile, raw: &[u8]) -> Result<(u64, u64)> {
    ensure!(
        !raw.is_empty() && raw.len() <= 4 << 20,
        "original manager journal bound"
    );
    let mut rows = Vec::new();
    let mut cursors = BTreeSet::new();
    let mut last = 0;
    for line in std::str::from_utf8(raw)?.lines() {
        let v: Value = serde_json::from_str(line)?;
        let at = string(&v, "__REALTIME_TIMESTAMP")?.parse::<u64>()?;
        let boot = string(&v, "_BOOT_ID")?;
        ensure!(
            v["_PID"] == "1"
                && v["_UID"] == "0"
                && v["UNIT"] == p.unit
                && at > 0
                && at >= last
                && !string(&v, "__CURSOR")?.is_empty()
                && cursors.insert(string(&v, "__CURSOR")?.to_owned())
                && boot.len() == 32
                && boot
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
            "original manager identity, boot, clock or cursor differs"
        );
        last = at;
        rows.push((at, v));
        ensure!(rows.len() <= 16384, "original manager row bound");
    }
    let starts = rows
        .iter()
        .filter(|(_, r)| {
            r["INVOCATION_ID"] == p.iid
                && r["MESSAGE_ID"] == "39f53479d3a045ac8e11786248231fbf"
                && r["MESSAGE"]
                    .as_str()
                    .is_some_and(|s| s.starts_with(&format!("Started {} -", p.unit)))
        })
        .collect::<Vec<_>>();
    let ends = rows
        .iter()
        .filter(|(_, r)| {
            r["INVOCATION_ID"] == p.iid
                && r["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448"
                && r["MESSAGE"] == format!("{}: Deactivated successfully.", p.unit)
        })
        .collect::<Vec<_>>();
    ensure!(
        starts.len() == 1 && ends.len() == 1 && starts[0].0 < ends[0].0,
        "original exact PID 1 start/natural success missing"
    );
    for (_, r) in rows.iter().filter(|(at, _)| *at >= starts[0].0) {
        let message = string(r, "MESSAGE")?;
        ensure!(
            r["INVOCATION_ID"] == p.iid
                && r["_BOOT_ID"] == starts[0].1["_BOOT_ID"]
                && !message.starts_with("Stopping ")
                && !message.starts_with("Stopped ")
                && !message.contains(": Failed")
                && !message.contains(": Killing")
                && r.get("EXIT_STATUS").is_none_or(|v| v.is_null() || v == "0"),
            "original journal shows stop, failure or replacement"
        );
    }
    Ok((starts[0].0 / 1000, ends[0].0 / 1_000_000))
}
fn verify(p: Profile, s: Sources) -> Result<Proof> {
    let l = &s.launch;
    let r = &s.result;
    let m = &s.manifest;
    let v = &s.reader;
    ensure!(
        l["schema"]
            == format!(
                "jetstreamer-private-epoch{}-capped-root-prefix-launch-v1",
                p.epoch
            )
            && l["epoch"] == p.epoch
            && l["launched"] == true
            && l["private_run_root"] == p.root
            && l["node_sha256"] == NODE
            && l["worker_sha256"] == WORKER
            && l["runner_sha256"] == p.runner
            && l["plan_sha256"] == p.resource
            && l["snapshot_sha256"] == p.snapshot
            && l["bootstrap_slot"] == p.bootstrap
            && l["output_slot_start"] == p.start
            && l["output_slot_count"] == p.restart - p.start + 1
            && l["terminal_root_slot"] == p.restart
            && l["natural_parent_completion_required"] == true,
        "original launch profile changed"
    );
    ensure!(
        r["schema"]
            == format!(
                "jetstreamer-private-epoch{}-shrink-root-prefix-resource-v1",
                p.epoch
            )
            && r["epoch"] == p.epoch
            && r["unit"] == p.unit
            && r["invocation_id"] == p.iid
            && r["success"] == true
            && r["error"].is_null()
            && r["child_return_code"] == 0
            && r["external_signal"] == 0
            && r["natural_parent_completion_required"] == true
            && r["node_sha256"] == NODE
            && r["worker_sha256"] == WORKER
            && r["runner_sha256"] == p.runner
            && r["plan"]["sha256"] == p.resource
            && r["snapshot_sha256"] == p.snapshot
            && r["archive_length"] == p.bytes
            && r["producer_segment_manifest_sha256"] == p.hashes[4]
            && r["producer_segment_manifest"] == *m
            && r["target_slot"] == p.restart
            && r["terminal_root_slot"] == p.restart
            && r["producer_canonical_root_prefix_present"] == true,
        "original natural result or manifest changed"
    );
    for key in [
        "canonical_prefix_independently_qualified",
        "full_cold_epoch_peak_qualified",
        "ordinary_replay_authorized",
        "runtime_promotion_authorized",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(
            r["authority"][key] == false,
            "original result preclaims authority"
        );
    }
    let archive = format!("{}/output/epoch-{}-prefix.jet", p.root, p.epoch);
    ensure!(
        m["epoch"] == p.epoch
            && m["bootstrap"]["slot"] == p.bootstrap
            && m["output_slot_start"] == p.start
            && m["output_slot_count"] == p.restart - p.start + 1
            && m["terminal"]["slot"] == p.restart
            && m["terminal"]["slot_complete"] == true
            && m["archive_sha256"] == p.archive
            && m["worker_executable_sha256"] == WORKER
            && m["runtime"]["runtime_profile"] == "solana-v1.6.16"
            && m["runtime"]["runtime_revision"] == "86c26f843276581509c3434acc2efbf4202c44e0",
        "original prefix profile changed"
    );
    ensure!(
        v["schema"] == "jetstreamer-focused-qualification-artifact-validation-v1"
            && v["validation"] == "pass"
            && v["epoch"] == p.epoch
            && v["archive"] == archive
            && v["manifest"] == format!("{archive}.segment.json")
            && v["archive_sha256"] == p.archive
            && v["archive_bytes"] == p.bytes
            && v["output_slot_start"] == p.start
            && v["output_slot_count"] == p.restart - p.start + 1
            && v["bootstrap_slot"] == p.bootstrap
            && v["terminal_slot"] == p.restart
            && v["worker_executable_sha256"] == WORKER
            && v["runtime_profile"] == "solana-v1.6.16"
            && v["runtime_revision"] == m["runtime"]["runtime_revision"]
            && v["runtime_admission"] == "candidate"
            && v["canonical_checksum_sidecar_absent"] == true,
        "independent complete original reader changed"
    );
    terminal_shape(p, l, &s.terminal, true)?;
    let (started_ms, ended_seconds) = journal(p, &s.journal)?;
    Ok(Proof {
        p,
        launch: s.launch,
        started_ms,
        ended_seconds,
    })
}

pub(super) fn idle_for_plan(unit: &Value, p: &Value) -> Result<()> {
    let epoch = p["epoch"]
        .as_u64()
        .context("original proof plan epoch missing")?;
    if capped204205_admission::original_idle(unit, epoch).is_ok() {
        return Ok(());
    }
    ensure!(
        unit["LoadState"] == "loaded" && unit["InvocationID"] == "",
        "original owner is not the closed cleared-display fallback"
    );
    let proof = authenticate(epoch, &p["metadata"])?;
    terminal_shape(proof.p, &proof.launch, unit, false)
}

/// Closed repair namespaces are owners, never blanket census exemptions.
pub(super) fn repair_unit(name: &str, first: u64, last: u64) -> bool {
    [204, 205].into_iter().any(|e| {
        (first..=last).contains(&e)
            && [
                format!("horizon-capped204205-resource-probe-{e}-"),
                format!("horizon-capped{e}-"),
                format!("horizon-capped-native-input-{e}-"),
                format!("horizon-capped-capture-{e}-"),
                format!("horizon-guard-{e}-capped-continuation-"),
                format!("horizon-repair-{e}-"),
                format!("horizon-recover-{e}-"),
            ]
            .iter()
            .any(|prefix| name.starts_with(prefix))
            && name.ends_with(".service")
    })
}
fn epoch_unit(name: &str, epoch: u64) -> bool {
    repair_unit(name, epoch, epoch)
        || [
            "horizon-qualify-",
            "horizon-guard-",
            "horizon-publish-",
            "horizon-upload-",
            "horizon-full-verify-",
            "horizon-plugin-verify-",
            "horizon-independent-full-read-",
            "horizon-import-",
        ]
        .iter()
        .any(|prefix| name.starts_with(&format!("{prefix}{epoch}-")))
}
fn no_replacement(epoch: u64, current: &BTreeMap<String, Value>) -> Result<()> {
    let p = profile(epoch)?;
    for (name, u) in current
        .iter()
        .filter(|(name, _)| epoch_unit(name, epoch) && name.as_str() != p.unit)
    {
        ensure!(
            u["MainPID"] == "0"
                && matches!(u["ActiveState"].as_str(), Some("inactive" | "failed"))
                && matches!(u["SubState"].as_str(), Some("dead" | "failed")),
            "active or ambiguous repair/continuation owner blocks original status cleanup: {name}"
        );
    }
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TerminalEvidence {
    schema: String,
    epoch: u64,
    metadata: Value,
    archive_completion_claimed: bool,
    replay_launch_authorized: bool,
    publication_authorized: bool,
    remote_mutations: bool,
    r2_mutations: bool,
}
fn terminal_evidence(epoch: u64, e: &Value) -> Result<Proof> {
    let e: TerminalEvidence = serde_json::from_value(e.clone())?;
    ensure!(
        e.schema == SCHEMA
            && e.epoch == epoch
            && !e.archive_completion_claimed
            && !e.replay_launch_authorized
            && !e.publication_authorized
            && !e.remote_mutations
            && !e.r2_mutations,
        "original cleanup evidence scope or authority changed"
    );
    authenticate(epoch, &e.metadata)
}
pub(super) fn terminal_time(epoch: u64, e: &Value) -> Result<Option<u64>> {
    if e["schema"] != SCHEMA {
        return Ok(None);
    }
    Ok(Some(terminal_evidence(epoch, e)?.ended_seconds))
}
pub(super) fn terminal_current(
    epoch: u64,
    e: &Value,
    current: &BTreeMap<String, Value>,
    owners: &[(String, String)],
) -> Result<bool> {
    if e["schema"] != SCHEMA {
        return Ok(false);
    }
    let proof = terminal_evidence(epoch, e)?;
    let p = proof.p;
    ensure!(
        owners == [(p.unit.into(), p.iid.into())],
        "original cleanup publication owner changed"
    );
    terminal_shape(
        p,
        &proof.launch,
        current
            .get(p.unit)
            .context("original cleanup owner omitted")?,
        false,
    )?;
    no_replacement(epoch, current)?;
    // A current complete manager history independently rules out a later
    // invocation hidden by the cleared execution display. This is metadata only.
    let observed = ProcessCommand::new("/usr/bin/journalctl")
        .args([
            "--no-pager",
            "--output=json",
            "_PID=1",
            &format!("UNIT={}", p.unit),
        ])
        .output()?;
    ensure!(
        observed.status.success() && observed.stdout.len() <= 4 << 20,
        "original current manager history unavailable"
    );
    ensure!(
        journal(p, &observed.stdout)? == (proof.started_ms, proof.ended_seconds),
        "original manager lifecycle changed after sealed terminal proof"
    );
    let group = Path::new("/sys/fs/cgroup/system.slice").join(p.unit);
    match fs::symlink_metadata(&group) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
        Ok(m) => {
            ensure!(
                m.is_dir() && group.canonicalize()? == group,
                "redirected original cgroup"
            );
            let events = fs::read_to_string(group.join("cgroup.events"))?;
            ensure!(
                events.lines().any(|l| l == "populated 0"),
                "original cgroup or descendant remains populated"
            );
        }
    }
    let refs = jetstreamer_horizon_observe::process_references::scan(
        Path::new("/proc"),
        Path::new(p.root),
    )?;
    ensure!(
        refs.references.is_empty(),
        "original prefix still has live process references"
    );
    Ok(true)
}

#[cfg(test)]
mod tests;
