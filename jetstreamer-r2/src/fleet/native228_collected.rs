//! Exact collected native228 terminal recovery. Absence alone never qualifies.
use super::native228 as c;
use super::*;
const IID: &str = "1b207be826cc45979d5a92a44de4bd14";
const PID: u64 = 297588;
const ORIGIN: &str = "/var/lib/jetstreamer/horizon-228-native-capture-actual-v1/intent.json";
const ORIGIN_SHA: &str = "f53486f4fca27ae950f0af4412d262e5f1946769f2cdbe97ae62c8fc1193a349";
const JOURNAL: &str =
    "/var/lib/jetstreamer/horizon-native228-terminal-raw-1b207be8-v1/journal.json";
const JOURNAL_SHA: &str = "5894b7b9c0e612f8e10d984fe22a8d4087b3cca522d076f2d7ecd3b690325710";
const SCHEMA: &str = "jetstreamer-native228-collected-terminal-witness-v1";
fn original() -> BoundFile {
    BoundFile {
        path: ORIGIN.into(),
        sha256: ORIGIN_SHA.into(),
    }
}
fn raw_journal() -> BoundFile {
    BoundFile {
        path: JOURNAL.into(),
        sha256: JOURNAL_SHA.into(),
    }
}
fn scope(proof: &Value) -> Result<()> {
    ensure!(
        proof["running_origin"] == private157::binding(&original())
            && proof["journal"] == private157::binding(&raw_journal())
            && proof["unit"] == c::UNIT
            && proof["epoch"] == 228
            && proof["invocation_id"] == IID
            && proof["main_pid"] == PID,
        "228 collected recovery requires the exact actual origin, journal, IID and PID"
    );
    Ok(())
}
fn absent(u: &Value) -> Result<()> {
    ensure!(
        u["Id"] == c::UNIT
            && u["LoadState"] == "not-found"
            && u["ActiveState"] == "inactive"
            && u["SubState"] == "dead"
            && u["MainPID"] == "0"
            && u["InvocationID"] == ""
            && u["NRestarts"] == "0"
            && u["Result"] == "success"
            && u["ExecMainStatus"] == "0"
            && u.get("ExecStart").is_none_or(|v| v == "")
            && u["ControlGroup"] == "",
        "228 collected owner is loaded, live, replaced or ambiguous"
    );
    Ok(())
}
fn rows(bytes: &[u8]) -> Result<Vec<Value>> {
    let r = serde_json::Deserializer::from_slice(bytes)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        !r.is_empty() && r.len() <= 4096,
        "228 collected manager history bounds"
    );
    Ok(r)
}
fn history(rows: &[Value], origin: &Value, terminal: u64) -> Result<()> {
    let start = origin["producer_started_unix_millis"]
        .as_u64()
        .context("228 original start")?;
    let mut starting = None;
    let mut started = None;
    let mut finished = None;
    let mut last = 0;
    for r in rows {
        let clock = r["__REALTIME_TIMESTAMP"]
            .as_str()
            .context("228 history clock")?
            .parse::<u64>()?;
        ensure!(clock >= last, "228 history clock rollback");
        last = clock;
        if r["_PID"] == "1" && r["UNIT"] == c::UNIT {
            let msg = r["MESSAGE"].as_str().context("228 manager message")?;
            let start_message = r["MESSAGE_ID"] == "7d4958e842da4a758f6c1cdc7b36dcc5";
            ensure!(!start_message || clock < terminal, "228 later PID1 start");
            let lifecycle = start_message
                || msg.starts_with(&format!("Starting {} -", c::UNIT))
                || msg.starts_with(&format!("Started {} -", c::UNIT))
                || msg.contains("Deactivated successfully")
                || r["INVOCATION_ID"].as_str().is_some();
            if lifecycle {
                ensure!(
                    r["_UID"] == "0" && r["INVOCATION_ID"] == IID,
                    "228 missing/foreign/later PID1 invocation"
                );
            }
            if msg.starts_with(&format!("Starting {} -", c::UNIT)) {
                ensure!(
                    starting.replace(clock).is_none(),
                    "228 duplicate/later Starting"
                );
            }
            if msg.starts_with(&format!("Started {} -", c::UNIT)) {
                ensure!(
                    started.replace(clock).is_none(),
                    "228 duplicate/later Started"
                );
            }
            if msg == format!("{}: Deactivated successfully.", c::UNIT) {
                ensure!(finished.replace(clock).is_none(), "228 duplicate terminal");
            }
        } else if r["_SYSTEMD_UNIT"] == c::UNIT {
            ensure!(
                r["_SYSTEMD_INVOCATION_ID"] == IID
                    && r["_PID"].as_str().and_then(|s| s.parse::<u64>().ok()) == Some(PID),
                "228 later/foreign original-unit child"
            );
        }
    }
    ensure!(
        starting
            .zip(started)
            .zip(finished)
            .is_some_and(|((a, b), e)| a <= b
                && b < e
                && e == terminal
                && (a / 1000).abs_diff(start) <= 5000),
        "228 original PID1 start/success or authoritative clock missing"
    );
    Ok(())
}
fn related(name: &str) -> bool {
    name == c::UNIT
        || [
            "horizon-native-input-228-",
            "horizon-singleton-228-",
            "horizon-qualify-228-",
            "archive-228-",
            "horizon-upload-228-",
            "horizon-publish-228-",
            "horizon-full-verify-228-",
            "horizon-plugin-verify-228-",
            "horizon-independent-full-read-228-",
        ]
        .iter()
        .any(|p| name.starts_with(p))
}
fn discovered(v: &Value, accepted: &Value) -> Result<()> {
    let mut seen = BTreeSet::new();
    for row in v.as_array().context("228 full discovered unit table")? {
        let name = row["unit"].as_str().context("228 discovered unit name")?;
        ensure!(seen.insert(name), "228 duplicate discovery row");
        let live =
            row["active"] == "activating" || (row["active"] == "active" && row["sub"] == "running");
        ensure!(
            !related(name) || (!live && row["load"] == "not-found"),
            "228 loaded replacement/downstream owner discovered"
        );
        if live
            && (name.starts_with("horizon-singleton-") || name.starts_with("horizon-native-input-"))
        {
            ensure!(
                accepted.get(name).is_some_and(Value::is_object),
                "228 collection census omits another actual singleton/native owner"
            );
        }
    }
    Ok(())
}
fn no_jobs(text: &str) -> Result<()> {
    ensure!(
        !super::super::inactive_status::queued_job_units(text.as_bytes())?
            .iter()
            .any(|u| related(u)),
        "228 original/replacement/downstream start is queued"
    );
    Ok(())
}
fn request(program: &str, args: &[&str]) -> Result<Vec<u8>> {
    let r = ProcessCommand::new(program).args(args).output()?;
    ensure!(
        r.status.success() && r.stdout.len() <= 16 << 20,
        "228 metadata command failed/oversize"
    );
    Ok(r.stdout)
}
fn cgroup_absent() -> Result<()> {
    match fs::symlink_metadata(Path::new("/sys/fs/cgroup/system.slice").join(c::UNIT)) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => bail!("228 collected unit still has a cgroup or cannot prove absence"),
    }
}
fn snapshot(f: &Value, start: u64, terminal: u64, origin: &Value) -> Result<Value> {
    let names = f["unit_census"]
        .as_object()
        .context("228 complete accepted census")?
        .keys()
        .cloned()
        .chain(std::iter::once(c::UNIT.into()))
        .collect::<BTreeSet<_>>();
    let current = census(&names, 201, 300)?;
    singleton227_admission::owners(f, &current)?;
    absent(current.get(c::UNIT).context("228 collected unit omitted")?)?;
    cgroup_absent()?;
    let all: Value = serde_json::from_slice(&request(
        "/usr/bin/systemctl",
        &[
            "list-units",
            "--all",
            "--type=service",
            "--output=json",
            "--no-pager",
        ],
    )?)?;
    discovered(&all, &serde_json::to_value(&current)?)?;
    let jobs = String::from_utf8(request(
        "/usr/bin/systemctl",
        &[
            "list-jobs",
            "--no-legend",
            "--no-pager",
            "--plain",
            "--full",
        ],
    )?)?;
    no_jobs(&jobs)?;
    let since = format!("@{}", start.saturating_sub(5));
    let raw = request(
        "/usr/bin/journalctl",
        &[
            "--unit",
            c::UNIT,
            "--since",
            &since,
            "--output=json",
            "--no-pager",
        ],
    )?;
    let logs = rows(&raw)?;
    history(&logs, origin, terminal)?;
    Ok(
        json!({"census":current,"discovered_units":all,"queued_jobs":jobs,"original_unit_history":logs,
        "cgroup_absent":true}),
    )
}
fn registered(f: &Value, p: &Plan) -> Result<()> {
    ensure!(
        f["schema"] == SCHEMA_FLEET
            && f["first_epoch"] == 201
            && f["last_epoch"] == 300
            && f["inventory"]["anomalies"] == 0
            && p.first_epoch == 201
            && p.last_epoch == 300,
        "228 collected recovery needs complete accepted modern fleet"
    );
    ensure!(
        p.pipeline_claims.iter().filter(|c| c.epoch == 228).count() == 1
            && p.pipeline_claims.iter().any(|c| c.epoch == 228
                && c.unit == self::c::UNIT
                && c.invocation_id == IID
                && c.phase == "private-cold-snapshot-verification"
                && c.evidence.first() == Some(&original()))
            && !p.diagnostics.iter().any(|c| c.epoch == 228)
            && f["active"]
                .as_array()
                .context("228 accepted active census")?
                .iter()
                .all(|r| r["epoch"] != 228)
            && p.gates
                .get(&228)
                .is_some_and(|g| g.state == "blocked-qualification"),
        "228 collected origin is unregistered, replaced or has another staged/live owner"
    );
    Ok(())
}
const SCHEMA_FLEET: &str = "jetstreamer-horizon-campaign-fleet-v1";
pub(super) fn capture(proof: &Value, f: &Value, p: &Plan, origin: &Value) -> Result<Value> {
    scope(proof)?;
    registered(f, p)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let sample = utc_seconds(
        f["sampled_at_utc"]
            .as_str()
            .context("228 accepted sample clock")?,
    )?;
    ensure!(
        now >= sample && now - sample <= 1800,
        "228 collected capture requires fresh accepted observer"
    );
    let terminal = proof["terminal_unix_microseconds"]
        .as_u64()
        .context("228 real terminal clock")?;
    let start = origin["producer_started_unix_millis"]
        .as_u64()
        .context("228 original start")?
        / 1000;
    let before = snapshot(f, start, terminal, origin)?;
    let after = snapshot(f, start, terminal, origin)?;
    ensure!(
        before["census"] == after["census"],
        "228 complete census changed across collection checks"
    );
    let observed = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    Ok(
        json!({"schema":SCHEMA,"running_origin":proof["running_origin"],"journal":proof["journal"],
        "checked_unix_seconds":observed,"before":before,"after":after}),
    )
}
fn witness(v: &Value, proof: &Value, origin: &Value) -> Result<()> {
    ensure!(
        v["schema"] == SCHEMA
            && v["running_origin"] == proof["running_origin"]
            && v["journal"] == proof["journal"]
            && v["checked_unix_seconds"] == proof["recorded_unix_seconds"],
        "228 collected witness binding/clock differs"
    );
    let terminal = proof["terminal_unix_microseconds"]
        .as_u64()
        .context("228 terminal clock")?;
    for side in ["before", "after"] {
        let s = &v[side];
        absent(&s["census"][c::UNIT])?;
        ensure!(
            s["census"][c::UNIT] == proof["terminal_manager"] && s["cgroup_absent"] == true,
            "228 collected witness does not preserve actual not-found state"
        );
        discovered(&s["discovered_units"], &s["census"])?;
        no_jobs(s["queued_jobs"].as_str().context("228 raw queued jobs")?)?;
        let logs = s["original_unit_history"]
            .as_array()
            .context("228 raw owner history")?;
        history(logs, origin, terminal)?;
    }
    ensure!(
        v["before"]["census"] == v["after"]["census"],
        "228 collected witness changed owners"
    );
    Ok(())
}
pub(super) fn validate(proof: &Value) -> Result<()> {
    scope(proof)?;
    let origin = c::immutable_json(&original())?;
    let f = bound_json(&serde_json::from_value(proof["fleet"].clone())?)?;
    let p: Plan = serde_json::from_value(bound_json(&BoundFile {
        path: f["plan"]
            .as_str()
            .context("228 collected accepted plan")?
            .into(),
        sha256: f["plan_sha256"]
            .as_str()
            .context("228 collected plan digest")?
            .into(),
    })?)?;
    registered(&f, &p)?;
    for side in ["before", "after"] {
        let census: BTreeMap<String, Value> =
            serde_json::from_value(proof["collected_terminal"][side]["census"].clone())?;
        singleton227_admission::owners(&f, &census)?;
    }
    let (_, clock) = super::native228_terminal::journal(&raw_journal(), IID, PID)?;
    ensure!(
        proof["terminal_unix_microseconds"] == clock,
        "228 collected canonical journal differs"
    );
    witness(&proof["collected_terminal"], proof, &origin)
}
pub(super) fn current(proof: &Value, current: &Value) -> Result<()> {
    validate(proof)?;
    absent(current)?;
    let f = bound_json(&serde_json::from_value(proof["fleet"].clone())?)?;
    let origin = c::immutable_json(&original())?;
    snapshot(
        &f,
        origin["producer_started_unix_millis"]
            .as_u64()
            .context("228 start")?
            / 1000,
        proof["terminal_unix_microseconds"]
            .as_u64()
            .context("228 terminal")?,
        &origin,
    )?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn manager() -> Value {
        json!({"Id":c::UNIT,"LoadState":"not-found","ActiveState":"inactive","SubState":"dead",
            "MainPID":"0","InvocationID":"","NRestarts":"0","Result":"success","ExecMainStatus":"0",
            "ControlGroup":""})
    }
    fn origin() -> Value {
        json!({"producer_started_unix_millis":1792798846918u64})
    }
    fn logs() -> Vec<Value> {
        let r = |m: String, t: &str| {
            json!({"_PID":"1","_UID":"0","UNIT":c::UNIT,"INVOCATION_ID":IID,
            "MESSAGE":m,"__REALTIME_TIMESTAMP":t})
        };
        vec![
            r(format!("Starting {} - actual", c::UNIT), "1792798846918041"),
            r(format!("Started {} - actual", c::UNIT), "1792798846950097"),
            r(
                format!("{}: Deactivated successfully.", c::UNIT),
                "1792799467531268",
            ),
        ]
    }
    fn proof() -> Value {
        let s = json!({"census":{(c::UNIT):manager()},"discovered_units":[],"queued_jobs":"",
            "original_unit_history":logs(),"cgroup_absent":true});
        let mut p = json!({"epoch":228,"unit":c::UNIT,"invocation_id":IID,"main_pid":PID,
            "running_origin":private157::binding(&original()),"journal":private157::binding(&raw_journal()),
            "recorded_unix_seconds":1792801000u64,"terminal_unix_microseconds":1792799467531268u64,
            "terminal_manager":manager()});
        p["collected_terminal"] = json!({"schema":SCHEMA,"running_origin":p["running_origin"],"journal":p["journal"],
            "checked_unix_seconds":p["recorded_unix_seconds"],"before":s,"after":s});
        p
    }
    #[test]
    fn collection_requires_bound_real_history_and_never_default_not_found_alone() {
        let p = proof();
        scope(&p).unwrap();
        witness(&p["collected_terminal"], &p, &origin()).unwrap();
        assert!(super::super::native228_terminal::terminal_shape(&manager(), IID).is_err());
        assert!(witness(&Value::Null, &p, &origin()).is_err());
        for (key, value) in [
            ("main_pid", json!(PID + 1)),
            ("invocation_id", json!("f".repeat(32))),
            ("journal", json!({"path":JOURNAL,"sha256":"f".repeat(64)})),
            (
                "running_origin",
                json!({"path":ORIGIN,"sha256":"f".repeat(64)}),
            ),
        ] {
            let mut bad = p.clone();
            bad[key] = value;
            assert!(scope(&bad).is_err(), "{key}");
        }
        for (pointer, value) in [
            (
                "/before/census/horizon-native-input-228-capped-1bfa8d51-v1.service/LoadState",
                json!("loaded"),
            ),
            ("/after/cgroup_absent", json!(false)),
            (
                "/after/queued_jobs",
                json!(format!("1 {} start waiting\n", c::UNIT)),
            ),
            (
                "/before/discovered_units",
                json!([{"unit":"horizon-singleton-228-new.service","load":"loaded","active":"active","sub":"running"}]),
            ),
        ] {
            let mut bad = p["collected_terminal"].clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(witness(&bad, &p, &origin()).is_err(), "{pointer}");
        }
    }
    #[test]
    fn later_started_foreign_missing_or_reordered_pid1_history_fails() {
        let good = logs();
        history(&good, &origin(), 1792799467531268).unwrap();
        for key in ["INVOCATION_ID", "_UID", "UNIT"] {
            let mut bad = good.clone();
            bad[0][key] = json!("wrong");
            assert!(history(&bad, &origin(), 1792799467531268).is_err(), "{key}");
        }
        for i in 0..good.len() {
            let mut bad = good.clone();
            bad.remove(i);
            assert!(history(&bad, &origin(), 1792799467531268).is_err());
        }
        let mut later = good.clone();
        let mut row = good[0].clone();
        row["__REALTIME_TIMESTAMP"] = json!("1792799999999999");
        later.push(row);
        assert!(history(&later, &origin(), 1792799467531268).is_err());
        assert!(history(&good, &origin(), 1792799467531267).is_err());
    }
    #[test]
    #[ignore = "root current read-only native228 collected metadata; no resource sample, Bank, runtime mutation, receipt write or R2"]
    fn actual_collected_native228_has_sealed_canonical_success_and_no_current_replacement() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let o = c::immutable_json(&original()).unwrap();
        let (marker, clock) =
            super::super::native228_terminal::journal(&raw_journal(), IID, PID).unwrap();
        assert_eq!(marker["accounts_hash"], c::ACCOUNTS_HASH);
        assert_eq!(marker["capitalization"], "504915797589943503");
        assert_eq!(marker["transaction_count"], "29954968857");
        let fleet=BoundFile {path:"/var/lib/jetstreamer/horizon-campaign-fleet/20261024T002600Z-v337/fleet-ledger.json".into(),
            sha256:"fee5c015fd38928ad9ec3d16cb675d8b21bab96a127793edf60907a648fda9bd".into()};
        let f = bound_json(&fleet).unwrap();
        let p: Plan = serde_json::from_value(
            bound_json(&BoundFile {
                path: f["plan"].as_str().unwrap().into(),
                sha256: f["plan_sha256"].as_str().unwrap().into(),
            })
            .unwrap(),
        )
        .unwrap();
        registered(&f, &p).unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let sample = utc_seconds(f["sampled_at_utc"].as_str().unwrap()).unwrap();
        assert!(now >= sample);
        // An old accepted ledger can still prove exact registered history; this
        // regression makes no fresh-observer claim and does not create a proof.
        let v = snapshot(
            &f,
            o["producer_started_unix_millis"].as_u64().unwrap() / 1000,
            clock,
            &o,
        )
        .unwrap();
        assert_eq!(v["census"][c::UNIT]["LoadState"], "not-found");
    }
}
