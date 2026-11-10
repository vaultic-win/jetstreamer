//! Evidence-bound closure and current terminal-state checks. Root must supply the
//! real immutable source-owner lineage and every relevant current/staged reader;
//! a ready canonical archive, a boolean or the bounded scanner is insufficient.
use crate::{PRIMARY, SHA, SOURCE, bound, raw, s, sha};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::Command,
};
pub(crate) const LANE: &str =
    "/home/sol/.jetstreamer-private/epoch130-v1417-production-20260930-v1/lane-a";
const QUALIFICATION: &str = "/usr/local/lib/jetstreamer/horizon-node02-holding-qualification-20261023-v1/qualification.json";
const QUALIFICATION_SHA: &str = "15692445c39b47b011851b9db68798730077be2cb665dbb7e527049c5e9c5f70";
const ROOTS: &[&str] = &[
    "/etc/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
    "/run/systemd/system",
    "/run/systemd/transient",
    "/run/systemd/generator",
    "/run/systemd/generator.early",
    "/run/systemd/generator.late",
    "/etc/systemd/user",
    "/usr/lib/systemd/user",
    "/lib/systemd/user",
    "/home/sol/.config/systemd/user",
    "/root/.config/systemd/user",
    "/etc/crontab",
    "/etc/anacrontab",
    "/etc/cron.d",
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
    "/var/spool/cron",
];
fn native(name: &str) -> Result<Value> {
    ensure!(
        name.ends_with(".service") || name.ends_with(".timer") || name.ends_with(".path"),
        "explicit unit required"
    );
    let o=Command::new("/usr/bin/systemctl").env_remove("DBUS_SYSTEM_BUS_ADDRESS").env_remove("SYSTEMD_BUS_ADDRESS").env_remove("DBUS_SESSION_BUS_ADDRESS").env_remove("SYSTEMD_HOST").args(["show",name,"--no-pager","-pId,LoadState,ActiveState,SubState,MainPID,ControlPID,InvocationID,NRestarts,Job,Triggers,TriggeredBy,OnSuccess,OnFailure"]).output()?;
    ensure!(
        o.status.success() && o.stderr.is_empty() && o.stdout.len() < 65536,
        "terminal query failed"
    );
    let mut m = serde_json::Map::new();
    for line in std::str::from_utf8(&o.stdout)?.lines() {
        let (k, v) = line.split_once('=').context("native delimiter")?;
        ensure!(
            m.insert(k.into(), json!(v)).is_none(),
            "duplicate native property"
        );
    }
    Ok(Value::Object(m))
}
fn terminal(name: &str, v: &Value) -> Result<()> {
    let service = name.ends_with(".service");
    let zero = |key: &str| v[key] == "0" || (!service && (v.get(key).is_none() || v[key] == ""));
    ensure!(
        v["Id"] == name
            && ["inactive", "failed"].contains(&s(v, "ActiveState")?)
            && ["dead", "failed"].contains(&s(v, "SubState")?)
            && zero("MainPID")
            && zero("ControlPID")
            && zero("NRestarts")
            && v["Job"] == ""
            && ["Triggers", "TriggeredBy", "OnSuccess", "OnFailure"]
                .iter()
                .all(|k| v.get(*k).is_none() || v[*k] == ""),
        "source or consumer owner/retry/trigger is not wholly terminal"
    );
    Ok(())
}

fn terminal_lineage(v: &Value, unit: &str, iid: &str) -> Result<()> {
    ensure!(
        iid.len() == 32 && iid.bytes().all(|b| b.is_ascii_hexdigit()),
        "original invocation required"
    );
    let rows = v["original_PID1_terminal_journal"]
        .as_array()
        .context("genuine original terminal journal required")?;
    ensure!(
        rows.iter().any(|r| r["_PID"] == "1"
            && r["UNIT"] == unit
            && r["INVOCATION_ID"] == iid
            && (r["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448"
                || r.get("UNIT_RESULT").is_some()
                || (r["JOB_TYPE"] == "stop" && r["JOB_RESULT"] == "done"))),
        "original PID1 terminal lineage differs"
    );
    Ok(())
}
pub(crate) fn validate_review_shape(review: &Value) -> Result<()> {
    ensure!(
        review["schema"] == "horizon-cold130-indirect-consumer-retirement-review-v2"
            && review["owner"] == "/root"
            && review["primary_thread"] == PRIMARY
            && review["source"] == SOURCE
            && review["sha256"] == SHA
            && review["no_current_or_staged_consumer_requires_local_body"] == true
            && review["old_body_is_distinct_from_current_canonical"] == true
            && review["restore_admission_required_before_any_future_consumer"] == true,
        "exact independently reviewed source closure required"
    );
    let classes = review["covered_reader_classes"]
        .as_array()
        .context("reader-class census required")?;
    let got: BTreeSet<_> = classes
        .iter()
        .map(|x| x.as_str().context("reader-class string"))
        .collect::<Result<_>>()?;
    let expected: BTreeSet<_> = [
        "source-producer",
        "source-controller",
        "import-publication",
        "full-verifier",
        "plugin-verifier",
        "left-boundary",
        "right-boundary",
        "recovery",
        "frame",
        "admission",
        "retirement",
        "timer-path-cron",
        "sealed-launch-plans",
        "libraries-and-relative-inputs",
    ]
    .into_iter()
    .collect();
    ensure!(
        got == expected && classes.len() == expected.len(),
        "incomplete/duplicate indirect reader classes"
    );
    let owners = review["closed_source_owners"]
        .as_array()
        .context("exact original owners required")?;
    ensure!(
        owners.len() == 2
            && owners[0]["role"] == "source-producer"
            && owners[1]["role"] == "source-controller",
        "original producer/controller must be explicitly identified"
    );
    let fence = bound(&review["controller_handoff_fence"])?;
    ensure!(
        fence["source"] == SOURCE
            && fence["sha256"] == SHA
            && fence["owner"] == "/root"
            && fence["primary_thread"] == PRIMARY
            && fence["all_relevant_writers_and_readers_excluded"] == true
            && fence["no_automatic_reopen_until_retirement_result_reconciled"] == true
            && fence["all_staged_and_indirect_inputs_enumerated"] == true
            && !s(review, "fence_id")?.is_empty()
            && fence["fence_id"] == review["fence_id"],
        "exclusive controller handoff fence missing"
    );
    ensure!(
        fence["closed_source_owners"] == review["closed_source_owners"]
            && fence["consumers"] == review["consumers"]
            && fence["staged_inputs"] == review["staged_inputs"]
            && fence["absent_reader_classes"] == review["absent_reader_classes"]
            && fence["current_fleet"] == review["current_fleet"],
        "fence does not cover exact current closure"
    );
    ensure!(
        review["original_publication"]["path"]
            == "/home/sol/.jetstreamer-private/epoch130-v1417-production-20260930-v1/lane-a/private/destination-ac17a7c6a33e8f921efc1a4659db0cd6983e67b63879a478b4e22d754a68218e/evidence/archive-batches/destination-000000000000fc00-000000000602045a/batch-968e6bb14f312a21deb907c70b8637b97271f87e232d8594e2fcbcac323e6b71.json"
            && review["original_publication"]["sha256"]
                == "df716fd20a2c83dd566d988ce46df9b2b2486de3b3b8c885c3aa76f997a5ea05",
        "original publication lineage differs"
    );
    let publication = bound(&review["original_publication"])?;
    ensure!(
        publication["schema"] == "jetstreamer-root-cohort-publication-receipt-v2"
            && publication["epochs"] == json!([130])
            && publication["outcome"]["kind"] == "committed"
            && publication["outcome"]["members"][0]["archive_sha256"] == crate::CANONICAL_SHA,
        "genuine original canonical import missing"
    );
    Ok(())
}
pub(crate) fn holding_lineage(p: &Value, c: &Value) -> Result<()> {
    ensure!(
        p["holding_transport_qualification"]["path"] == QUALIFICATION
            && p["holding_transport_qualification"]["sha256"] == QUALIFICATION_SHA,
        "unregistered holding qualification"
    );
    let q = bound(&p["holding_transport_qualification"])?;
    ensure!(
        q["schema"] == "jetstreamer-horizon-node02-holding-transport-qualification-v2"
            && q["host"] == "dev-samjohnson"
            && q["prefix"] == "node_02/"
            && q["mapping"] == c["mapping"]
            && q["qualified"]["small_authenticated_holding_park_readback_restore"] == true,
        "authenticated holding restoration is not qualified"
    );
    ensure!(
        p["park_spec"]["path"]
            == "/usr/local/lib/jetstreamer/horizon-cold130-holding-plan-20261110-v1/plan.json"
            && p["park_spec"]["sha256"]
                == "51521593b641d165c60fa3d0190d1b3ca0677110bdb0b2194230b338dedb0651",
        "genuine normally sealed park specification differs"
    );
    ensure!(
        p["holding_original_completion"]["path"]
            == "/home/sol/.jetstreamer-private/epoch173-independent-singleton-20261110-v1/cold130-candidate-20261110-v1/ROOT_COLD130_CUSTODY_COMPLETE_NO_RETIREMENT.json"
            && p["holding_original_completion"]["sha256"]
                == "50423005a35d87c6a674120069752d5bbc0e9a7d5c3a9abc7e3ab8ae33bacf7e",
        "original holding completion pin differs"
    );
    let spec = bound(&p["park_spec"])?;
    ensure!(
        spec["schema"] == "jetstreamer-horizon-holding-park-plan-v2"
            && spec["source"] == SOURCE
            && spec["length"] == crate::LENGTH
            && spec["sha256"] == SHA
            && spec["mapping"] == c["mapping"]
            && spec["eligibility"] == c["eligibility"],
        "park/custody/restore lineage differs"
    );
    let mapping = bound(&c["mapping"])?;
    ensure!(
        mapping["schema"] == "jetstreamer-horizon-host-holding-prefix-v2"
            && mapping["host"] == "dev-samjohnson"
            && mapping["prefix"] == "node_02/"
            && mapping["user_provided_prefix"] == true,
        "host holding authorization differs"
    );
    let eligibility = bound(&c["eligibility"])?;
    ensure!(
        eligibility["schema"] == "jetstreamer-horizon-holding-eligibility-v2"
            && eligibility["source"] == SOURCE
            && eligibility["sha256"] == SHA
            && eligibility["length"] == crate::LENGTH
            && eligibility["closed"] == true
            && eligibility["canonical_archive"] == false
            && eligibility["no_checkpoint_or_job_resume_claim"] == true,
        "private-body holding eligibility differs"
    );
    let done = bound(&p["holding_original_completion"])?;
    ensure!(
        done["custody"] == p["custody"]
            && done["original_invocation_id"] == "45c8b6e182174dfda7c69884bd412a7a"
            && done["source_preserved"] == true
            && done["local_retirement_authorized"] == false,
        "original holding completion differs"
    );
    terminal_lineage(
        &done,
        "horizon-cold130-holding-park-20261110-v1.service",
        "45c8b6e182174dfda7c69884bd412a7a",
    )?;
    Ok(())
}
fn walk(
    path: &Path,
    seen: &mut BTreeSet<PathBuf>,
    depth: usize,
    count: &mut u64,
    targets: &[PathBuf],
) -> Result<()> {
    ensure!(depth < 48 && *count < 200_000, "staged scan bound");
    let m = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    // Follow a staged symlink deliberately, retaining a global canonical cycle set;
    // never silently skip a directory or broken link.
    let resolved = if m.file_type().is_symlink() {
        path.canonicalize()
            .with_context(|| format!("unresolved staged symlink {}", path.display()))?
    } else {
        path.to_path_buf()
    };
    if !seen.insert(resolved.clone()) {
        return Ok(());
    }
    let m = fs::metadata(&resolved)?;
    if m.is_dir() {
        for e in fs::read_dir(&resolved)? {
            walk(&e?.path(), seen, depth + 1, count, targets)?;
        }
    } else if m.is_file() {
        ensure!(m.len() <= 16 << 20, "staged input exceeds bound");
        let bytes = fs::read(&resolved)?;
        let after = fs::metadata(&resolved)?;
        ensure!(
            m.dev() == after.dev()
                && m.ino() == after.ino()
                && m.len() == after.len()
                && m.mtime() == after.mtime()
                && m.mtime_nsec() == after.mtime_nsec()
                && m.ctime() == after.ctime()
                && m.ctime_nsec() == after.ctime_nsec(),
            "staged input changed"
        );
        for target in targets {
            ensure!(
                !crate::process_references::encoded_reference(
                    &bytes,
                    target.as_os_str().as_encoded_bytes(),
                    true
                ),
                "staged direct/indirect reader references {}: {}",
                target.display(),
                resolved.display()
            );
        }
        *count += 1;
    }
    Ok(())
}
pub(crate) fn census(p: &Value) -> Result<Value> {
    let review = bound(&p["indirect_consumers_review"])?;
    validate_review_shape(&review)?;
    let mut units = Vec::new();
    let mut indirect = Vec::new();
    let mut known = BTreeSet::new();
    for owner in review["closed_source_owners"]
        .as_array()
        .context("original source owners")?
    {
        let unit = s(owner, "unit")?;
        let iid = s(owner, "invocation_id")?;
        ensure!(
            known.insert(unit.to_owned()),
            "duplicate original source owner"
        );
        let lineage = bound(&owner["terminal_evidence"])?;
        ensure!(
            lineage["source"] == SOURCE
                && lineage["sha256"] == SHA
                && lineage["unit"] == unit
                && lineage["invocation_id"] == iid,
            "source owner lineage not tied to exact body"
        );
        terminal_lineage(&lineage, unit, iid)?;
        let current = native(unit)?;
        terminal(unit, &current)?;
        ensure!(
            current["InvocationID"] == "" || current["InvocationID"] == iid,
            "source unit reused after terminal proof"
        );
        units.push(current);
    }
    let consumers = review["consumers"]
        .as_array()
        .context("current and historical reader census required")?;
    let mut consumer_classes = BTreeSet::new();
    for consumer in consumers {
        let class = s(consumer, "class")?;
        consumer_classes.insert(class.to_owned());
        let evidence = bound(&consumer["evidence"])?;
        ensure!(
            evidence["source"] == SOURCE
                && evidence["sha256"] == SHA
                && evidence["class"] == class
                && evidence["local_body_required"] == false,
            "consumer closure not independently bound"
        );
        let unit = s(consumer, "unit")?;
        let iid = s(consumer, "invocation_id")?;
        terminal_lineage(&evidence, unit, iid)?;
        let current = native(unit)?;
        terminal(unit, &current)?;
        ensure!(
            current["InvocationID"] == "" || current["InvocationID"] == iid,
            "consumer unit reused"
        );
        units.push(current);
        for input in consumer["immutable_inputs"]
            .as_array()
            .context("exact consumer input census required")?
        {
            let path = PathBuf::from(s(input, "path")?);
            let bytes = raw(&path, 16 << 20, false)?;
            ensure!(
                sha(&bytes) == s(input, "sha256")?,
                "consumer plan/library changed"
            );
            indirect.push(path);
        }
    }
    let fleet = bound(&review["current_fleet"])?;
    ensure!(
        fleet["owner"] == "/root"
            && fleet["epochs"].as_array().is_some_and(|rows| rows
                .iter()
                .any(|r| r["epoch"] == 130 && r["state"] == "remote-ready")),
        "complete fleet130 classification missing"
    );
    for absent in review["absent_reader_classes"]
        .as_array()
        .context("explicit absent-reader-class inventory required")?
    {
        let class = s(absent, "class")?;
        ensure!(
            consumer_classes.insert(class.to_owned()),
            "reader class is both present and absent"
        );
        let proof = bound(&absent["evidence"])?;
        ensure!(
            proof["source"] == SOURCE
                && proof["sha256"] == SHA
                && proof["class"] == class
                && proof["actual_consumer_count"] == 0
                && proof["current_fleet"] == review["current_fleet"]
                && proof["staged_inputs"] == review["staged_inputs"]
                && proof["fence_id"] == review["fence_id"]
                && !s(&proof, "reason")?.is_empty(),
            "absent reader class lacks exact source/fleet/staged/fence evidence"
        );
        let inspected = proof["independently_inspected_immutable_inputs"]
            .as_array()
            .context("absence proof must bind actual inspected source/plan inputs")?;
        ensure!(
            !inspected.is_empty(),
            "no inspected evidence for absent reader class"
        );
        for input in inspected {
            let path = PathBuf::from(s(input, "path")?);
            let bytes = raw(&path, 16 << 20, false)?;
            ensure!(
                sha(&bytes) == s(input, "sha256")?,
                "absent-reader source/plan evidence changed"
            );
            indirect.push(path);
        }
    }
    for class in [
        "import-publication",
        "full-verifier",
        "plugin-verifier",
        "left-boundary",
        "right-boundary",
        "recovery",
        "frame",
        "admission",
        "retirement",
        "timer-path-cron",
        "sealed-launch-plans",
        "libraries-and-relative-inputs",
    ] {
        ensure!(
            consumer_classes.contains(class),
            "reader class not backed by individual consumers: {class}"
        );
    }
    ensure!(
        consumer_classes.len() == 12,
        "reader inventory contains foreign classes"
    );
    let plans = review["staged_inputs"]
        .as_array()
        .context("sealed launch-plan closure required")?;
    for plan in plans {
        let path = PathBuf::from(s(plan, "path")?);
        let bytes = raw(&path, 16 << 20, false)?;
        ensure!(
            sha(&bytes) == s(plan, "sha256")?,
            "staged immutable input changed"
        );
        indirect.push(path);
    }
    indirect.sort();
    indirect.dedup();
    let scan = crate::process_references::scan(
        Path::new("/proc"),
        Path::new(SOURCE),
        Path::new(LANE),
        &indirect,
    )?;
    ensure!(
        scan.references.is_empty(),
        "live direct/relative/ancestor/indirect references: {:?}",
        scan.references
    );
    let mut targets = vec![
        PathBuf::from(SOURCE),
        PathBuf::from(Path::new(SOURCE).parent().context("source parent")?),
    ];
    targets.extend(indirect.iter().cloned());
    let mut count = 0;
    let mut seen = BTreeSet::new();
    for root in ROOTS {
        walk(Path::new(root), &mut seen, 0, &mut count, &targets)?;
    }
    for root in plans {
        walk(
            Path::new(s(root, "path")?),
            &mut seen,
            0,
            &mut count,
            &targets,
        )?;
    }
    ensure!(
        bound(&p["indirect_consumers_review"])? == review,
        "consumer closure changed during native scan"
    );
    for (unit, before) in units
        .iter()
        .map(|x| Ok((s(x, "Id")?, x)))
        .collect::<Result<Vec<_>>>()?
    {
        ensure!(
            native(unit)? == *before,
            "terminal owner changed during closure scan"
        );
    }
    Ok(
        json!({"review":p["indirect_consumers_review"],"current_terminal_units":units,"processes":scan.inspected_processes,"references":scan.references,"staged_files_inspected":count,"staged_roots":ROOTS,"indirect_inputs":indirect,"errors":0,"scanner_is_only_a_supplement_to_bound_controller_fence":true}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    #[test]
    fn staged_symlink_directory_is_traversed_and_reference_detected() {
        let t = tempfile::tempdir().unwrap();
        fs::create_dir(t.path().join("real")).unwrap();
        fs::write(t.path().join("real/unit"), SOURCE).unwrap();
        symlink("real", t.path().join("linked")).unwrap();
        assert!(
            walk(
                &t.path().join("linked"),
                &mut BTreeSet::new(),
                0,
                &mut 0,
                &[PathBuf::from(SOURCE)]
            )
            .is_err()
        );
    }
    #[test]
    fn staged_broken_symlink_is_a_failed_gate() {
        let t = tempfile::tempdir().unwrap();
        symlink("absent", t.path().join("link")).unwrap();
        assert!(walk(&t.path().join("link"), &mut BTreeSet::new(), 0, &mut 0, &[]).is_err());
    }
    #[test]
    fn reader_reappearance_is_not_a_terminal_shape() {
        let unit = "test.service";
        let good = json!({"Id":unit,"ActiveState":"inactive","SubState":"dead","MainPID":"0","ControlPID":"0","NRestarts":"0","Job":"","Triggers":"","TriggeredBy":"","OnSuccess":"","OnFailure":""});
        terminal(unit, &good).unwrap();
        for (k, v) in [
            ("MainPID", "9"),
            ("ActiveState", "active"),
            ("Job", "1 queued"),
            ("TriggeredBy", "launch.timer"),
            ("OnSuccess", "reader.service"),
        ] {
            let mut bad = good.clone();
            bad[k] = json!(v);
            assert!(terminal(unit, &bad).is_err());
        }
    }
    #[test]
    fn unrelated_or_failure_text_is_not_original_terminal_lineage() {
        let v = json!({"original_PID1_terminal_journal":[{"_PID":"1","UNIT":"foreign.service","INVOCATION_ID":"a".repeat(32),"MESSAGE_ID":"7ad2d189f7e94e70a38c781354912448"}]});
        assert!(terminal_lineage(&v, "owned.service", &"a".repeat(32)).is_err());
    }
}
