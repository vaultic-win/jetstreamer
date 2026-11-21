//! Bind old6/7 retirement to the observed native retry9 stop and all twelve renewed DATA members.
use super::*;

const R: &str = "/var/lib/jetstreamer/horizon_runtime_data";
fn fixed(path: &str, digest: &str) -> Result<Value> {
    bound(&json!({"path":Path::new(R).join(path),"sha256":digest}))
}
fn stat_member(v: &Value, target: &Path, ancestor: bool) -> Result<()> {
    let path = Path::new(string(v, "path")?);
    let m = path.symlink_metadata()?;
    ensure!(
        path.canonicalize()? == path
            && !path.starts_with(target)
            && v["dev"] == m.dev()
            && v["ino"] == m.ino()
            && v["uid"] == m.uid()
            && v["gid"] == m.gid()
            && v["mode"] == m.mode(),
        "renewed witness changed {}",
        path.display()
    );
    if ancestor {
        ensure!(
            m.is_dir()
                && (v["owned_change_times"].is_null()
                    || v["owned_change_times"]
                        == json!([m.mtime(), m.mtime_nsec(), m.ctime(), m.ctime_nsec()])),
            "witness ancestor changed {}",
            path.display()
        );
    } else {
        ensure!(
            m.is_file()
                && v["nlink"] == m.nlink()
                && v["allocated_blocks512"] == m.blocks()
                && v["logical_bytes"] == m.len()
                && v["ctime"] == m.ctime()
                && v["ctime_nsec"] == m.ctime_nsec()
                && v["mtime"] == m.mtime()
                && v["mtime_nsec"] == m.mtime_nsec(),
            "renewed DATA member changed {}",
            path.display()
        );
    }
    Ok(())
}
pub(super) fn verify(
    profile: &Value,
    target: &Path,
    original: &Value,
    plan: &Value,
) -> Result<Value> {
    ensure!(
        matches!(string(profile, "attempt")?, "local3retry6" | "local3retry7"),
        "terminal9 scope is old6/7 only"
    );
    let result = fixed(
        "incident-replay-fit-20261121-v1/ORIGINAL_GUARD_TIMERS_RETIRED.json",
        "59ec2c86879321c3fb6499d0e602d1eab78c4a4d8dbcdef6f48264ded650ecbc",
    )?;
    let report = bound(&result["reports"]["170"])?;
    let stop = bound(&report["guard_stop_completion"])?;
    let intent = bound(&report["guard_stop_intent"])?;
    ensure!(
        report["guard_stop_completion"]["sha256"]
            == "7cfb549dcac9507cb06401067e4f089778edeee2085222da0f4ab9ccce50bbb4"
            && report["guard_stop_intent"]["sha256"]
                == "56966262b9520b465b0ae3e9a65364efcae7c4aa7cd356272b36f2c425951231"
            && intent["producer_invocation_id"] == ORIGINAL
            && intent["reason"] == "DATA-fulfillment-observation-failed"
            && stop["producer_invocation_id"] == ORIGINAL
            && stop["terminal"]["pid"] == 0
            && stop["intent"] == report["guard_stop_intent"]["path"]
            && stop["scratch_deleted"] == false,
        "retry9 terminal binding changed"
    );
    let sample = bound(&report["guard"])?;
    ensure!(
        sample["producer_invocation_id"] == ORIGINAL
            && intent["sample"] == sample
            && sample["trip_reason"] == intent["reason"]
            && intent["plan_sha256"] == stop["plan_sha256"]
            && sample["plan_sha256"] == stop["plan_sha256"]
            && plan["unit"] == original["producer_unit"]
            && plan == &bound(&json!({"path":sample["plan"], "sha256":sample["plan_sha256"]}))?,
        "different stopped guard sample or plan"
    );
    let generation = &result["expected"]["170"];
    ensure!(
        generation["producer_unit"] == original["producer_unit"]
            && generation["producer_invocation_id"] == ORIGINAL,
        "wrong retired generation"
    );
    for k in ["producer_unit", "guard_unit", "timer_unit"] {
        closed(string(generation, k)?)?;
    }
    closed("horizon-qualify-170-replacement-local3retry10-20261121-v1.service")?;
    let custody = fixed(
        "epoch170-ancestor-accounts-20261121-v1/TERMINAL9_CHECKPOINT_INVENTORY.json",
        "cf240fbb9a490713c58617266316acf85c3380773da4ab4a9329b56102bfecd2",
    )?;
    ensure!(
        custody["replay_resume_available"] == false && custody["epoch_terminal"] == 73871999,
        "retry9 terminality changed"
    );
    for k in ["archive", "bootstrap_copy"] {
        let v = &custody[k];
        let p = Path::new(string(v, "path")?);
        let m = p.symlink_metadata()?;
        ensure!(
            p.canonicalize()? == p
                && !p.starts_with(target)
                && m.is_file()
                && v["device"] == m.dev()
                && v["inode"] == m.ino()
                && v["size"] == m.len()
                && v["allocated"] == m.blocks() * 512
                && v["mtime_ns"] == m.mtime() * 1_000_000_000 + m.mtime_nsec(),
            "retry9 custody changed"
        );
    }
    let fresh = fixed(
        "incident-replay-guard-20261121-v1/NATIVE_WITNESS.json",
        "33e62f01194935876985fabdc18a283ac00baccef58e30e97c65360420bb7f91",
    )?;
    let members = fresh["allocation"]["first"]
        .as_array()
        .context("missing native witness")?;
    ensure!(
        members.len() == 12 && fresh["allocation"]["second"] == fresh["allocation"]["first"],
        "renewed proof incomplete"
    );
    for v in members {
        stat_member(v, target, false)?;
        for ancestor in v["ancestors"].as_array().context("missing ancestors")? {
            stat_member(ancestor, target, true)?;
        }
    }
    let next = bound(
        &json!({"path":Path::new(BASE).join("RETRY10_ROOT_PRECREATED.json"),
        "sha256":"dfde6272e53a73ab669a56fe273a72c183c1871be5406b951c22452349bdf7a0"}),
    )?;
    let run = Path::new(string(&next, "root")?);
    let m = run.symlink_metadata()?;
    ensure!(
        next["predecessor_iid"] == ORIGINAL
            && next["predecessor_stop_sha256"] == report["guard_stop_completion"]["sha256"]
            && m.is_dir()
            && run.canonicalize()? == run
            && next["identity"][0] == m.dev()
            && next["identity"][1] == m.ino()
            && !run.starts_with(target)
            && !target.starts_with(run),
        "cleanup overlaps the new working directory or its identity changed"
    );
    Ok(
        json!({"native_stop":report["guard_stop_completion"], "successor":run, "successor_inode":m.ino()}),
    )
}
