//! Offline geometry check only. No resource observation, launch or file mutation.
use {
    anyhow::{Context, Result, ensure},
    serde::{Deserialize, Serialize},
    serde_json::json,
    sha2::{Digest, Sha256},
    std::{
        env,
        fs::{self, OpenOptions},
        io::Read,
        os::unix::fs::{MetadataExt, OpenOptionsExt},
        path::Path,
    },
};

const GIB: u64 = 1 << 30;
const SCHEMA: &str = "jetstreamer-private-epoch203-ram-resource-geometry-v1";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Geometry {
    schema: String,
    tmpfs_bytes: u64,
    scratch_budget_bytes: u64,
    archive_budget_bytes: u64,
    anonymous_budget_bytes: u64,
    overhead_budget_bytes: u64,
    memory_high_bytes: u64,
    memory_max_bytes: u64,
    host_start_available_bytes: u64,
    host_stop_available_bytes: u64,
    protected_host_bytes: u64,
    century_floor_bytes: u64,
    // The archive must stay on a separately persistent RAM mount after the
    // producer ends, until it is sealed/retired by a qualified lifecycle.
    persistent_mount_required: bool,
    swap_max_bytes: u64,
}

#[derive(Debug, Serialize)]
struct Checked {
    aggregate_component_budget_bytes: u64,
    worst_case_tmpfs_free_bytes: u64,
    host_start_less_cap_bytes: u64,
    host_stop_less_cap_bytes: u64,
}

fn validate(g: &Geometry) -> Result<Checked> {
    ensure!(g.schema == SCHEMA, "wrong geometry schema");
    ensure!(
        g.persistent_mount_required,
        "diagnostic artifacts must survive producer exit"
    );
    ensure!(
        g.swap_max_bytes == 0,
        "RAM diagnostic must not spill into root-disk swap"
    );
    // These minima are experimental budgets, NOT measured peak claims. In
    // particular the retained same-input baseline consumed ~161 GiB scratch
    // and ~80 GiB cgroup memory on disk; 128 GiB scratch is not comparable.
    ensure!(
        g.scratch_budget_bytes >= 192 * GIB,
        "scratch budget below comparison envelope"
    );
    ensure!(g.archive_budget_bytes >= 16 * GIB, "missing archive budget");
    ensure!(
        g.anonymous_budget_bytes >= 96 * GIB,
        "missing worker memory budget"
    );
    ensure!(
        g.overhead_budget_bytes >= 16 * GIB,
        "missing supervisor/metadata margin"
    );
    ensure!(g.protected_host_bytes >= 224 * GIB, "host reserve weakened");
    ensure!(
        g.century_floor_bytes >= 231_874_716_783,
        "century floor below retained six-sample floor"
    );
    let aggregate = [
        g.scratch_budget_bytes,
        g.archive_budget_bytes,
        g.anonymous_budget_bytes,
        g.overhead_budget_bytes,
    ]
    .into_iter()
    .try_fold(0u64, |a, b| {
        a.checked_add(b).context("component budget overflow")
    })?;
    ensure!(
        aggregate <= g.memory_max_bytes,
        "RAM files and anonymous memory exceed shared cgroup cap"
    );
    ensure!(
        g.memory_high_bytes > 0 && g.memory_high_bytes < g.memory_max_bytes,
        "invalid memory soft/hard ceilings"
    );
    let tmpfs_free = g
        .tmpfs_bytes
        .checked_sub(g.memory_max_bytes)
        .context("tmpfs smaller than complete memory cap")?;
    ensure!(
        tmpfs_free >= g.century_floor_bytes,
        "tmpfs cannot preserve century floor at cgroup cap"
    );
    let start_less_cap = g
        .host_start_available_bytes
        .checked_sub(g.memory_max_bytes)
        .context("startup memory below cap")?;
    ensure!(
        start_less_cap >= g.host_stop_available_bytes,
        "startup does not reserve complete diagnostic cap"
    );
    let stop_less_cap = g
        .host_stop_available_bytes
        .checked_sub(g.memory_max_bytes)
        .context("stop reserve below cap")?;
    ensure!(
        stop_less_cap >= g.protected_host_bytes,
        "guard trip cannot preserve protected host reserve"
    );
    Ok(Checked {
        aggregate_component_budget_bytes: aggregate,
        worst_case_tmpfs_free_bytes: tmpfs_free,
        host_start_less_cap_bytes: start_less_cap,
        host_stop_less_cap_bytes: stop_less_cap,
    })
}

fn sha_valid(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn read_plan(path: &Path, expected: &str) -> Result<Vec<u8>> {
    ensure!(
        sha_valid(expected) && path.is_absolute() && path.canonicalize()? == path,
        "noncanonical plan path/hash"
    );
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let before = f.metadata()?;
    ensure!(
        before.is_file()
            && before.uid() == 0
            && before.nlink() == 1
            && before.mode() & 0o222 == 0
            && before.len() <= 65536,
        "unsafe immutable plan"
    );
    let mut bytes = Vec::new();
    (&mut f).take(65537).read_to_end(&mut bytes)?;
    let identity = |m: &fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.len(),
            m.mode(),
            m.uid(),
            m.gid(),
            m.nlink(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    };
    ensure!(
        identity(&before) == identity(&f.metadata()?)
            && identity(&before) == identity(&fs::symlink_metadata(path)?)
            && bytes.len() as u64 == before.len()
            && format!("{:x}", Sha256::digest(&bytes)) == expected,
        "plan changed or digest mismatch"
    );
    Ok(bytes)
}

fn run() -> Result<()> {
    let args: Vec<_> = env::args().skip(1).collect();
    ensure!(
        args.len() == 3 && args[1] == "--plan-sha256",
        "usage: jetstreamer-epoch203-ram-resource-plan /absolute/geometry.json --plan-sha256 HEX"
    );
    let bytes = read_plan(Path::new(&args[0]), &args[2])?;
    let g: Geometry = serde_json::from_slice(&bytes)?;
    let checked = validate(&g)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema":"jetstreamer-private-epoch203-ram-resource-geometry-check-v1",
            "plan_path":args[0],"plan_sha256":args[2],"geometry":g,"checked":checked,
            "live_resource_sample_taken":false,"fresh_admission_passed":false,
            "authority":{"replay_launch_authorized":false,"full_cold_epoch_peak_qualified":false,
                "runtime_promotion_authorized":false,"canonical_sidecar_authorized":false,
                "publication_authorized":false,"local_retirement_authorized":false,
                "remote_mutations":false,"r2_mutations":false}
        }))?
    );
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("RAM resource geometry rejected: {e:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn candidate() -> Geometry {
        Geometry {
            schema: SCHEMA.into(),
            tmpfs_bytes: 768 * GIB,
            scratch_budget_bytes: 192 * GIB,
            archive_budget_bytes: 16 * GIB,
            anonymous_budget_bytes: 96 * GIB,
            overhead_budget_bytes: 16 * GIB,
            memory_high_bytes: 304 * GIB,
            memory_max_bytes: 320 * GIB,
            host_start_available_bytes: 864 * GIB,
            host_stop_available_bytes: 544 * GIB,
            protected_host_bytes: 224 * GIB,
            century_floor_bytes: 231_874_716_783,
            persistent_mount_required: true,
            swap_max_bytes: 0,
        }
    }
    #[test]
    fn complete_ram_charge_preserves_both_reserves() {
        let c = validate(&candidate()).unwrap();
        assert_eq!(c.aggregate_component_budget_bytes, 320 * GIB);
        assert_eq!(c.worst_case_tmpfs_free_bytes, 448 * GIB);
        assert_eq!(c.host_start_less_cap_bytes, 544 * GIB);
        assert_eq!(c.host_stop_less_cap_bytes, 224 * GIB);
    }
    #[test]
    fn snapshot_test_sandbox_cannot_be_reused_for_entry_replay() {
        let mut g = candidate();
        g.memory_max_bytes = 128 * GIB;
        g.memory_high_bytes = 112 * GIB;
        assert!(validate(&g).is_err());
        g = candidate();
        g.tmpfs_bytes = 512 * GIB;
        assert!(validate(&g).is_err());
    }
    #[test]
    fn every_component_and_reserve_fails_closed() {
        for field in [
            "scratch_budget_bytes",
            "archive_budget_bytes",
            "anonymous_budget_bytes",
            "overhead_budget_bytes",
            "protected_host_bytes",
            "century_floor_bytes",
            "host_start_available_bytes",
            "host_stop_available_bytes",
        ] {
            let mut v = serde_json::to_value(candidate()).unwrap();
            v[field] = json!(v[field].as_u64().unwrap() - 1);
            let g = serde_json::from_value(v).unwrap();
            assert!(validate(&g).is_err(), "accepted {field}");
        }
    }
    #[test]
    fn no_overflow_swap_or_ephemeral_artifact_escape() {
        let mut g = candidate();
        g.scratch_budget_bytes = u64::MAX;
        assert!(validate(&g).is_err());
        g = candidate();
        g.swap_max_bytes = 1;
        assert!(validate(&g).is_err());
        g = candidate();
        g.persistent_mount_required = false;
        assert!(validate(&g).is_err());
        for high in [0, 320 * GIB, u64::MAX] {
            g = candidate();
            g.memory_high_bytes = high;
            assert!(validate(&g).is_err());
        }
    }
    #[test]
    fn unknown_fields_and_missing_fields_are_not_authority() {
        let mut v = serde_json::to_value(candidate()).unwrap();
        v["replay_launch_authorized"] = json!(true);
        assert!(serde_json::from_value::<Geometry>(v).is_err());
        let mut v = serde_json::to_value(candidate()).unwrap();
        v.as_object_mut()
            .unwrap()
            .remove("persistent_mount_required");
        assert!(serde_json::from_value::<Geometry>(v).is_err());
    }
}
