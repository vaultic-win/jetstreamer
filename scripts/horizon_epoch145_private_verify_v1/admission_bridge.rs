//! Metadata-only companion. This process alone links the reviewed integration
//! dependency graph. It calls opaque typed constructors, never archive routines.
use anyhow::{Context, Result, ensure};
use horizon_original199_parent_memory::{
    admission_bridge,
    model::{Bound, Request},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
fn digest(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn identity(m: &fs::Metadata) -> (u64, u64, u64, u32, u32, u32, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.mode(),
        m.uid(),
        m.gid(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}
fn read(b: &Bound, immutable: bool) -> Result<Vec<u8>> {
    ensure!(hex(&b.sha256, 64), "bridge input digest");
    let m = fs::symlink_metadata(&b.path)?;
    ensure!(
        b.path.is_absolute()
            && b.path.canonicalize()? == b.path
            && m.is_file()
            && m.uid() == 0
            && m.gid() == 0
            && m.nlink() == 1
            && m.len() <= 8 << 20
            && if immutable {
                m.mode() & 0o222 == 0
            } else {
                m.mode() & 0o777 == 0o600
            },
        "bridge metadata custody"
    );
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&b.path)?;
    ensure!(
        identity(&f.metadata()?) == identity(&m),
        "bridge input open changed"
    );
    let mut bytes = Vec::new();
    (&mut f).take((8 << 20) + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == m.len()
            && identity(&f.metadata()?) == identity(&m)
            && identity(&fs::symlink_metadata(&b.path)?) == identity(&m)
            && digest(&bytes) == b.sha256,
        "bridge metadata changed/digest mismatch"
    );
    Ok(bytes)
}
fn authority() -> Value {
    json!({"runtime_promotion_authorized":false,"canonical_sidecar_authorized":false,"publication_authorized":false,"retirement_authorized":false,"r2_mutations":false,"replay_launch_authorized":false})
}
fn bound(v: &Value, key: &str) -> Result<Bound> {
    Ok(serde_json::from_value(v[key].clone())?)
}
fn plan_scope(v: &Value) -> Result<()> {
    ensure!(
        v["schema"] == "horizon-epoch145-private-verification-plan-v1"
            && v["source"]["path"]
                == "/home/sol/.jetstreamer-private/epoch145-prefix-extract-real1328-20261106-v1/epoch-145.jet"
            && v["export_plan"]["sha256"]
                == "0c47a737ef3a3086ffe2e8042ba9a989175c1547eb1ab0680f121628b431d6e9",
        "bridge exact metadata scope"
    );
    Ok(())
}
fn crossed(a: &Value, pb: &Bound) -> Result<()> {
    ensure!(
        a["schema"] == "horizon-epoch145-private-verification-typed-admission-v1"
            && a["plan"] == json!(pb),
        "bridge continuity plan crossed"
    );
    Ok(())
}
fn run() -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "bridge Root identity");
    let args = std::env::args().collect::<Vec<_>>();
    let continuing = args.len() == 11
        && args[1] == "continuity"
        && args[3] == "--plan-sha256"
        && args[5] == "--admission"
        && args[7] == "--admission-sha256"
        && args[9] == "--self-sha256";
    let fresh = args.len() == 7
        && args[1] == "fresh"
        && args[3] == "--plan-sha256"
        && args[5] == "--self-sha256";
    ensure!(fresh || continuing, "bridge exact CLI");
    let own = fs::metadata("/proc/self/exe")?;
    ensure!(
        own.uid() == 0
            && own.gid() == 0
            && own.nlink() == 1
            && own.mode() & 0o222 == 0
            && own.len() <= 128 << 20,
        "bridge self custody"
    );
    let self_sha = &args[if continuing { 10 } else { 6 }];
    ensure!(
        hex(self_sha, 64) && digest(&fs::read("/proc/self/exe")?) == *self_sha,
        "bridge separately supplied self SHA"
    );
    let pb = Bound {
        path: Path::new(&args[2]).into(),
        sha256: args[4].clone(),
    };
    let p: Value = serde_json::from_slice(&read(&pb, true)?)?;
    plan_scope(&p)?;
    ensure!(
        fs::read_link("/proc/self/exe")? == bound(&p, "admission_bridge")?.path
            && bound(&p, "admission_bridge")?.sha256 == *self_sha,
        "bridge plan executable crossed"
    );
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let ab = if continuing {
        Some(Bound {
            path: Path::new(&args[6]).into(),
            sha256: args[8].clone(),
        })
    } else {
        None
    };
    let mut result = json!({"schema":"horizon-epoch145-typed-verification-admission-bridge-execution-v1","plan":pb,"admission":ab,
        "mode":if continuing{"continuity"}else{"fresh"},"pid":std::process::id(),"parent_pid":unsafe{libc::getppid()},
        "caller_iid":std::env::var("INVOCATION_ID").context("bridge parent IID")?,"at_unix_seconds":now,"authority":authority()});
    let stat = fs::read_to_string("/proc/self/stat")?;
    let ticks = stat
        .rsplit_once(')')
        .context("bridge stat")?
        .1
        .split_whitespace()
        .nth(19)
        .context("bridge ticks")?
        .parse::<u64>()?;
    result["start_ticks"] = json!(ticks);
    if let Some(ab) = ab {
        ensure!(
            ab.path
                == Path::new(p["state_root"].as_str().context("state root")?)
                    .join("admission.json"),
            "bridge exact admitted snapshot path"
        );
        let a: Value = serde_json::from_slice(&read(&ab, false)?)?;
        crossed(&a, &pb)?;
        horizon_original199_parent_memory::revalidate_running_guard(&a["memory_evidence"], now)?;
        horizon_terminal183_ended_data::revalidate_running_guard(
            &a["data_evidence"],
            &a["memory_evidence"],
            now,
        )?;
    } else {
        let request: Request = serde_json::from_slice(&read(&bound(&p, "memory_request")?, true)?)?;
        let memory = admission_bridge::from_current_reader(&request, now)?;
        let data = horizon_terminal183_ended_data::select(
            &memory,
            &bound(&p, "data_policy")?,
            &bound(&p, "data_policy_seal")?,
            now,
        )?;
        result["memory_evidence"] = memory.evidence().clone();
        result["data_evidence"] = data.evidence().clone();
        result["effective_total_memory_bytes"] = json!(memory.effective_total_bytes());
        result["effective_protected_DATA_bytes"] = json!(data.effective_protected_bytes());
    }
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("typed admission bridge failed: {e:#}");
        std::process::exit(1);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bridge_cannot_claim_publication_retirement_or_launch() {
        assert!(
            authority()
                .as_object()
                .unwrap()
                .values()
                .all(|v| *v == false)
        );
    }
    #[test]
    fn continuity_cannot_relabel_a_different_current_plan() {
        let pb = Bound {
            path: "/sealed/a".into(),
            sha256: "a".repeat(64),
        };
        let mut a =
            json!({"schema":"horizon-epoch145-private-verification-typed-admission-v1","plan":pb});
        assert!(crossed(&a, &pb).is_ok());
        a["plan"]["sha256"] = json!("b".repeat(64));
        assert!(crossed(&a, &pb).is_err());
    }
    #[test]
    fn bridge_scope_rejects_shortened_or_unrelated_archive() {
        let p = json!({"schema":"horizon-epoch145-private-verification-plan-v1","source":{"path":"/private/short145.jet","sha256":"cb8ac0bc47919c22dc7898e068fb43ffac80aceadcacac3ff8f24ef32d3b3353"}});
        assert!(plan_scope(&p).is_err());
    }
}
