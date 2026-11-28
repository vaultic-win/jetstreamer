//! Exact byte protocol to a separately sealed Rust metadata executable. No
//! selected JSON total is accepted without that real successful child execution.
use crate::{custody as f, model::*};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    io::Read,
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

fn reply(
    v: &Value,
    pb: &Bound,
    ab: Option<&Bound>,
    pid: u32,
    parent: u32,
    iid: &str,
) -> Result<()> {
    ensure!(
        v["schema"] == "horizon-epoch145-typed-verification-admission-bridge-execution-v1"
            && v["plan"] == json!(pb)
            && v["admission"] == json!(ab)
            && v["mode"] == if ab.is_some() { "continuity" } else { "fresh" }
            && v["pid"] == pid
            && v["parent_pid"] == parent
            && v["caller_iid"] == iid
            && v["start_ticks"].as_u64().is_some_and(|n| n > 0)
            && v["authority"] == super::false_authority(),
        "actual typed bridge child/plan/admission reply crossed"
    );
    Ok(())
}
pub fn call(p: &Plan, pb: &Bound, ab: Option<&Bound>) -> Result<Value> {
    let root = p.admission_bridge.path.parent().context("bridge parent")?;
    ensure!(
        root.parent() == Some(Path::new("/usr/local/lib/jetstreamer"))
            && root.file_name().and_then(|n| n.to_str()).is_some_and(
                |n| n.starts_with("horizon-epoch145-private-verify-admission-bridge-tools-")
            )
            && p.admission_bridge
                .path
                .file_name()
                .is_some_and(|n| n == "epoch145-verification-admission-bridge")
            && p.admission_bridge_seal.path == root.join("deployment-seal-receipt.json"),
        "exact bridge namespace"
    );
    f::bytes(&p.admission_bridge, 128 << 20, true)?;
    let seal = f::json(&p.admission_bridge_seal, true)?;
    ensure!(
        seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && seal["destination"] == root.to_string_lossy().as_ref()
            && seal["members"].as_array().is_some_and(|rows| rows
                .iter()
                .filter(|r| r["name"] == "epoch145-verification-admission-bridge"
                    && r["sha256"] == p.admission_bridge.sha256
                    && r["mode"] == "0555")
                .count()
                == 1),
        "actual bridge normal seal"
    );
    let iid = std::env::var("INVOCATION_ID").context("actual bridge caller IID")?;
    ensure!(f::hex(&iid, 32), "actual bridge caller IID shape");
    let mut cmd = Command::new(&p.admission_bridge.path);
    cmd.arg(if ab.is_some() { "continuity" } else { "fresh" })
        .arg(&pb.path)
        .args(["--plan-sha256", &pb.sha256]);
    if let Some(ab) = ab {
        cmd.arg("--admission")
            .arg(&ab.path)
            .args(["--admission-sha256", &ab.sha256]);
    }
    cmd.args(["--self-sha256", &p.admission_bridge.sha256])
        .env_clear()
        .env("INVOCATION_ID", &iid)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn()?;
    let pid = child.id();
    let stdout = child.stdout.take().context("bridge stdout")?;
    let stderr = child.stderr.take().context("bridge stderr")?;
    let out = thread::spawn(move || {
        let mut b = Vec::new();
        stdout.take((8 << 20) + 1).read_to_end(&mut b).map(|_| b)
    });
    let err = thread::spawn(move || {
        let mut b = Vec::new();
        stderr.take((64 << 10) + 1).read_to_end(&mut b).map(|_| b)
    });
    let deadline = Instant::now() + Duration::from_secs(90);
    let (status, expired) = loop {
        if let Some(status) = child.try_wait()? {
            break (status, false);
        }
        if Instant::now() >= deadline {
            child.kill()?;
            break (child.wait()?, true);
        }
        thread::sleep(Duration::from_millis(100));
    };
    let output = out
        .join()
        .map_err(|_| anyhow::anyhow!("bridge stdout thread"))??;
    let errors = err
        .join()
        .map_err(|_| anyhow::anyhow!("bridge stderr thread"))??;
    ensure!(
        !expired && status.success() && output.len() <= 8 << 20 && errors.len() <= 64 << 10,
        "typed bridge original child failed/bounded out: {}",
        String::from_utf8_lossy(&errors)
    );
    let v: Value = serde_json::from_slice(&output)?;
    reply(&v, pb, ab, pid, std::process::id(), &iid)?;
    Ok(v)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bridge_reply_requires_real_child_and_exact_bound_request() {
        let pb = Bound {
            path: "/sealed/plan.json".into(),
            sha256: "a".repeat(64),
        };
        let mut v = json!({"schema":"horizon-epoch145-typed-verification-admission-bridge-execution-v1","plan":pb,"admission":null,"mode":"fresh",
            "pid":2,"parent_pid":1,"caller_iid":"b".repeat(32),"start_ticks":3,"authority":super::super::false_authority()});
        assert!(reply(&v, &pb, None, 2, 1, &"b".repeat(32)).is_ok());
        assert!(reply(&v, &pb, None, 4, 1, &"b".repeat(32)).is_err());
        v["authority"]["publication_authorized"] = json!(true);
        assert!(reply(&v, &pb, None, 2, 1, &"b".repeat(32)).is_err());
    }
}
