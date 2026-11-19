//! Collect independent finalized boundary expectations before archive delivery.
//! Reads public RPC metadata only; never opens an archive or mutates R2.
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const ENDPOINT: &str = "https://api.mainnet-beta.solana.com";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    epoch: u64,
    output_directory: PathBuf,
}
fn digest(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn private_directory(p: &Path) -> Result<()> {
    let m = fs::symlink_metadata(p)?;
    ensure!(
        p.is_absolute()
            && p.canonicalize()? == p
            && m.is_dir()
            && m.uid() == 0
            && m.mode() & 0o7777 == 0o700,
        "invalid private output directory"
    );
    Ok(())
}
fn plan_bytes(p: &Path) -> Result<Vec<u8>> {
    ensure!(
        p.is_absolute() && p.canonicalize()? == p,
        "noncanonical plan"
    );
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(p)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o7777 == 0o444
            && m.len() <= 65536,
        "invalid plan custody"
    );
    let mut b = Vec::new();
    (&mut f).take(65537).read_to_end(&mut b)?;
    ensure!(
        b.len() <= 65536 && m.len() == b.len() as u64,
        "plan changed/oversize"
    );
    Ok(b)
}
fn save(p: &Path, b: &[u8]) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(p)?;
    f.write_all(b)?;
    f.sync_all()?;
    File::open(p.parent().context("output parent")?)?.sync_all()?;
    Ok(())
}
fn hash_text(v: &Value, field: &str) -> Result<String> {
    let s = v[field].as_str().context("missing blockhash")?;
    ensure!(
        bs58::decode(s)
            .into_vec()
            .map_err(|e| anyhow::anyhow!("{e}"))?
            .len()
            == 32,
        "invalid blockhash"
    );
    Ok(s.into())
}
fn first_slot(v: &Value, start: u64) -> Result<u64> {
    let rows = v.as_array().context("getBlocks result is not an array")?;
    ensure!(
        !rows.is_empty() && rows.len() <= 1024,
        "missing/bounded first epoch block"
    );
    let mut previous = None;
    for row in rows {
        let n = row.as_u64().context("noninteger slot")?;
        ensure!(
            (start..=start + 1023).contains(&n) && previous.is_none_or(|p| n > p),
            "invalid first-block census"
        );
        previous = Some(n);
    }
    rows[0].as_u64().context("first slot")
}
fn expectation(
    epoch: u64,
    first: u64,
    a: &Value,
    parent: &Value,
    z: &Value,
    evidence: Value,
) -> Result<Value> {
    let start = epoch.checked_mul(432000).context("epoch overflow")?;
    let terminal = start.checked_add(431999).context("terminal overflow")?;
    let parent_slot = a["parentSlot"].as_u64().context("first parent slot")?;
    ensure!(
        (start..=start + 1023).contains(&first) && parent_slot < start,
        "first block skips outside epoch boundary"
    );
    let parent_hash = hash_text(parent, "blockhash")?;
    ensure!(
        parent_hash == hash_text(a, "previousBlockhash")?,
        "independent first/parent blockhash disagreement"
    );
    hash_text(a, "blockhash")?;
    let terminal_parent = z["parentSlot"].as_u64().context("terminal parent slot")?;
    ensure!(
        terminal_parent >= first && terminal_parent < terminal,
        "terminal parent outside epoch"
    );
    hash_text(z, "previousBlockhash")?;
    let terminal_hash = hash_text(z, "blockhash")?;
    Ok(
        json!({"schema":"horizon-current-reader-epoch-expectation-v1","epoch":epoch,"parent_slot":parent_slot,"parent_blockhash":parent_hash,"terminal_slot":terminal,"terminal_blockhash":terminal_hash,"provenance_sha256":null,"independent_evidence":evidence}),
    )
}
struct Rpc {
    client: reqwest::Client,
    root: PathBuf,
    next_id: u64,
    evidence: Vec<Value>,
}
impl Rpc {
    async fn call(&mut self, label: &str, method: &str, params: Value) -> Result<Value> {
        self.next_id += 1;
        let request = json!({"jsonrpc":"2.0","id":self.next_id,"method":method,"params":params});
        let started = now()?;
        let mut response = self
            .client
            .post(ENDPOINT)
            .json(&request)
            .send()
            .await?
            .error_for_status()?;
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            ensure!(
                body.len() + chunk.len() <= 1 << 20,
                "RPC response exceeds bound"
            );
            body.extend_from_slice(&chunk);
        }
        let received = now()?;
        let path = self.root.join(format!("{label}.json"));
        save(&path, &body)?;
        self.evidence
            .push(json!({"path":path,"sha256":digest(&body)}));
        let v: Value = serde_json::from_slice(&body)?;
        ensure!(
            v["jsonrpc"] == "2.0"
                && v["id"] == self.next_id
                && v.get("error").is_none()
                && !v["result"].is_null(),
            "RPC returned missing/error/foreign result: {label}"
        );
        let request_path = self.root.join(format!("{label}-request.json"));
        let request_bytes = serde_json::to_vec_pretty(
            &json!({"endpoint":ENDPOINT,"request":request,"started_unix_seconds":started,"received_unix_seconds":received,"response_sha256":digest(&body)}),
        )?;
        save(&request_path, &request_bytes)?;
        self.evidence
            .push(json!({"path":request_path,"sha256":digest(&request_bytes)}));
        eprintln!("finalized boundary source: {label} complete at {received}");
        Ok(v["result"].clone())
    }
    async fn block(&mut self, label: &str, slot: u64) -> Result<Value> {
        self.call(label,"getBlock",json!([slot,{"commitment":"finalized","transactionDetails":"none","rewards":false,"maxSupportedTransactionVersion":0}])).await
    }
}
async fn run(args: Vec<String>) -> Result<()> {
    ensure!(
        args.len() == 5 && args[1] == "--plan-sha256" && args[3] == "--self-sha256",
        "usage: horizon-epoch-boundaries PLAN --plan-sha256 HEX --self-sha256 HEX"
    );
    ensure!(unsafe { libc::geteuid() } == 0, "root required");
    ensure!(
        digest(&fs::read("/proc/self/exe")?) == args[4],
        "running image differs"
    );
    let raw = plan_bytes(Path::new(&args[0]))?;
    ensure!(digest(&raw) == args[2], "plan digest differs");
    let p: Plan = serde_json::from_slice(&raw)?;
    ensure!(
        p.schema == "horizon-independent-epoch-boundary-plan-v1" && (201..=300).contains(&p.epoch),
        "foreign plan/epoch"
    );
    private_directory(&p.output_directory)?;
    ensure!(
        fs::read_dir(&p.output_directory)?.next().is_none(),
        "use a fresh evidence directory; preserve earlier attempts"
    );
    save(
        &p.output_directory.join("intent.json"),
        &serde_json::to_vec_pretty(
            &json!({"schema":"horizon-independent-epoch-boundary-intent-v1","plan":args[0],"plan_sha256":args[2],"tool_sha256":args[4],"epoch":p.epoch,"started_unix_seconds":now()?,"remote_mutations":false,"publication_authorized":false}),
        )?,
    )?;
    let mut rpc = Rpc {
        client: reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()?,
        root: p.output_directory.clone(),
        next_id: p.epoch * 100,
        evidence: Vec::new(),
    };
    let start = p.epoch * 432000;
    let slots = rpc
        .call(
            "first-block-census",
            "getBlocks",
            json!([start,start+1023,{"commitment":"finalized"}]),
        )
        .await?;
    let first = first_slot(&slots, start)?;
    let a = rpc.block("first-block", first).await?;
    let parent_slot = a["parentSlot"].as_u64().context("first parent slot")?;
    ensure!(
        parent_slot < start,
        "first block does not establish epoch parent"
    );
    let parent = rpc.block("parent-block", parent_slot).await?;
    let terminal = rpc.block("terminal-block", start + 431999).await?;
    let v = expectation(p.epoch, first, &a, &parent, &terminal, json!(rpc.evidence))?;
    private_directory(&p.output_directory)?;
    ensure!(plan_bytes(Path::new(&args[0]))? == raw, "plan changed");
    let bytes = serde_json::to_vec_pretty(&v)?;
    let path = p.output_directory.join(format!("epoch-{}.json", p.epoch));
    save(&path, &bytes)?;
    println!(
        "{}",
        json!({"expectation":path,"sha256":digest(&bytes),"completed_unix_seconds":now()?,"archive_verified":false,"publication_authorized":false,"remote_mutations":false})
    );
    Ok(())
}
fn main() {
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(run(std::env::args().skip(1).collect()));
    if let Err(e) = result {
        eprintln!("boundary collection rejected: {e:#}");
        std::process::exit(1)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ordered_first_block_census() {
        assert_eq!(first_slot(&json!([1001, 1004]), 1000).unwrap(), 1001);
        for bad in [
            json!([]),
            json!([999]),
            json!([1001, 1001]),
            json!([1002, 1001]),
            json!([2024]),
            json!(["1000"]),
        ] {
            assert!(first_slot(&bad, 1000).is_err());
        }
    }
    #[test]
    fn independent_parent_and_terminal_must_agree() {
        let start = 247 * 432000;
        let hash = bs58::encode([1u8; 32]).into_string();
        let other = bs58::encode([2u8; 32]).into_string();
        let a = json!({"parentSlot":start-1,"previousBlockhash":hash,"blockhash":other});
        let parent = json!({"blockhash":hash});
        let z = json!({"parentSlot":start+431998,"previousBlockhash":other,"blockhash":hash});
        assert!(expectation(247, start, &a, &parent, &z, json!([])).is_ok());
        assert!(expectation(247, start, &a, &json!({"blockhash":other}), &z, json!([])).is_err());
        let mut bad = a.clone();
        bad["parentSlot"] = json!(start);
        assert!(expectation(247, start, &bad, &parent, &z, json!([])).is_err());
        let mut bad = z.clone();
        bad["parentSlot"] = json!(start + 431999);
        assert!(expectation(247, start, &a, &parent, &bad, json!([])).is_err());
        let mut bad = z.clone();
        bad["blockhash"] = json!("invalid");
        assert!(expectation(247, start, &a, &parent, &bad, json!([])).is_err());
    }
}
