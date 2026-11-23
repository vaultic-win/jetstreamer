//! Fixed producer namespaces and finalized RPC evidence for the recovering peers.
use super::*;

#[cfg(feature = "cold168")]
pub(super) const PRODUCER_UNIT: &str = "horizon-qualify-168-full-metered-cold-v4-20261123.service";
#[cfg(feature = "cold168")]
pub(super) const PRODUCER_IID: &str = "913443d7f9f44d7e9d3e0eec420acfab";
#[cfg(feature = "cold168")]
pub(super) const LIVE_SHA: &str =
    "0ab0e88e1182f1672c5abfb612256722b101ce6beb7a78abf361f445516598d8";
#[cfg(feature = "cold168")]
pub(super) const TERMINAL_ROOT: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch168-cold-delivery-20261123-v4";

#[cfg(feature = "source167")]
pub(super) const EPOCH: u64 = 167;
#[cfg(feature = "retry170")]
pub(super) const EPOCH: u64 = 170;

#[cfg(all(feature = "source167", not(feature = "cold167")))]
pub(super) const PRODUCER_UNIT: &str = "horizon-qualify-167-source-index-v1-20261121.service";
#[cfg(feature = "cold167")]
pub(super) const PRODUCER_UNIT: &str = "horizon-qualify-167-source-index-v3-20261122.service";
#[cfg(all(feature = "retry170", not(feature = "cold170")))]
pub(super) const PRODUCER_UNIT: &str =
    "horizon-qualify-170-replacement-local3retry10-20261121-v1.service";
#[cfg(feature = "cold170")]
pub(super) const PRODUCER_UNIT: &str =
    "horizon-qualify-170-replacement-local3retry13-20261122.service";
#[cfg(all(feature = "source167", not(feature = "cold167")))]
pub(super) const PRODUCER_IID: &str = "0876e9944c784b41afeff1b666539ead";
#[cfg(feature = "cold167")]
pub(super) const PRODUCER_IID: &str = "6e4b569b61d7420fb30a24a4ad0609dd";
#[cfg(all(feature = "retry170", not(feature = "cold170")))]
pub(super) const PRODUCER_IID: &str = "a456b826ce1c4634a2df66d66c5cc07f";
#[cfg(feature = "cold170")]
pub(super) const PRODUCER_IID: &str = "c44b5215f8d949159e7ce9cf911e9be1";
#[cfg(all(feature = "source167", not(feature = "cold167")))]
pub(super) const LIVE_SHA: &str =
    "f9b3e1fbdddfd983f1589ead46439a5bde07762cfc6151a8cfbb6f5580e818be";
#[cfg(feature = "cold167")]
pub(super) const LIVE_SHA: &str =
    "525b8104545f5d8a5716291e8540386932f49b1cfc096898fb380c602713c16e";
#[cfg(all(feature = "retry170", not(feature = "cold170")))]
pub(super) const LIVE_SHA: &str =
    "8221f8f31df8bd360b7ef95a82b6cbf04c27fff2a0dc53508f6c79d1731dff7b";
#[cfg(feature = "cold170")]
pub(super) const LIVE_SHA: &str =
    "c73815d49529c42cc70f0e7ba11ab171f9b1ecdfb92c418afbe1b7631e57d898";
#[cfg(all(feature = "source167", not(feature = "cold167")))]
pub(super) const TERMINAL_ROOT: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch167-current-delivery-20261121-v1";
#[cfg(feature = "cold167")]
pub(super) const TERMINAL_ROOT: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch167-cold-delivery-20261122-v3";
#[cfg(all(feature = "retry170", not(feature = "cold170")))]
pub(super) const TERMINAL_ROOT: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch170-current-delivery-20261121-v1";
#[cfg(feature = "cold170")]
pub(super) const TERMINAL_ROOT: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch170-cold-delivery-20261122-v13";

#[cfg(feature = "full172")]
pub(super) const EPOCH: u64 = 172;
#[cfg(feature = "full172")]
pub(super) const PRODUCER_UNIT: &str = "horizon-qualify-172-full-half-core-20261120-v1.service";
#[cfg(feature = "full172")]
pub(super) const PRODUCER_IID: &str = "0e17b745938546608b0bdc52815151d0";
#[cfg(feature = "full172")]
pub(super) const LIVE_SHA: &str =
    "4d4e760ba2d4cb53368cfc7c616044f789f82f66934499ad91e5797f41cf6dc2";
#[cfg(feature = "full172")]
pub(super) const TERMINAL_ROOT: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch172-current-delivery-20261121-v1";

fn document(reference: &Value, path: &Path) -> Result<Value> {
    ensure!(
        reference["path"] == json!(path) && path.canonicalize()? == path,
        "unexpected evidence path"
    );
    let raw = small(path, 1 << 20)?;
    ensure!(
        reference["sha256"] == format!("{:x}", Sha256::digest(&raw)),
        "evidence digest changed"
    );
    Ok(serde_json::from_slice(&raw)?)
}

fn rpc(record: &Value, root: &Path, name: &str, method: &str, slot: u64) -> Result<Value> {
    let refs = record["independent_evidence"]
        .as_array()
        .context("RPC bindings")?;
    let get = |suffix: &str| -> Result<(&Value, Value)> {
        let p = root.join(format!("{name}{suffix}.json"));
        let mut matching = refs.iter().filter(|r| r["path"] == json!(p));
        let r = matching.next().context("missing RPC binding")?;
        ensure!(matching.next().is_none(), "ambiguous RPC binding");
        Ok((r, document(r, &p)?))
    };
    let (_, call) = get("-request")?;
    let (rr, response) = get("")?;
    let req = &call["request"];
    let args = req["params"].as_array().context("RPC parameters")?;
    ensure!(
        call["endpoint"] == "https://api.mainnet-beta.solana.com"
            && req["method"] == method
            && args.first() == Some(&json!(slot))
            && args
                .last()
                .is_some_and(|last| last["commitment"] == "finalized")
            && response["id"] == req["id"]
            && response["jsonrpc"] == "2.0"
            && response.get("error").is_none()
            && call["response_sha256"] == rr["sha256"],
        "different finalized request or response"
    );
    Ok(response["result"].clone())
}

pub(super) fn boundary(live: &Value) -> Result<receipt::TerminalBoundary> {
    #[cfg(not(any(feature = "full172", feature = "cold168")))]
    let root=Path::new("/home/sol/.jetstreamer-private/epoch166167170-current-publication-20261120-v1/finalized-boundaries").join(format!("epoch-{EPOCH}"));
    #[cfg(not(any(feature = "full172", feature = "cold168")))]
    let p = root.join(format!("epoch-{EPOCH}.json"));
    #[cfg(feature = "full172")]
    let inputs = Path::new(
        "/var/lib/jetstreamer/horizon_runtime_data/producer-publication-inputs-20261121-v1",
    );
    #[cfg(feature = "full172")]
    let (root, p) = (
        inputs.join("epoch172-rpc-evidence"),
        inputs.join("epoch-expectations/epoch-172.json"),
    );
    #[cfg(feature = "cold168")]
    let inputs = Path::new(
        "/var/lib/jetstreamer/horizon_runtime_data/epoch168-current-delivery-20261121-v1",
    );
    #[cfg(feature = "cold168")]
    let (root, p) = (
        inputs.join("rpc-evidence"),
        inputs.join("epoch-expectations/epoch-168.json"),
    );
    let bindings = Path::new(
        "/var/lib/jetstreamer/horizon_runtime_data/epoch168-current-delivery-20261121-v1/epoch-expectations/bindings.json",
    );
    let manifest = &live["boundary_manifest"];
    ensure!(
        manifest["sha256"] == "b31b09549161b515da4d254662545ed11dbd2b0d33cb9263072485cbd6985488",
        "foreign boundary inventory"
    );
    let binding = document(manifest, bindings)?;
    let reference = &live["independent_boundary"];
    ensure!(
        &binding[EPOCH.to_string()] == reference,
        "different independent boundary"
    );
    let row = document(reference, &p)?;
    let start = EPOCH * 432_000;
    let last = start + 431_999;
    ensure!(
        row["schema"] == "horizon-current-reader-epoch-expectation-v1"
            && row["epoch"] == EPOCH
            && live["epoch_bounds"] == json!([start, last])
            && row["terminal_slot"] == last,
        "foreign epoch bounds"
    );
    let times = rpc(&row, &root, "first-block-census", "getBlocks", start)?;
    let first = times[0].as_u64().context("first produced slot")?;
    let first_row = rpc(&row, &root, "first-block", "getBlock", first)?;
    let parent = row["parent_slot"].as_u64().context("parent slot")?;
    let earlier = rpc(&row, &root, "parent-block", "getBlock", parent)?;
    let end = rpc(&row, &root, "terminal-block", "getBlock", last)?;
    ensure!(
        start <= first
            && first <= last
            && parent < start
            && first_row["parentSlot"] == parent
            && earlier["blockhash"] == row["parent_blockhash"]
            && first_row["previousBlockhash"] == row["parent_blockhash"]
            && end["blockhash"] == row["terminal_blockhash"],
        "inconsistent finalized boundaries"
    );
    let decoded = bs58::decode(s(&end["blockhash"])?).into_vec()?;
    Ok(receipt::TerminalBoundary {
        epoch: EPOCH,
        last_block: last,
        last_block_hash: decoded
            .try_into()
            .map_err(|_| anyhow::anyhow!("blockhash length"))?,
    })
}

fn file_hash(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hash = Sha256::new();
    std::io::copy(&mut file, &mut hash)?;
    Ok(format!("{:x}", hash.finalize()))
}

fn matches_identity(path: &Path, identity: &Value) -> Result<()> {
    let meta = path.metadata()?;
    ensure!(
        meta.dev() == identity["device"] && meta.ino() == identity["inode"],
        "different live inode at {}",
        path.display()
    );
    Ok(())
}

pub(super) fn live_namespace(live: &Value) -> Result<Value> {
    let native = &live["native"];
    let p = &native["parent"];
    let w = &native["worker"];
    let proc = |row: &Value| -> Result<PathBuf> {
        Ok(Path::new("/proc").join(row["pid"].as_u64().context("PID")?.to_string()))
    };
    let node = proc(p)?;
    let worker = proc(w)?;
    ensure!(
        process_bound(p)? && process_bound(w)? && show(UNIT)?["InvocationID"] == IID,
        "wrong live actors"
    );
    let ns = fs::read_link(node.join("ns/mnt"))?;
    ensure!(
        fs::read_link(worker.join("ns/mnt"))? == ns,
        "worker changed mount namespace"
    );
    let root = node.join("root");
    let args = fs::read(node.join("cmdline"))?;
    let args = std::str::from_utf8(&args)?
        .strip_suffix('\0')
        .context("incomplete argument list")?
        .split('\0')
        .collect::<Vec<_>>();
    ensure!(
        live["normal_argv"] == json!(args),
        "different producer arguments"
    );
    let cgroup = format!("0::/system.slice/{UNIT}");
    for (path, actor, key) in [
        (&node, p, "executable_sha256"),
        (&worker, w, "worker_sha256"),
    ] {
        ensure!(
            fs::read_to_string(path.join("cgroup"))?.trim() == cgroup,
            "foreign cgroup"
        );
        let executable = path.join("exe");
        matches_identity(&executable, &actor["identity"])?;
        let actual = root.join(Path::new(s(&actor["exe"])?).strip_prefix("/")?);
        matches_identity(&actual, &actor["identity"])?;
        ensure!(
            file_hash(&executable)? == live[key],
            "executing image digest changed"
        );
    }
    let mut manifests = args
        .iter()
        .filter_map(|arg| arg.strip_prefix("--cohort-manifest="));
    let visible_manifest = manifests.next().context("missing manifest")?;
    ensure!(manifests.next().is_none(), "duplicate manifest");
    let in_namespace = root.join(Path::new(visible_manifest).strip_prefix("/")?);
    let published = Path::new(s(&live["manifest"]["path"])?);
    ensure!(
        file_hash(&in_namespace)? == live["manifest"]["sha256"]
            && file_hash(published)? == live["manifest"]["sha256"],
        "different namespace manifest"
    );
    let partial = &native["open_work_archive"];
    matches_identity(
        &node
            .join("fd")
            .join(partial["fd"].as_u64().context("archive fd")?.to_string()),
        partial,
    )?;
    for recorded in [
        &live["output"],
        &live["private_batch_receipts"],
        &live["producer_log"],
        &native["lock"],
        partial,
    ] {
        let absolute = Path::new(s(&recorded["path"])?);
        matches_identity(&root.join(absolute.strip_prefix("/")?), recorded)?;
        matches_identity(absolute, recorded)?;
    }
    let b = boundary(live)?;
    ensure!(
        process_bound(p)?
            && process_bound(w)?
            && fs::read_link(node.join("ns/mnt"))? == ns
            && show(UNIT)?["InvocationID"] == IID,
        "producer changed during proof"
    );
    Ok(
        json!({"epoch":EPOCH,"producer_unit":UNIT,"invocation_id":IID,"mount_namespace":ns,"node":p,"worker":w,
              "manifest_in_namespace":visible_manifest,"manifest":live["manifest"],"local_open_archive":partial,
              "finalized_terminal_slot":b.last_block,"finalized_terminal_blockhash":bs58::encode(b.last_block_hash).into_string(),
              "archive_publication_authorized":false}),
    )
}
