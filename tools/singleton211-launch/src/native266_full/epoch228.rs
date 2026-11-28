//! Bounded archive replay with the original cold reservation intact.
use super::*;
pub(super) const STATE: &str = "/var/lib/jetstreamer/horizon228-native-root-tail-v166-a1";
pub(super) const CTRL: &str = "horizon228-native-root-tail-v166-a1.service";
pub(super) const GUARD: &str =
    "/var/lib/jetstreamer/horizon228-demotion-controls-v160-a1-qualified/guard";
pub(super) const GUARD_SHA: &str =
    "98ae85499fd21fa294104a1ff05c21dc155c9aa14ea10a70a0b29302d853dbfb";
pub(super) const MEMORY: u64 = 120_000_000_000;
pub(super) const ROOT_BYTES: u64 = 112 << 30;
pub(super) const ASSIGNED: u64 = MEMORY + GUARD_MEM + CONTROL_MEM;
const U251: &str = "horizon-qualify-251-replacement-20261118-v1.service";
const IID251: &str = "cd2477bfec7f4e498545762c633e7bb0";
const PAIR: &str = "8248727043dc05b54effd1b383e8094283970d673a33dd65e0ff9aababa968b2";
const WORKER: &str =
    "/var/lib/jetstreamer/horizon228-demotion-bank-9d2fd8d4-v158-v2-qualified/worker";
pub(super) const WORKER_SHA: &str =
    "16d4b15881979bb7d65a0f49408580d4508b451a5953f35cbb60505d2e3cee00";
const SNAP: &str = "/var/lib/jetstreamer/horizon-contiguous-228-230-current-46b4b4a-v1/snapshot-98495291-GfiRSgpC1qvH3uxVd9VAtYZ6qKM8fcdkyoyAkhF7izLq.tar.zst";
const HASHES: &str = "/var/lib/jetstreamer/horizon-bounded228-inputs-v2/epoch-hashes.txt";
const GENESIS: &str = "/var/lib/jetstreamer/horizon-stage227-bootstrap-dcaafc6-v1/genesis.tar.bz2";
const CLOSE_SOURCE: &str = "f797454ebc571dd2f062f683e68524d61f5039b3";
const CLOSE_TEST: &str =
    "epoch228_demotion::tests::qualification_requires_a_natural_reap_after_shutdown";

fn one<T>(mut rows: impl Iterator<Item = T>) -> Result<T> {
    let value = rows.next().context("missing original row")?;
    ensure!(rows.next().is_none(), "ambiguous original row");
    Ok(value)
}
// The original delivery writer stores its digest-pinned receipts as root-owned 0600 files.
fn read_terminal_receipt(receipt: &Bound) -> Result<Value> {
    trusted_parents(&receipt.path)?;
    receipt.json()
}

pub(super) fn proof251(n: &mut Native, fleet: &Value, ledger: &Value) -> Result<Value> {
    let source = Path::new("/var/lib/jetstreamer/horizon-singleton-delivery251-20261119-v1");
    let hand = Bound::new(
        source.join("terminal-handoff.json"),
        "85a9e5c794ebbb2699f00e0371aaaa2d8c4550c17622b967ae35defd13a0d65d",
    );
    let drain = Bound::new(
        source.join("terminal-drain.json"),
        "dc4e672d2b95528a5758ae06355819d8a2f7bfe17fa80d2218c7f3c8ad1f6194",
    );
    let h = read_terminal_receipt(&hand)?;
    let d = read_terminal_receipt(&drain)?;
    let row = one(rows(ledger, "reservations")?
        .iter()
        .filter(|v| v["unit"] == U251))?;
    ensure!(
        row["invocation_id"] == IID251
            && row["maximum_memory_bytes"] == 128_000_000_000u64
            && row["remaining_disk_growth_bytes"] == 506191984640u64
            && row.get("release") == Some(&Value::Null),
        "epoch 251 reservation"
    );
    binding(&row["source"])?.sealed()?;
    ensure!(
        d["terminal_handoff"] == json!(hand)
            && d["producer_cgroup_drained"] == true
            && d["resource_release_authorized"] == false
            && h["producer"]["unit"] == d["producer"]["unit"],
        "epoch 251 drain"
    );
    for c in ["first_census", "second_census"] {
        ensure!(
            d[c]["cgroup_present"] == false && d[c]["descendant_processes"] == 0,
            "original 251 census"
        );
    }
    let plan = Bound::new(text(fleet, "plan")?, text(fleet, "plan_sha256")?).json()?;
    let gate = &plan["gates"]["251"];
    let evidence = rows(gate, "evidence")?;
    ensure!(
        gate["state"] == "staged-admissible"
            && evidence.contains(&json!(hand))
            && evidence.contains(&json!(drain))
            && !rows(fleet, "active")?.iter().any(|v| v["epoch"] == 251),
        "251 has new work or evidence"
    );
    let m = n.show(U251)?;
    for key in [
        "Id",
        "InvocationID",
        "NRestarts",
        "Result",
        "SubState",
        "MainPID",
        "ActiveState",
        "LoadState",
        "ExecMainCode",
        "ExecMainStatus",
    ] {
        ensure!(
            m[key] == h["producer"]["unit"][key],
            "251 terminal manager changed: {key}"
        );
    }
    ensure!(
        m["Id"] == U251
            && m["InvocationID"] == IID251
            && m["MainPID"] == "0"
            && m["Result"] == "success",
        "original 251 owner"
    );
    live::verify_drained_group(U251)?;
    let batch = local_pair(&h)?;
    Ok(
        json!({"unit":U251,"invocation_id":IID251,"handoff":hand,"drain":drain,"batch":batch,"retained_disk_bytes":506191984640u64,"assigned_memory_bytes":ASSIGNED,"retained_memory_bytes":128_000_000_000u64-ASSIGNED,"disk_credit":0}),
    )
}
fn local_pair(h: &Value) -> Result<Bound> {
    let batch = binding(&h["source"]["publication_receipt"])?;
    let meta = identity(&batch.path)?;
    ensure!(
        meta.2 < 16 << 20
            && meta.3 == 1000
            && meta.4 & 0o022 == 0
            && batch.sha256 == "54be6d7331d268131e0ea2c23765e87beebca1495e0cafb77332a8e705122b2a",
        "epoch 251 batch identity"
    );
    let contents = fs::read(&batch.path)?;
    ensure!(
        digest(&contents) == batch.sha256 && identity(&batch.path)? == meta,
        "epoch 251 batch changed"
    );
    let b: Value = serde_json::from_slice(&contents)?;
    let member = one(rows(&b["outcome"], "members")?.iter())?;
    ensure!(
        b["outcome"]["kind"] == "committed"
            && b["epochs"] == json!([251])
            && member["archive_sha256"] == PAIR,
        "251 committed archive"
    );
    let out = Path::new(
        "/home/ubuntu/.jetstreamer-private/qualification-251-replacement-20261118-v1/output",
    );
    for (part, committed, name) in [
        ("archive", "committed_archive", "epoch-251.jet"),
        ("sidecar", "committed_checksum", "epoch-251.jet.sha256"),
    ] {
        let p = out.join(name);
        let custody = &h["source"][part];
        let id = &member[committed];
        let m = fs::symlink_metadata(&p)?;
        ensure!(
            p.canonicalize()? == p
                && m.is_file()
                && custody["path"] == json!(p)
                && custody["identity"] == *id
                && m.dev() == num(id, "device")?
                && m.ino() == num(id, "inode")?
                && m.len() == num(id, "length")?
                && u64::from(m.mode()) == num(id, "mode")?
                && u64::from(m.uid()) == num(id, "uid")?
                && u64::from(m.gid()) == num(id, "gid")?
                && m.nlink() == num(id, "link_count")?
                && m.mtime() == num(id, "modified_seconds")? as i64
                && m.mtime_nsec() == num(id, "modified_nanoseconds")? as i64
                && m.ctime() == num(id, "changed_seconds")? as i64
                && m.ctime_nsec() == num(id, "changed_nanoseconds")? as i64,
            "251 archive pair changed"
        );
    }
    ensure!(
        fs::read_to_string(out.join("epoch-251.jet.sha256"))? == format!("{PAIR}  epoch-251.jet\n")
            && member["committed_archive"]["length"] == 180869655584u64,
        "251 local pair"
    );
    Ok(batch)
}
pub(super) fn mapped_command(m: &Value, book: &Value) -> Result<()> {
    let proc = Path::new("/proc").join(text(m, "MainPID")?);
    let argv = rows(book, "argv")?
        .iter()
        .map(|a| a.as_str().context("uploader argument"))
        .collect::<Result<Vec<_>>>()?;
    let exe = Path::new(argv.first().context("missing sealed command")?);
    let mut command = Vec::new();
    for arg in &argv {
        command.extend_from_slice(arg.as_bytes());
        command.push(0);
    }
    ensure!(
        fs::read(proc.join("cmdline"))? == command
            && fs::read_link(proc.join("exe"))? == exe
            && metadata_identity(&fs::metadata(proc.join("exe"))?) == identity(exe)?,
        "different mapped process"
    );
    Ok(())
}
pub(super) fn kernel(p: &Profile, owner: &Value, fit: &Value) -> Result<()> {
    let group = Path::new("/sys/fs/cgroup/system.slice").join(&p.unit);
    let cpus = rows(fit, "cpus")?
        .iter()
        .map(|c| {
            c.as_u64()
                .context("elected CPU")
                .and_then(|n| u32::try_from(n).map_err(Into::into))
        })
        .collect::<Result<BTreeSet<_>>>()?;
    let status = fs::read_to_string(
        Path::new("/proc")
            .join(text(owner, "MainPID")?)
            .join("status"),
    )?;
    let actual = status
        .lines()
        .find_map(|l| l.strip_prefix("Cpus_allowed_list:"))
        .context("held affinity")?;
    ensure!(
        cpus.len() == 8
            && funding::cpus(actual)? == cpus
            && funding::cpus(&fs::read_to_string(group.join("cpuset.cpus.effective"))?)? == cpus
            && fs::read_to_string(group.join("cpu.max"))?.trim() == "800000 100000"
            && fs::read_to_string(group.join("pids.max"))?.trim() == "512"
            && owner["TasksMax"] == "512",
        "held CPU or task envelope"
    );
    let memory = if p.lane.is_bounded() {
        bounded::MEMORY
    } else if matches!(p.lane, Lane::Instructions266 | Lane::Turnover266) {
        successor::MEMORY
    } else {
        MEMORY
    };
    ensure!(
        fit["winner"]["memory"] == memory,
        "incorrect elected memory"
    );
    live::finite_owner(owner, &p.unit, text(owner, "InvocationID")?, memory)?;
    Ok(())
}
pub(super) fn funding(n: &mut Native, r: &Value, fleet: &Value, ledger: &Value) -> Result<Value> {
    ensure!(
        r["epoch251_assignment"]
            == json!({"unit":U251,"invocation_id":IID251,"bytes":ASSIGNED,"disk_credit":0}),
        "explicit original 251 assignment required"
    );
    let failed = Bound::new(
        "/var/lib/jetstreamer/horizon228-demotion-live-v164-a1/failure.json",
        "9bee722146f4c487edbd017dc5d01290884b18de4841f68e7a8cd4b5b0df8996",
    );
    failed.sealed()?;
    let cold = "horizon-native-input-228-demotion-16d4b158-v1.service";
    live::verify_drained_group(cold)?;
    let plan = Bound::new(text(fleet, "plan")?, text(fleet, "plan_sha256")?).json()?;
    ensure!(
        plan["gates"]["228"]["state"] == "failed-needs-repair"
            && rows(&plan["gates"]["228"], "evidence")?.contains(&json!(failed)),
        "original epoch 228 failure was reclassified"
    );
    proof251(n, fleet, ledger)
}
fn parent(result: &Bound, parent: &Bound) -> Result<()> {
    let q = result.sealed()?;
    ensure!(
        parent.path.file_name().is_some_and(|s| s == "parent")
            && parent.path.parent() == result.path.parent()
            && result.path.file_name().is_some_and(|s| s == "result.json")
            && q["source"] == CLOSE_SOURCE
            && q["worker"] == json!(Bound::new(WORKER, WORKER_SHA))
            && q["binary"]["sha256"] == parent.sha256
            && q["natural_mismatch_replayed"] == false
            && q["leaves"].get(CLOSE_TEST).is_some(),
        "natural-close release parent"
    );
    let dir = parent.path.parent().context("release")?;
    let test = binding(&q["leaves"][CLOSE_TEST])?;
    let receipt = Bound::new(
        dir.join(test.path.file_name().context("test")?),
        test.sha256,
    )
    .sealed()?;
    ensure!(
        receipt["code"] == 0 && text(&receipt, "stdout")?.contains("1 passed; 0 failed"),
        "actual natural-close regression"
    );
    let seal = bound_at(&dir.join("deployment-seal-receipt.json"))?.sealed()?;
    for b in [parent, result] {
        ensure!(
            rows(&seal, "members")?.iter().any(|v| v["name"].as_str()
                == b.path.file_name().and_then(|x| x.to_str())
                && v["sha256"] == b.sha256),
            "parent deployment"
        );
    }
    parent.artifact()
}
fn snapshot_identity() -> Result<()> {
    let dir = Path::new(SNAP).parent().context("snapshot directory")?;
    let seal = Bound::new(
        dir.join("deployment-seal-receipt.json"),
        "119c1a46573bdd3b3667ea6de0d425267ddecf26dd0f1f4fdfc21062d1318895",
    )
    .sealed()?;
    let snapshot = one(rows(&seal, "members")?
        .iter()
        .filter(|r| r["name"].as_str() == Path::new(SNAP).file_name().and_then(|n| n.to_str())))?;
    ensure!(
        snapshot["sha256"] == "da26bd1b4b3b93be74c9dae28d1d982f821474333aa06e87f32dfa83342915f3"
            && snapshot["bytes"] == 10_510_540_911u64,
        "original sealed snapshot"
    );
    trusted_parents(Path::new(SNAP))?;
    let m = identity(Path::new(SNAP))?;
    ensure!(
        m.0 == 66305
            && m.1 == 12294366
            && m.2 == 10_510_540_911
            && m.3 == 0
            && m.4 & 0o222 == 0
            && m.8 == 1792002794
            && m.9 == 398077847,
        "original immutable snapshot changed"
    );
    Ok(())
}
fn args(p: &Profile, parent: &Bound) -> Value {
    json!([
        parent.path,
        "228",
        p.root.join("ledger"),
        "--verify",
        "--qualification-end-slot=98928278",
        format!("--snapshot-archive={SNAP}"),
        format!("--epoch-hashes={HASHES}"),
        format!(
            "--horizon-output={}",
            p.root
                .join("output/epoch-228-through-98928278.jet")
                .display()
        ),
        format!("--replay-scratch={}", p.root.join("scratch").display())
    ])
}
pub(super) fn plan(p: &Profile, cap: u64, r: &Value) -> Result<Value> {
    let b = binding(&r["parent"])?;
    let result = binding(&r["parent_result"])?;
    parent(&result, &b)?;
    let worker = Bound::new(WORKER, WORKER_SHA);
    worker.artifact()?;
    let genesis = Bound::new(
        GENESIS,
        "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945",
    );
    genesis.artifact()?;
    Bound::new(
        HASHES,
        "b430b5bd98f75f718fe7b96a9a900173f9c9c4e469ed3a0b1583b663aa6ae154",
    )
    .artifact()?;
    snapshot_identity()?;
    Ok(
        json!({"mode":p.mode,"unit":p.unit,"root":p.root,"root_cap":cap,"parent":b,"parent_result":result,"worker":worker,"argv":args(p,&b),"projections":[{"source":genesis.path,"target":p.root.join("ledger/genesis.tar.bz2"),"sha256":genesis.sha256}]}),
    )
}
pub(super) fn verify_payload(p: &Profile, s: &Value) -> Result<()> {
    let b = binding(&s["parent"])?;
    parent(&binding(&s["parent_result"])?, &b)?;
    let worker = Bound::new(WORKER, WORKER_SHA);
    ensure!(
        s["worker"] == json!(worker)
            && s["argv"] == args(p, &b)
            && std::env::var("JETSTREAMER_HISTORICAL_WORKER_EPOCH228_DEMOTION")? == WORKER,
        "wrong archive replay payload"
    );
    worker.artifact()?;
    snapshot_identity()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "requires the original immutable 251 handoff and private local pair"]
    fn opens_original_251_batch_sidecar_and_snapshot_seal() {
        let h = read_terminal_receipt(&Bound::new(
            "/var/lib/jetstreamer/horizon-singleton-delivery251-20261119-v1/terminal-handoff.json",
            "85a9e5c794ebbb2699f00e0371aaaa2d8c4550c17622b967ae35defd13a0d65d",
        ))
        .unwrap();
        local_pair(&h).unwrap();
        snapshot_identity().unwrap();
        let mut bad = h;
        bad["source"]["sidecar"]["identity"]["inode"] = json!(0);
        assert!(local_pair(&bad).is_err());
    }
    #[test]
    fn original_251_assignment_retains_its_disk_and_unused_memory() {
        assert_eq!(ASSIGNED, 121342177280);
        assert_eq!(128000000000 - ASSIGNED, 6657822720);
        assert_eq!(ROOT_BYTES + RECEIPTS, 121332826112);
        let p = Profile::new(Lane::Epoch228, "pilot").unwrap();
        assert_eq!(
            p.unit,
            "horizon-qualify-228-demotion-root-tail-16d4b158-v1.service"
        );
        for mode in ["qa-disk", "qa-memory"] {
            let q = Profile::new(Lane::Epoch228, mode).unwrap();
            assert_ne!(p.unit, q.unit);
            assert_ne!(p.root, q.root);
            assert_ne!(p.root, Profile::new(Lane::Epoch266, mode).unwrap().root);
        }
    }
}
