//! Retire the reproduced account files from epoch 227's stopped input probe.
use super::*;

const PROOF: &str =
    "/var/lib/jetstreamer/horizon227-attempt1-unpacked-reproduction-v322/completion.json";
const PROOF_SHA: &str = "eb821bdd692c5f5a42a3213f2d593ab9233f4ef033f477d38b49bd9d6aaf9d9f";
const STATE: &str = "/var/lib/jetstreamer/horizon227-attempt1-accounts-retirement-v323";
const ROOT: &str =
    "/home/ubuntu/.jetstreamer-private/native-input227-attempt1-216c2d0e-retained-v1";
const ORIGINAL_UNIT: &str = "horizon-native-input-227-capped-710f6523-v1.service";
const ORIGINAL_INVOCATION: &str = "216c2d0e7d5b4bd6bc843063255251f1";

fn body_manifest(target: &Path, device: u64, expected_count: u64) -> Result<String> {
    let mut entries = fs::read_dir(target)?.collect::<io::Result<Vec<_>>>()?;
    ensure!(
        entries.len() as u64 == expected_count,
        "account count changed"
    );
    entries.sort_by_key(|item| item.file_name());
    let mut aggregate = Sha256::new();
    for entry in entries {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_str().context("non-UTF-8 accounts filename")?;
        let (slot, id) = name.split_once('.').context("invalid accounts filename")?;
        ensure!(
            [slot, id]
                .iter()
                .all(|n| !n.is_empty() && n.bytes().all(|c| c.is_ascii_digit())),
            "unexpected file in the reproduced subtree"
        );
        let mut f = open_regular(&path)?;
        let m = f.metadata()?;
        ensure!(
            m.dev() == device && m.uid() == 1000,
            "foreign accounts file"
        );
        let mut hash = Sha256::new();
        io::copy(&mut f, &mut hash)?;
        ensure!(
            identity(&m) == identity(&f.metadata()?)
                && identity(&m) == identity(&path.symlink_metadata()?),
            "accounts file changed while read"
        );
        aggregate.update(name.as_bytes());
        aggregate.update([0]);
        aggregate.update(hash.finalize());
    }
    Ok(format!("{:x}", aggregate.finalize()))
}

pub(super) fn run(apply: bool, self_sha: &str) -> Result<()> {
    let state = Path::new(STATE);
    let mode = state.symlink_metadata()?;
    ensure!(
        state.canonicalize()? == state
            && mode.is_dir()
            && mode.uid() == 0
            && mode.mode() & 0o077 == 0,
        "unsafe receipt directory"
    );
    let proof: Value = read_bound(Path::new(PROOF), PROOF_SHA, JSON_LIMIT)?;
    let attempt = value(&proof["attempt"])?;
    ensure!(
        proof["schema"] == "foundation-epoch227-stopped-unpacked-reproduction-v322"
            && proof["epoch"] == 227
            && proof["source_matches_all_existing_bytes"] == true
            && proof["partial_file_count"] == 0
            && proof["scratch_retired"] == false
            && attempt["invocation_id"] == ORIGINAL_INVOCATION
            && attempt["unit"] == ORIGINAL_UNIT
            && attempt["entry_replay"] == false
            && attempt["outcome"] == "stopped-after-protective-guard-rejection",
        "wrong source reproduction proof"
    );
    let scope = Path::new(ROOT);
    let target = Path::new(
        proof["target"]["path"]
            .as_str()
            .context("missing account subtree")?,
    );
    ensure!(
        target.starts_with(scope.join("scratch")) && target.ends_with("unpacked/accounts"),
        "wrong account subtree"
    );
    let dev = proof["target"]["device"]
        .as_u64()
        .context("missing device")?;
    let ino = proof["target"]["inode"].as_u64().context("missing inode")?;
    let root = stopped_tree::open_root(target, dev, ino)?;
    let input = &proof["sealed_bootstrap"];
    let source = Path::new(
        input["path"]
            .as_str()
            .context("missing compressed source")?,
    );
    let f = open_regular(source)?;
    let m = f.metadata()?;
    ensure!(
        !source.starts_with(scope)
            && m.uid() == 0
            && m.mode() & 0o222 == 0
            && input["device"] == m.dev()
            && input["inode"] == m.ino()
            && input["bytes"] == m.len(),
        "retained input changed"
    );
    terminal_unit(ORIGINAL_UNIT)?;
    assert_no_nested_mount(target)?;
    let schedule = scheduled(scope, target)?;
    let consumers = process_references::scan(Path::new("/proc"), target)?;
    ensure!(
        consumers.inspected_processes > 0 && consumers.references.is_empty(),
        "live accounts references"
    );
    let check = state.join("check.json");
    let intent = state.join("intent.json");
    let completion = state.join("completion.json");
    let ledger = state.join("ledger.json");
    ensure!(!completion.exists(), "retirement is already complete");
    let current = stopped_tree::capture(&root, dev, 1000, 1000)?;
    if !apply {
        let count = proof["checked_files"]
            .as_u64()
            .context("missing accounts count")?;
        ensure!(
            !check.exists() && !intent.exists() && current.len() as u64 == count + 1,
            "unexpected retirement state"
        );
        ensure!(
            proof["file_hash_manifest_sha256"] == body_manifest(target, dev, count)?,
            "account bytes changed after reproduction"
        );
        let details = write_json(&ledger, &current)?;
        let receipt = write_json(
            &check,
            &json!({"tool_sha256":self_sha,"reproduction_sha256":PROOF_SHA,
            "ledger":details,"entries":current.len(),"scheduled":schedule,"consumers":consumers}),
        )?;
        println!("{}", serde_json::to_string(&receipt)?);
        return Ok(());
    }
    let reference = open_regular(&check)?;
    let mode = reference.metadata()?;
    ensure!(
        mode.uid() == 0 && mode.mode() & 0o222 == 0 && mode.len() <= JSON_LIMIT,
        "unsafe check receipt"
    );
    let review: Value = serde_json::from_reader(reference)?;
    ensure!(
        review["tool_sha256"] == self_sha && review["reproduction_sha256"] == PROOF_SHA,
        "wrong check receipt"
    );
    let qualified: Binding = serde_json::from_value(review["ledger"].clone())?;
    ensure!(qualified.path == ledger, "unexpected ledger");
    let expected: stopped_tree::Ledger = read_bound(&ledger, &qualified.sha256, LEDGER_LIMIT)?;
    let resuming = intent.exists();
    if resuming {
        let saved = open_regular(&intent)?;
        let mode = saved.metadata()?;
        ensure!(
            mode.uid() == 0 && mode.mode() & 0o222 == 0 && mode.len() <= JSON_LIMIT,
            "unsafe prior intent"
        );
        let previous: Value = serde_json::from_reader(saved)?;
        ensure!(
            previous["ledger_sha256"] == qualified.sha256
                && previous["tool_sha256"] == self_sha
                && previous["device"] == dev
                && previous["inode"] == ino,
            "foreign prior intent"
        );
    }
    stopped_tree::validate_remaining(&expected, &current, resuming)?;
    drop(current);
    terminal_unit(ORIGINAL_UNIT)?;
    let free = available(scope)?;
    if !resuming {
        write_json(
            &intent,
            &json!({"ledger_sha256":qualified.sha256,"tool_sha256":self_sha,"device":dev,"inode":ino,"free_before_bytes":free}),
        )?;
    }
    let removed = stopped_tree::remove_contents(&root, &expected, dev, 1000, 1000)?;
    ensure!(
        target.symlink_metadata()?.ino() == ino
            && identity(&m) == identity(&source.symlink_metadata()?),
        "source or scratch changed during retirement"
    );
    let receipt = write_json(
        &completion,
        &json!({"epoch":227,"original_invocation":ORIGINAL_INVOCATION,
        "reproduction_sha256":PROOF_SHA,"allocated_account_bytes_before":proof["allocated_bytes"],
        "recorded_entries_removed":removed,"free_at_attempt_start_bytes":free,"free_after_bytes":available(scope)?,
        "retained_compressed_source":input,"empty_accounts_root_retained":true,"remote_mutations":false}),
    )?;
    println!("{}", serde_json::to_string(&receipt)?);
    Ok(())
}
