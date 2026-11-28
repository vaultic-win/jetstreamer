//! Retire the exact verified members of a closed AccountsDb, with a resume ledger.
use super::{selective_accounts::record, *};

#[derive(Deserialize)]
struct Qualified {
    anchors: Value,
    entries: stopped_tree::Ledger,
}

pub(super) fn sealed(path: &Path, limit: u64) -> Result<Binding> {
    let mut file = open_regular(path)?;
    let m = file.metadata()?;
    ensure!(
        m.uid() == 0 && m.mode() & 0o222 == 0 && m.len() <= limit,
        "unsealed retirement evidence"
    );
    Ok(Binding {
        path: path.into(),
        sha256: digest(&mut file)?,
    })
}

pub(super) fn require_census(target: &Path, files: usize, census_sha: &str) -> Result<()> {
    let output = Command::new("/usr/bin/find")
        .env("LC_ALL", "C")
        .current_dir(target)
        .args([
            "0",
            "1",
            "2",
            "3",
            "-xdev",
            "-mindepth",
            "1",
            "-maxdepth",
            "1",
            "-printf",
            "%p\\t%y\\t%n\\t%U\\t%G\\t%m\\t%D\\t%i\\t%s\\t%b\\t%T@\\t%C@\\n",
        ])
        .output()?;
    ensure!(
        output.status.success(),
        "cannot capture AccountsDb inode stamps"
    );
    let rows = output
        .stdout
        .strip_suffix(b"\n")
        .context("empty source census")?;
    let mut rows: Vec<_> = rows.split(|b| *b == b'\n').collect();
    rows.sort_unstable();
    let mut hash = Sha256::new();
    for row in &rows {
        hash.update(row);
        hash.update(b"\n");
    }
    ensure!(
        rows.len() == files && format!("{:x}", hash.finalize()) == census_sha,
        "source no longer matches the staging inode, allocation and timestamp census"
    );
    Ok(())
}

pub(super) struct Tree<'a> {
    pub epoch: u64,
    pub state: &'a Path,
    pub root: &'a File,
    pub target: &'a Path,
    pub device: u64,
    pub files: usize,
    pub allocation: u64,
    pub census_sha: &'a str,
    pub anchors: Value,
    pub readers: Value,
}

pub(super) fn run(
    apply: bool,
    tree: Tree<'_>,
    check_preserved: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let Tree {
        epoch,
        state,
        root,
        target,
        device,
        files,
        allocation,
        census_sha,
        anchors,
        readers,
    } = tree;
    let capture = || stopped_tree::capture(root, device, 1000, 1000);
    let ledger_path = state.join("ledger.json");
    let intent_path = state.join("intent.json");
    let complete_path = state.join("completion.json");
    if !apply {
        ensure!(!intent_path.try_exists()?, "retirement has already started");
        let entries = capture()?;
        require_census(target, files, census_sha)?;
        stopped_tree::validate_remaining(&entries, &capture()?, false)?;
        ensure!(entries.len() == files + 5, "wrong source entry count");
        let reference = if ledger_path.try_exists()? {
            let reference = sealed(&ledger_path, LEDGER_LIMIT)?;
            let prior: Qualified = read_bound(&reference.path, &reference.sha256, LEDGER_LIMIT)?;
            ensure!(
                prior.anchors == anchors && prior.entries == entries,
                "conflicting ledger"
            );
            reference
        } else {
            record(
                &ledger_path,
                &json!({
                    "anchors":anchors,"entries":entries,
                    "scheduled":readers["scheduled"],"consumers":readers["processes"]
                }),
            )?
        };
        println!("{}", serde_json::to_string(&reference)?);
        return Ok(());
    }

    let ledger = sealed(&ledger_path, LEDGER_LIMIT)?;
    let qualified: Qualified = read_bound(&ledger.path, &ledger.sha256, LEDGER_LIMIT)?;
    ensure!(
        qualified.anchors == anchors,
        "source or retained evidence changed since check"
    );
    let expected = qualified.entries;
    ensure!(
        expected.len() == files + 5,
        "wrong qualified source entry count"
    );
    let authorization = json!({"ledger":ledger,"anchors":anchors});
    let pending = snapshot288::lookup_receipt(&intent_path)?;
    if let Some((_, intent)) = &pending {
        ensure!(
            intent["authorization"] == authorization,
            "conflicting retirement intent"
        );
    }
    let current = capture()?;
    stopped_tree::validate_remaining(&expected, &current, pending.is_some())?;
    if let Some((reference, done)) = snapshot288::lookup_receipt(&complete_path)? {
        ensure!(
            pending.is_some() && done["authorization"] == authorization && current.len() == 1,
            "retirement completion and remaining source disagree"
        );
        println!("{}", serde_json::to_string(&reference)?);
        return Ok(());
    }
    let free_before = available(target)?;
    let intent = match pending {
        Some((prior, _)) => prior,
        None => record(
            &intent_path,
            &json!({"authorization":authorization,"free_before_bytes":free_before}),
        )?,
    };
    drop(current);
    let removed = stopped_tree::remove_contents(root, &expected, device, 1000, 1000)?;
    let named_root = target.symlink_metadata()?;
    ensure!(
        named_root.dev() == device && named_root.ino() == root.metadata()?.ino(),
        "source root changed"
    );
    check_preserved()?;
    let completion = record(
        &complete_path,
        &json!({
            "authorization":authorization,"intent":intent,"epoch":epoch,"removed_entries_this_attempt":removed,
            "verified_allocated_bytes_removed":allocation,"free_at_attempt_start_bytes":free_before,
            "free_after_bytes":available(target)?,"empty_root_retained":true,
            "r2_mutations":false,"publication_authorized":false,
        }),
    )?;
    println!("{}", serde_json::to_string(&completion)?);
    Ok(())
}
