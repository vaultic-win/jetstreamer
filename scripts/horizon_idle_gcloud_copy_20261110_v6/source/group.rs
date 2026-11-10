//! Pure bounded-input local identity checks; no account lookup or network calls.
use anyhow::{Context, Result, ensure};
use std::collections::BTreeSet;

pub fn sole_local_group(
    passwd: &str,
    groups: &str,
    nsswitch: &str,
    uid: u32,
    gid: u32,
    account: &str,
    group: &str,
) -> Result<()> {
    let mut accounts = BTreeSet::new();
    let mut selected_account = 0;
    for line in passwd.lines().filter(|s| !s.is_empty()) {
        let fields: Vec<_> = line.split(':').collect();
        ensure!(
            fields.len() == 7 && accounts.insert(fields[0]),
            "malformed or duplicate passwd account"
        );
        let user: u32 = fields[2].parse().context("passwd uid")?;
        let primary: u32 = fields[3].parse().context("passwd gid")?;
        if user == uid || fields[0] == account || primary == gid {
            ensure!(
                user == uid && fields[0] == account && primary == gid,
                "another primary member or mismatched source account"
            );
            selected_account += 1;
        }
    }
    ensure!(
        selected_account == 1,
        "exact source account missing or aliased"
    );
    let mut names = BTreeSet::new();
    let mut selected_group = 0;
    for line in groups.lines().filter(|s| !s.is_empty()) {
        let fields: Vec<_> = line.split(':').collect();
        ensure!(
            fields.len() == 4 && names.insert(fields[0]),
            "malformed or duplicate group"
        );
        let id: u32 = fields[2].parse().context("group gid")?;
        if id == gid || fields[0] == group {
            ensure!(
                id == gid && fields[0] == group,
                "source group identity differs"
            );
            ensure!(
                fields[3].is_empty() || fields[3] == account,
                "another supplementary source group member"
            );
            selected_group += 1;
        }
    }
    ensure!(selected_group == 1, "exact source group missing or aliased");
    let mut policies = BTreeSet::new();
    for line in nsswitch.lines() {
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let (key, value) = line.split_once(':').context("malformed nsswitch line")?;
        let key = key.trim();
        if ["passwd", "group", "initgroups"].contains(&key) {
            ensure!(policies.insert(key), "duplicate identity NSS policy");
            let sources: Vec<_> = value.split_whitespace().collect();
            ensure!(
                sources == ["files"] || sources == ["files", "systemd"],
                "unqualified external or action-based identity NSS policy"
            );
        }
    }
    ensure!(
        policies.contains("passwd") && policies.contains("group"),
        "identity NSS policy missing"
    );
    Ok(())
}
