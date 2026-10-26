//! Exact extraction-owned status cleanup; no archive or downstream authority.
use super::*;

fn row<'a>(fleet: &'a Value, owners: &[(String, String)], epoch: u64) -> Option<&'a Value> {
    if !matches!(epoch, 225 | 226) || owners.len() != 1 {
        return None;
    }
    let rows = fleet["epoch225_extraction"].as_array()?;
    let matching = rows
        .iter()
        .filter(|r| r["epoch"] == epoch && r["live"] == false && r["producer"]["Id"] == owners[0].0)
        .collect::<Vec<_>>();
    match matching.as_slice() {
        [row] => Some(*row),
        _ => None,
    }
}
pub(super) fn recognized(fleet: &Value, owners: &[(String, String)], epoch: u64) -> bool {
    row(fleet, owners, epoch).is_some()
}
pub(super) fn validate(
    current: &BTreeMap<String, Value>,
    fleet: &Value,
    owners: &[(String, String)],
    epoch: u64,
) -> Result<()> {
    let row =
        row(fleet, owners, epoch).context("exact epoch 225 terminal extraction row absent")?;
    fleet::epoch225_extraction_cleanup_current(
        row,
        current
            .get(&owners[0].0)
            .context("epoch 225 current terminal owner omitted")?,
        &owners[0],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn e225_cleanup_routes_only_one_exact_inactive_epoch_and_preserves_replacement_checks() {
        let owners = vec![(
            "horizon-qualify-225-prefix-extract-v1.service".into(),
            "a".repeat(32),
        )];
        let row = json!({"epoch":225,"live":false,"producer":{"Id":owners[0].0}});
        let f = json!({"epoch225_extraction":[row]});
        assert!(recognized(&f, &owners, 225));
        assert!(!recognized(&f, &owners, 226));
        assert!(!recognized(&f, &owners, 224));
        let duplicate = json!({"epoch225_extraction":[row,row]});
        assert!(!recognized(&duplicate, &owners, 225));
        let mut live = f.clone();
        live["epoch225_extraction"][0]["live"] = json!(true);
        assert!(!recognized(&live, &owners, 225));
        let mut other = owners.clone();
        other[0].0 = "foreign.service".into();
        assert!(!recognized(&f, &other, 225));
        other.push(owners[0].clone());
        assert!(!recognized(&f, &other, 225));
    }
}
