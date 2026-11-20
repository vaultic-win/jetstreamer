//! Select the unresolved transaction without broadening execution or publication authority.
const SLOT: u64 = 59_183_097;
const ENTRY: u64 = 197;
const SIGNATURE: &str =
    "2B96JV6WYJDwxNF3MS4KtS4jb1ToCcQ3xxhcKNysJsdK1jbZ45NCF1EiEWk5GK7Yr5LGVzrT1fBA6Jnvc9VU36L3";

pub fn selected(slot: u64, entry: u64, signature: &str) -> bool {
    slot == SLOT && entry == ENTRY && signature == SIGNATURE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_neighboring_entries_slots_and_other_signatures() {
        assert!(selected(SLOT, ENTRY, SIGNATURE));
        for slot in [SLOT - 1, SLOT + 1].iter() {
            assert!(!selected(*slot, ENTRY, SIGNATURE));
        }
        for entry in [ENTRY - 1, ENTRY + 1].iter() {
            assert!(!selected(SLOT, *entry, SIGNATURE));
        }
        assert!(!selected(SLOT, ENTRY, ""));
        assert!(!selected(SLOT, ENTRY, &SIGNATURE.replacen('2', "3", 1)));
    }
}
