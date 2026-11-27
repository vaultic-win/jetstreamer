//! Generation-pinned NY5 checkpoints from the epoch 141 original-entry recovery interval.
use crate::{BankHashExpectation, Hash, QualificationPlan, historical::HistoricalCheckpoint};
use std::collections::{BTreeMap, BTreeSet};

// (snapshot slot, legacy accounts hash, cumulative original-entry targets).
// Source comparison a1643ab0cdc8bd0ebfce4243d4be15723f93e7802797f765fe41169d2cf0af0d.
type Checkpoint = (u64, &'static str, usize);
#[rustfmt::skip]
const CHECKPOINTS: &[Checkpoint] = &[
    (60911751, "GyFbDnPnUWrFStHKfwWC98xJpmBQKjLyJ9sMf2m6MrWR", 0),
    (60921282, "6mfL2hQo8ygLjJXDwKscTEBMxZAAtopQtsautMDC8UFf", 355),
    (60928493, "7jmzVuomxUeE3WeR1XStbdiH1EDVR61Kz44km6J2jwv2", 643),
    (60935310, "FU1VdL2RPr4Ubn2SGE727jU8TQscWYn1gWbBE6peiC6r", 973),
    (60942184, "EMsXJsestzPAfJtGfNdQdeji3JmuvaCKDAMPcD8hW3ZT", 1313),
    (60948885, "2EsJDSWGzZUaPKtjefUMfFnE2TWAn8ba5hAvDZbGaFfa", 1620),
    (60955832, "B6F9ztw7sVcNeY2Sa1nKh9c2EpC5SjuVSLgoLTi4Zxo2", 1929),
    (60962797, "WzFsfhhYv92695hM43vaymygFpUxRzrkAMWmNiQVnqN", 2233),
    (60969906, "EWkJogcKkjP223PNgGs3uNz3UbMJabLaDLFTm1Gv3b5i", 2563),
    (60977093, "EdZSh4k5UBkqqqiMHXJWVurwfyPpKyprWNHR4BGP1igz", 2826),
    (60983876, "8umap7RpPBRbpdBVrkuin1jJgdfSrJzFeFjuFTvH2ZVU", 3130),
    (60990929, "GyvvxZXoTh6zbckEaSrg5aMdsbArYJ4dLKgFJsGjsbHR", 3477),
    (60997433, "DeYETJkxfpUu8MHZ84SC6Hn38SCPVAGjiiGyt48LbKyJ", 3821),
    (61004303, "Chiouvrt5AvQodK81KfKHHjGDVHXiBreRow6GLsZAtSZ", 4159),
    (61011425, "3R9iK8qtE7JRWesDtsKeVJRYgBW2tvQGqJ9EjVAcyVVR", 4485),
    (61018261, "Az8JtGmvL4h6vmEcmDji9mhxcK6EDARrLMQVhCFv1TTY", 4812),
    (61025101, "HJgPWrqDxx3cYfQkfuRZ3n5L6YbpTEPXt3TEgUvozu7e", 5140),
    (61043403, "DT57bxvFGdZC94q6mKqu7oG5E9aMhZjVQdQc21qDPK7u", 6070),
    (61050187, "2MBipTnUTBHo8wM2EyQ9PwtHxv9C1n8tF9RjMgxpE1LV", 6427),
    (61057007, "7wqc4CBEhwr57tbHHV8yZXbjuUnKGVY8TLe3y7iMQHS2", 6753),
    (61064380, "CrxVDp6gCSvg9UEzD9hLnj4QRBPrsqwLxfxnqcmGKUrq", 7045),
    (61071231, "7Qb1FMawyCaT3KSHidnym4zr6w72voRFRidGKZRZuDmt", 7298),
    (61078088, "JBZoBXoBoADBo5MToGPRYYbwWjV5Nm55FxmUDydEkoa6", 7602),
    (61085105, "3BTfd6j3PwTDLMNMTVyqmz3sE6xFjYPbmCzwiq8GxpnN", 7924),
    (61092192, "mZKiS8HX7m698BL9gn27Y5bzweQmVbUBSH4tVMuGrbe", 8221),
    (61099495, "7kMKcAk48gXqagadPNn8ZdQRd5P3Rc21gUQubEGnehwV", 8562),
    (61106537, "x9WrdMvkpb23E8BheKp8t8B9svFQUyZxBrfWyGBDciU", 8900),
    (61113179, "DmnHCC11Uj9s35sAAvevwcsy2YSFphQ4cBo6Ce153BBG", 9244),
    (61120035, "37WYK4Tnf4vmosovjZ9TpXSRwzZhqu5t8J18mxqvWdfr", 9604),
    (61127374, "ED7ZaaZ8e7vzHA3GRfpzEZqcPfeVZpeDzmDkWKCQ9MDW", 9933),
    (61134306, "GAe9Zu4A27UFNu6FSVNi5LgegmBA6cKMSH1fUdQTvtU4", 10299),
    (61141144, "F74auCYyYncWXaw3DxVKViDSJVyYzkc4wN2Qu9rP6PKz", 10608),
    (61148428, "4eDC28XATnFwMpo5RKtDJcFcAmj7bB9kcLY1zCvF4msS", 10950),
    (61155556, "G4f6Y4wCyeqHsyKv4F17f4KwqkzBPobuJAAX7VEZhs8S", 11279),
    (61162915, "4R9mXVC2nSNcNFvZgryyf9YpGmEGTTNw7MRCQbgXe3C8", 11676),
    (61170102, "3Pe6zMujTBdGiA8brnqm2uAVDH3Z9EWbXsUKmPPpw6fG", 11997),
    (61177312, "7eMAmQLNLECczRH5EjNadq5ywCcHKHWcYvPxSbDqKczg", 12326),
    (61197107, "5hdB2GVpCLgzZbfQYwkCjk1CCru7L3xvdt9doSxJTeqg", 13271),
    (61204069, "F5AjvoryueAttjhTyxwwwmAystZEA6vL74io4dVsnfLT", 13578),
    (61211049, "6GwE1qQKPrF3o5FjqJxapsj47FuBHVov4z5rMynwsgyi", 13875),
    (61218152, "HFHb3hfcqKNK4CGCLSNbrcjDYYiPA63fn59xR8FbrTXy", 14188),
    (61225291, "J6vX6ykAgVQweSKXv5L3ZhzpDvkSxDv7xnGSZcdRDF4H", 14481),
    (61232174, "GMZddFumx7BDzzwKZkWzzPAJNwEcvHunnDysuhYgvLjK", 14756),
    (61239383, "Hw6ro7QSqAv7hFzNYhg9cyacUaGGybi9g3rMv3cZfw6d", 15042),
    (61246780, "3NdxMnE82ck4hDPsVoKJEE99nbTJD6yKkGMUQaqMFirb", 15335),
    (61253988, "FXwymEJ3UPhSzn2hiRecycYxSywdAkeeaAPALBrXHjUf", 15593),
    (61261169, "G3AJKjk4L2m9ow7YqbGeimfsdnV873wUbjd7eZo2NS8f", 15873),
    (61268392, "7UF2o15KW7cuPbYuM5WgndU9ojgdNbfTiJPWHqqZer42", 16139),
    (61275400, "H5aWtEicN71ubvJ2jxuTkPHcHMtGA1zEzhHeZGVbgUT7", 16398),
    (61283070, "ADGZHiPRbJzyvdiVJCh2noVzh2nhxz6nYNYRk2r8GCfZ", 16664),
    (61290313, "7u55yxJjcaJ5ekD7qJwQMyi1J1BACkTiYEJr68QacfHi", 16934),
    (61297724, "Hm4R4NkLn1sh8bWRRdpEsEeHWpECVMVnLJZigZKnnkur", 17205),
    (61305301, "4k6WgPTzFnQhSAp1gVH6ww3NmDFcxsfEZRF9TCZfoSFa", 17487),
    (61312518, "76x4Yxcw8Mb2k7KcMNHcwd4d4qz2ZxqtsV4HtHrAnuRk", 17762),
    (61320281, "DwiR69wSEt4vYJRyvmXEeJ4TVyCTcQ8swi33Md4qqCfb", 18027),
    (61327781, "GeKVqhS7faS1ZkEUFZKYvXWux3bywyuwfW6f55SLMDcJ", 18258),
    (61328765, "8LfMXtdKmPEvMcBzEz2XZ56HZ8pUPGSaWGA6mYG4dAFY", 18283),
];

const WARMUP_TERMINAL: u64 = 60_911_999;
const VOTED_CHILD: u64 = 60_912_004;
const FIRST_HOURLY: u64 = 60_921_282;
const STRICT_WORKER: &str = "c536dcf360b7866b3aa99e0ff6d7d927dcf5db27bfbbb8f73887eb4bb7d87344";

// The capped v1.4.25 worker bounds AccountsDb shrink debt after each root.
// Both release images passed the Bank and wire-protocol qualification in 2d39915c.
const CAPPED_WORKER: &str = "fce05d551d8154ebda6ff6b3791d02f60b0e0a1e3a69982ea06fa7c31c34b759";

// The journal binds the last epoch 140 Bank. Finalized signed votes bind
// its first child and the downstream root independently of the snapshot hashes.
pub(super) fn checkpoint_slots(
    mut slots: BTreeSet<u64>,
    bootstrap: u64,
    worker: [u8; 32],
) -> Result<BTreeSet<u64>, String> {
    if worker != crate::parse_lower_sha256(STRICT_WORKER, "epoch 141 hourly strict worker")?
        && worker != crate::parse_lower_sha256(CAPPED_WORKER, "epoch 141 hourly capped worker")?
    {
        return Err("epoch 141 hourly replay initialized a different historical worker".into());
    }
    if bootstrap == CHECKPOINTS[0].0 {
        slots.extend([WARMUP_TERMINAL, VOTED_CHILD]);
    }
    Ok(slots)
}

pub(super) fn check_bank(
    checkpoint: &HistoricalCheckpoint,
    pending: &BTreeSet<u64>,
) -> Result<(), String> {
    if checkpoint.slot == FIRST_HOURLY
        && [WARMUP_TERMINAL, VOTED_CHILD]
            .iter()
            .any(|s| pending.contains(s))
    {
        return Err(
            "first hourly endpoint reached without both epoch 140 boundary observations".into(),
        );
    }
    let (bank, last_block) = match checkpoint.slot {
        WARMUP_TERMINAL => (
            "AYzJ6h8BcyraPHeypjd4uhj4L99y7WdMkmeb1L93id7L",
            "8gXVZp8oXjr7K5L59p1HxVhzKgtZFCjgUwSVXhjKxEVC",
        ),
        VOTED_CHILD => (
            "GtE6AijvzVgK1UKQ5HyVEZMGisDddVWRQkBnM74sjABf",
            "BmqNC9AmE58o2YPAWzJfmRQWLJG4xMiA1mb7pGMbABFV",
        ),
        61_328_765 => (
            "AYuUy6nQtC6u52MFZGpQU9VEZo1GqazC8LQFneWBWM6Y",
            "J6rRToKMK5DQDzVLqo7ibL3snwBYtqkYnRnQ7vXoUSEc",
        ),
        _ => return Ok(()),
    };
    if !checkpoint.slot_complete
        || Hash::new_from_array(checkpoint.bank_hash).to_string() != bank
        || Hash::new_from_array(checkpoint.last_blockhash).to_string() != last_block
    {
        return Err(format!(
            "epoch 141 hourly Bank or block hash differs at slot {}",
            checkpoint.slot
        ));
    }
    Ok(())
}

pub(super) const ORIGINAL_INDEX: &str =
    "fe38bd4ce018996349c10029720dd7f738340fb0ad30ce6b8577b9651bf87df3";
pub(super) const ORIGINAL_DATA: &str =
    "5605dd1ba08b7e790227b0efc388a74a02cdf665220d2455c3ed39f803feada0";

#[derive(Clone, Copy)]
pub(super) struct Interval {
    start: Checkpoint,
    end: Checkpoint,
}

impl Interval {
    pub(super) fn from_plan(plan: Option<(u64, u64, u64)>) -> Option<Self> {
        let (bootstrap, replay_start, terminal) = plan?;
        if bootstrap.checked_add(1)? != replay_start {
            return None;
        }
        CHECKPOINTS
            .windows(2)
            .find(|pair| pair[0].0 == bootstrap && pair[1].0 == terminal)
            .map(|pair| Self {
                start: pair[0],
                end: pair[1],
            })
    }

    pub(super) fn matches(self, bootstrap: u64, terminal: u64) -> bool {
        (bootstrap, terminal) == (self.start.0, self.end.0)
    }

    pub(super) fn contains(self, slot: u64) -> bool {
        self.start.0 < slot && slot <= self.end.0
    }

    pub(super) fn expected_targets(self) -> usize {
        self.end.2 - self.start.2
    }
}

pub(super) fn validate_roots(
    plan: QualificationPlan,
    expected: &BTreeMap<u64, BankHashExpectation>,
) -> Result<(), String> {
    let interval = Interval::from_plan(Some((
        plan.bootstrap_slot,
        plan.replay_start,
        plan.end_inclusive,
    )))
    .ok_or("unsupported hourly checkpoint pair")?;
    if plan.epoch != 141 || expected.len() != 2 {
        return Err("epoch 141 hourly replay requires both exact checkpoint filenames".into());
    }
    for (slot, hash, _) in [interval.start, interval.end] {
        let hash = hash
            .parse()
            .map_err(|_| "invalid registered hourly accounts hash")?;
        if expected.get(&slot) != Some(&BankHashExpectation::LegacyAccountsHash(hash)) {
            return Err(format!(
                "epoch 141 hourly replay requires the registered accounts hash at {slot}"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intervals_cover_the_complete_original_census_once() {
        assert_eq!(CHECKPOINTS.first().unwrap().0, 60_911_751);
        assert_eq!(CHECKPOINTS.last().unwrap().0, 61_328_765);
        assert_eq!(CHECKPOINTS.len(), 57);
        let mut targets = 0;
        for pair in CHECKPOINTS.windows(2) {
            let (a, b) = (pair[0].0, pair[1].0);
            assert!(b > a && b - a <= 19_795);
            let r = Interval::from_plan(Some((a, a + 1, b))).unwrap();
            assert!(!r.contains(a) && r.contains(a + 1) && r.contains(b) && !r.contains(b + 1));
            targets += r.expected_targets();
        }
        assert_eq!(targets, 18_283);
        assert!(Interval::from_plan(Some((60_911_751, 60_911_752, 60_921_283))).is_none());
        assert!(Interval::from_plan(Some((60_911_751, 60_911_753, 60_921_282))).is_none());
        assert!(Interval::from_plan(Some((60_911_751, 60_911_752, 61_328_765))).is_none());
    }

    #[test]
    fn first_interval_requires_the_original_parent_and_its_voted_child() {
        let worker = crate::parse_lower_sha256(STRICT_WORKER, "worker").unwrap();
        let roots = BTreeSet::from([CHECKPOINTS[0].0, FIRST_HOURLY]);
        assert!(checkpoint_slots(roots.clone(), CHECKPOINTS[0].0, [0; 32]).is_err());
        let capped = crate::parse_lower_sha256(CAPPED_WORKER, "capped worker").unwrap();
        let mut pending = checkpoint_slots(roots.clone(), CHECKPOINTS[0].0, worker).unwrap();
        assert_eq!(
            checkpoint_slots(roots, CHECKPOINTS[0].0, capped).unwrap(),
            pending
        );
        let mut checkpoint = HistoricalCheckpoint {
            slot: VOTED_CHILD,
            bank_hash: "GtE6AijvzVgK1UKQ5HyVEZMGisDddVWRQkBnM74sjABf"
                .parse::<Hash>()
                .unwrap()
                .to_bytes(),
            last_blockhash: "BmqNC9AmE58o2YPAWzJfmRQWLJG4xMiA1mb7pGMbABFV"
                .parse::<Hash>()
                .unwrap()
                .to_bytes(),
            accounts_hash: [0; 32],
            capitalization: 0,
            transaction_count: 0,
            tick_height: 0,
            slot_complete: true,
            writes: Vec::new(),
            next_write_version: 0,
        };
        check_bank(&checkpoint, &pending).unwrap();
        checkpoint.bank_hash[0] ^= 1;
        assert!(check_bank(&checkpoint, &pending).is_err());
        checkpoint.slot = FIRST_HOURLY;
        assert!(check_bank(&checkpoint, &pending).is_err());
        assert!(pending.remove(&WARMUP_TERMINAL));
        assert!(check_bank(&checkpoint, &pending).is_err());
        assert!(pending.remove(&VOTED_CHILD));
        check_bank(&checkpoint, &pending).unwrap();
    }

    #[test]
    fn both_canonical_roots_are_mandatory_and_bound_to_their_slots() {
        let plan = QualificationPlan {
            epoch: 141,
            bootstrap_slot: 60_911_751,
            replay_start: 60_911_752,
            output_slot_start: 60_912_000,
            end_inclusive: 60_921_282,
        };
        let mut expected = BTreeMap::from_iter(CHECKPOINTS[..2].iter().map(|&(slot, hash, _)| {
            (
                slot,
                BankHashExpectation::LegacyAccountsHash(hash.parse().unwrap()),
            )
        }));
        validate_roots(plan, &expected).unwrap();
        let wrong = expected.remove(&plan.bootstrap_slot).unwrap();
        assert!(validate_roots(plan, &expected).is_err());
        let terminal = expected.insert(plan.end_inclusive, wrong).unwrap();
        expected.insert(plan.bootstrap_slot, terminal);
        assert!(validate_roots(plan, &expected).is_err());
    }
}
