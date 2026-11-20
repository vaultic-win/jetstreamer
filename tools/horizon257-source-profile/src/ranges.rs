use crate::edges::EDGES;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};

pub const START: u64 = 111_024_000;
pub const SLOTS: usize = 432_000;
pub const CAR_SIZE: u64 = 392_183_478_837;

#[derive(Debug, Default, PartialEq)]
struct Scan {
    absent: u64,
    present: u64,
    first: Option<(u64, u64)>,
    last: Option<(u64, u64)>,
    logical_skip_runs_without_physical_break: u64,
    edges: Vec<(u64, u64, u64, u64)>,
}

fn scan(raw: &[u8], slots: usize, car_size: u64) -> Result<Scan> {
    ensure!(raw.len() == slots * 12, "incorrect raw index length");
    let mut result = Scan::default();
    for (i, record) in raw.as_chunks::<12>().0.iter().enumerate() {
        let offset = u64::from_le_bytes(record[..8].try_into()?);
        let length = u32::from_le_bytes(record[8..].try_into()?);
        if offset == 0 || length == 0 {
            ensure!(
                offset == 0 && length == 0,
                "partial zero record at {}",
                START + i as u64
            );
            result.absent += 1;
            continue;
        }
        let slot = START + i as u64;
        let end = offset
            .checked_add(u64::from(length))
            .context("CAR offset overflow")?;
        ensure!(
            offset >= 59 && end <= car_size,
            "range outside CAR at {slot}"
        );
        result.present += 1;
        result.first.get_or_insert((slot, offset));
        if let Some((previous_slot, previous_end)) = result.last {
            if previous_end != offset {
                result
                    .edges
                    .push((previous_slot, slot, previous_end, offset));
            } else if slot > previous_slot + 1 {
                result.logical_skip_runs_without_physical_break += 1;
            }
        }
        result.last = Some((slot, end));
    }
    Ok(result)
}

pub fn validate(raw: &[u8]) -> Result<Value> {
    let scan = scan(raw, SLOTS, CAR_SIZE)?;
    ensure!(
        scan.absent == 46_728 && scan.present == 385_272,
        "presence count"
    );
    ensure!(
        scan.first == Some((111024004, 59)) && scan.last == Some((111455999, 392167679878)),
        "boundary records"
    );
    ensure!(
        scan.edges == EDGES && scan.logical_skip_runs_without_physical_break == 14231,
        "epoch257 physical or logical transition profile changed"
    );
    let positive_bytes: u64 = EDGES
        .iter()
        .map(|(_, _, end, offset)| offset.saturating_sub(*end))
        .sum();
    let edges: Vec<_> = scan.edges.iter().map(|&(previous_slot,slot,previous_end,offset)| {
        json!({"previous_slot":previous_slot,"slot":slot,"absent_slots_between":slot-previous_slot-1,"previous_end":previous_end,"offset":offset,"kind":if offset>previous_end {"forward_gap"} else {"overlap"},"bytes":offset.abs_diff(previous_end)})
    }).collect();
    Ok(
        json!({"rows":SLOTS,"present":scan.present,"absent_zero_records":scan.absent,"first_present":scan.first,"last_present":scan.last,"interior_skipped_runs_with_contiguous_bytes":scan.logical_skip_runs_without_physical_break,"physical_forward_gaps":28,"forward_gap_bytes":positive_bytes,"physical_overlaps":1,"overlap_bytes":1757860845_u64,"discontinuities":edges,"raw_index_qualified_for_replay":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(rows: &[(u64, u32)]) -> Vec<u8> {
        rows.iter()
            .flat_map(|(o, n)| o.to_le_bytes().into_iter().chain(n.to_le_bytes()))
            .collect()
    }

    #[test]
    fn skipped_slots_alone_do_not_create_physical_gaps() {
        let raw = bytes(&[
            (0, 0),
            (59, 4),
            (0, 0),
            (63, 5),
            (0, 0),
            (0, 0),
            (75, 5),
            (79, 2),
            (0, 0),
        ]);
        let result = scan(&raw, 9, 81).unwrap();
        assert_eq!(result.absent, 5);
        assert_eq!(result.logical_skip_runs_without_physical_break, 1);
        assert_eq!(
            result.edges,
            [
                (START + 3, START + 6, 68, 75),
                (START + 6, START + 7, 80, 79)
            ]
        );
    }

    #[test]
    fn detects_bad_sentinels_lengths_and_car_bounds() {
        for row in [(59, 0), (0, 7), (58, 1), (99, 2), (u64::MAX, 4)] {
            assert!(scan(&bytes(&[row]), 1, 100).is_err());
        }
        assert!(scan(&[0; 11], 1, 100).is_err());
    }

    #[test]
    fn every_recorded_discontinuity_has_independent_slot_and_byte_coordinates() {
        assert_eq!(EDGES.len(), 29);
        assert!(EDGES.windows(2).all(|pair| pair[0].1 < pair[1].0));
        assert_eq!(EDGES.iter().filter(|e| e.3 > e.2).count(), 28);
        assert_eq!(
            EDGES
                .iter()
                .copied()
                .filter(|e| e.3 < e.2)
                .collect::<Vec<_>>(),
            [(111226320, 111226322, 200106038129, 198348177284)]
        );
    }
}
