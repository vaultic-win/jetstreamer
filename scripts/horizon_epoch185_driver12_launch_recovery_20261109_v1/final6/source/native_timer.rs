//! Byte-equivalent checked parser from actual qualified Driver11.
use crate::*;
pub(super) fn native_timer_micros(raw: &str) -> Result<u64> {
    ensure!(
        !raw.is_empty() && raw.len() <= 128 && raw.is_ascii() && raw.trim() == raw,
        "native timer timespan framing"
    );
    let value = if raw.bytes().all(|b| b.is_ascii_digit()) {
        raw.parse::<u64>()?
    } else {
        let mut total = 0u64;
        let mut previous_rank = 8u8;
        for token in raw.split(' ') {
            let at = token
                .find(|c: char| !c.is_ascii_digit() && c != '.')
                .context("native timer timespan unit")?;
            let (number, unit) = token.split_at(at);
            let (rank, multiplier) = match unit {
                "w" => (7, 604_800_000_000u64),
                "d" => (6, 86_400_000_000),
                "h" => (5, 3_600_000_000),
                "min" => (4, 60_000_000),
                "s" => (3, 1_000_000),
                "ms" => (2, 1_000),
                "us" => (1, 1),
                _ => anyhow::bail!("unsupported native timer timespan unit"),
            };
            ensure!(
                rank < previous_rank,
                "native timer units duplicated or out of order"
            );
            previous_rank = rank;
            let (whole, fraction) = number.split_once('.').unwrap_or((number, ""));
            ensure!(
                !whole.is_empty()
                    && whole.bytes().all(|b| b.is_ascii_digit())
                    && fraction.len() <= 6
                    && fraction.bytes().all(|b| b.is_ascii_digit())
                    && (!number.contains('.') || !fraction.is_empty()),
                "native timer decimal spelling"
            );
            let integer = whole
                .parse::<u64>()?
                .checked_mul(multiplier)
                .context("native timer integer overflow")?;
            let fractional = if fraction.is_empty() {
                0
            } else {
                let numerator = fraction
                    .parse::<u64>()?
                    .checked_mul(multiplier)
                    .context("native timer fraction overflow")?;
                let scale = 10u64.pow(fraction.len() as u32);
                ensure!(
                    numerator.is_multiple_of(scale),
                    "native timer sub-microsecond value"
                );
                numerator / scale
            };
            total = total
                .checked_add(integer)
                .and_then(|v| v.checked_add(fractional))
                .context("native timer timespan sum overflow")?;
        }
        total
    };
    ensure!(
        value > 0 && value != u64::MAX,
        "native timer trigger must be finite positive"
    );
    Ok(value)
}
