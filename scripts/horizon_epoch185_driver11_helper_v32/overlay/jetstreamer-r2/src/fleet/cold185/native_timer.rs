//! Exact Driver11 native timespan arithmetic, shared with retained helper readers.
use super::*;
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
pub(super) fn timer_activation_fresh(trigger: u64, begin: u64, at: u64) -> Result<()> {
    ensure!(
        trigger > 0
            && trigger != u64::MAX
            && begin > 0
            && begin
                .checked_sub(trigger)
                .is_some_and(|gap| gap <= 5_000_000)
            && at.checked_sub(begin).is_some_and(|age| age <= 90_000_000),
        "not a fresh timer-driven native activation"
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual1800_formatted_timer_trigger_is_exact_and_raw_guard_start_stays_raw() {
        let trigger = native_timer_micros("4w 1d 43min 54.141704s").unwrap();
        assert_eq!(trigger, 2_508_234_141_704);
        assert_eq!(native_timer_micros("2508234141704").unwrap(), trigger);
        let begin = "2508234142704".parse::<u64>().unwrap();
        timer_activation_fresh(trigger, begin, begin + 1000).unwrap();
        assert!("4w 1d 43min 54.142704s".parse::<u64>().is_err());
    }
    #[test]
    fn native_timer_timespan_rejects_malformed_unsupported_and_nonintegral_values() {
        for raw in [
            "",
            " 1s",
            "1s ",
            "1s  1us",
            "infinity",
            "n/a",
            "1ns",
            "1year",
            "-1s",
            "+1s",
            "1e3s",
            ".5s",
            "1.s",
            "1.2.3s",
            "1s 1s",
            "1us 1s",
            "1s 1",
            "1.0000001s",
            "0.1us",
            "0.0001ms",
            "1µs",
            "1s\n",
        ] {
            assert!(native_timer_micros(raw).is_err(), "accepted {raw:?}");
        }
        assert_eq!(
            native_timer_micros("1h 2min 3.000004s").unwrap(),
            3_723_000_004
        );
        assert_eq!(native_timer_micros("1ms 1us").unwrap(), 1001);
    }
    #[test]
    fn native_timer_timespan_overflow_zero_and_infinity_never_become_trigger() {
        for raw in [
            "0",
            "0us",
            "0.000000s",
            "18446744073709551616",
            "18446744073709551615",
            "18446744073709551615us",
            "18446744073709551615s",
            "30500569w",
            "18446744073709551ms 615us",
            "18446744073709551ms 616us",
        ] {
            assert!(native_timer_micros(raw).is_err(), "accepted {raw:?}");
        }
        assert_eq!(
            native_timer_micros("18446744073709551614us").unwrap(),
            u64::MAX - 1
        );
    }
    #[test]
    fn native_timer_activation_retains_exact_five_and_ninety_second_bounds() {
        let trigger = 2_508_234_141_704;
        let begin = trigger + 5_000_000;
        timer_activation_fresh(trigger, begin, begin + 90_000_000).unwrap();
        for (trigger, begin, at) in [
            (trigger, begin + 1, begin + 1),
            (trigger, begin, begin + 90_000_001),
            (trigger, trigger - 1, trigger),
            (trigger, begin, begin - 1),
            (0, begin, begin),
            (trigger, 0, begin),
            (u64::MAX, u64::MAX, u64::MAX),
        ] {
            assert!(timer_activation_fresh(trigger, begin, at).is_err());
        }
    }
}
