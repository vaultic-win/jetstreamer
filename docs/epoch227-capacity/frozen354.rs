//! Frozen cycle 354 derivation only. No host, archive, R2 or admission API.
//! Missing physical output/guard credits remain explicit caller inputs.
#![deny(warnings)]
const FREE: u64 = 2_323_934_646_272;
const CENTURY: u64 = 245_383_154_903;
const FLOOR: u64 = 2_000_000_000_000;
const CANDIDATE: u64 = 300_016_777_216;
const PARK_METADATA: u64 = 32 << 20;
const PARK_MEMORY: u64 = 6 << 30;
const OUTPUT_CAP: u64 = 128 << 30;
const S209: u64 = 139_918_577_664;
const S223: u64 = 118_010_724_352;
const PEAK: u64 = 471_798_691_840;
#[derive(Debug, PartialEq)]
struct Derived {
    old_remaining_growth_with_park: u64,
    protected_floor: u64,
    required_initial_free: u64,
    fits_frozen_disk: bool,
    park_remaining_memory_reserved: u64,
}
fn derive(o204: u64, o205: u64, deficit209: u64, deficit223: u64) -> Option<Derived> {
    if o204 > OUTPUT_CAP || o205 > OUTPUT_CAP || deficit209 > S209 || deficit223 > S223 {
        return None;
    }
    let r225 = (640u64 << 30).checked_sub(215_663_988_736 - 179_696_549_888)?;
    let r204 = PEAK.checked_sub(156_957_847_552)?.checked_sub(o204)?;
    let r205 = PEAK.checked_sub(168_103_198_720)?.checked_sub(o205)?;
    let r209 = PEAK.checked_sub(S209)?.checked_add(deficit209)?;
    let r223 = PEAK.checked_sub(S223)?.checked_add(deficit223)?;
    let growth = [r225, r204, r205, r209, r223, PARK_METADATA]
        .into_iter()
        .try_fold(0u64, u64::checked_add)?;
    let protected = CENTURY.checked_add(growth)?.max(FLOOR);
    let required = protected.checked_add(CANDIDATE)?;
    Some(Derived {
        old_remaining_growth_with_park: growth,
        protected_floor: protected,
        required_initial_free: required,
        fits_frozen_disk: required <= FREE,
        park_remaining_memory_reserved: PARK_MEMORY,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn no_output_credit_does_not_fit_and_park_is_not_free() {
        let d = derive(0, 0, 0, 0).unwrap();
        assert_eq!(d.old_remaining_growth_with_park, 1_955_465_302_016);
        assert_eq!(d.protected_floor, 2_200_848_456_919);
        assert_eq!(d.required_initial_free, 2_500_865_234_135);
        assert!(!d.fits_frozen_disk);
        assert_eq!(d.park_remaining_memory_reserved, 6_442_450_944);
    }
    #[test]
    fn exact_conditional_fit_threshold_has_no_provisional_padding() {
        let needed = 176_930_587_863;
        let first = needed / 2;
        let second = needed - first;
        assert_eq!(
            derive(first, second, 0, 0).unwrap().required_initial_free,
            FREE
        );
        assert!(derive(first, second, 0, 0).unwrap().fits_frozen_disk);
        assert!(!derive(first, second - 1, 0, 0).unwrap().fits_frozen_disk);
        assert!(!derive(first, second, 1, 0).unwrap().fits_frozen_disk);
    }
    #[test]
    fn all_current_guard_deficits_are_conservative_and_caps_are_preserved() {
        assert!(derive(OUTPUT_CAP + 1, 0, 0, 0).is_none());
        assert!(derive(0, 0, S209 + 1, 0).is_none());
        let best = derive(OUTPUT_CAP, OUTPUT_CAP, 0, 0).unwrap();
        assert_eq!(best.protected_floor, FLOOR);
        assert_eq!(FREE - best.required_initial_free, 23_917_869_056);
        assert!(best.fits_frozen_disk);
        assert!(
            !derive(OUTPUT_CAP, OUTPUT_CAP, S209, S223)
                .unwrap()
                .fits_frozen_disk
        );
    }
}
