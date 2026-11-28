//! Fixed restore profile pending independent qualification; no runtime/replay authority.
pub const ACTOR: &str = "horizon-epoch163-native48-input-20261107-v1.service";
pub const ISSUER: &str = "horizon-epoch163-native48-admission-20261107-v1.service";
pub const MEMORY: u64 = 48 << 30;
pub const SCRATCH: u64 = 40 << 30;
pub const EXPORTER_AVAILABLE_FLOOR: u64 = 642_177_138_688;
pub const LIVE_EXPORTER_HARD_PROMISE: u64 = (80 << 30) + (256 << 20);
pub const NORMAL_POOL: u64 = 6 << 30;
// The issuer's 2GiB slot is INSIDE this pool, never additive to it.
pub const INITIAL_MEMORY_FLOOR: u64 =
    EXPORTER_AVAILABLE_FLOOR + LIVE_EXPORTER_HARD_PROMISE + NORMAL_POOL + MEMORY;
//1030 known complete retained DATA plus this source-only packet's 2MiB bound.
//Fresh current accounting or a larger Root booking can only raise this floor.
pub const DATA_FLOOR: u64 = 5_082_742_132_530 + (2 << 20);
pub const PLAN_SCHEMA: &str = "epoch163-native48-input-plan-v1";
pub const ADMISSION_SCHEMA: &str = "epoch163-native48-input-admission-v1";
pub fn remaining_floor(initial: u64, current: u64) -> Option<u64> {
    if initial < INITIAL_MEMORY_FLOOR || current > MEMORY {
        return None;
    }
    initial.checked_sub(current)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn profile_keeps_exporter_full_hard_promise_and_one_pool() {
        assert_eq!(MEMORY, 51_539_607_552);
        assert_eq!(INITIAL_MEMORY_FLOOR, 786_326_978_560);
        assert_eq!(INITIAL_MEMORY_FLOOR - MEMORY, 734_787_371_008);
        assert!(SCRATCH < MEMORY);
        assert_ne!(ACTOR, "horizon-epoch163-native-input-20261106-v1.service");
        assert_ne!(ADMISSION_SCHEMA, "epoch163-native-input-admission-v2");
    }
    #[test]
    fn only_actual_owned_cgroup_usage_changes_native_remaining_floor() {
        assert_eq!(
            remaining_floor(INITIAL_MEMORY_FLOOR, 0),
            Some(INITIAL_MEMORY_FLOOR)
        );
        assert_eq!(
            remaining_floor(INITIAL_MEMORY_FLOOR, MEMORY),
            Some(INITIAL_MEMORY_FLOOR - MEMORY)
        );
        assert!(remaining_floor(INITIAL_MEMORY_FLOOR, MEMORY + 1).is_none());
        assert!(remaining_floor(INITIAL_MEMORY_FLOOR, 128 << 30).is_none());
        assert!(remaining_floor(INITIAL_MEMORY_FLOOR - 1, 0).is_none());
    }
    #[test]
    fn retained_data_floor_never_reuses_the_obsolete4720_floor() {
        assert_eq!(DATA_FLOOR, 5_082_744_229_682);
        assert!(DATA_FLOOR > 5_074_152_197_938);
        assert!(DATA_FLOOR > 4_720_000_000_000);
    }
}
