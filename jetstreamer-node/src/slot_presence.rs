//! Shared slot-presence evidence used by the replay scheduler and recorder.
use solana_clock::Slot;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SlotPresenceState {
    Present,
    Missing,
}

#[derive(Debug)]
pub(crate) struct SlotPresenceMap {
    pub(crate) start: Slot,
    pub(crate) end_inclusive: Slot,
    pub(crate) states: Vec<SlotPresenceState>,
    pub(crate) next_present_after: Vec<Option<Slot>>,
}

impl SlotPresenceMap {
    pub(crate) fn state(&self, slot: Slot) -> Option<SlotPresenceState> {
        if slot < self.start || slot > self.end_inclusive {
            return None;
        }
        let idx = (slot - self.start) as usize;
        self.states.get(idx).copied()
    }

    pub(crate) fn next_present_after(&self, slot: Slot) -> Option<Slot> {
        if slot < self.start || slot > self.end_inclusive {
            return None;
        }
        let idx = (slot - self.start) as usize;
        self.next_present_after.get(idx).copied().flatten()
    }
}
