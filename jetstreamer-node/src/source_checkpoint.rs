//! Explicit pressure requests select a whole source block, never shared shutdown.
//! Selection is input evidence only; drainage, freeze, export and replay recovery
//! must independently succeed before the result can release any resources.
use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};

static REQUESTED: AtomicBool = AtomicBool::new(false);
static INSTALLED: AtomicBool = AtomicBool::new(false);

#[cfg(test)]
pub(crate) static SIGNAL_TEST_LOCK: Mutex<()> = Mutex::new(());

extern "C" fn request_checkpoint(_: libc::c_int) {
    REQUESTED.store(true, Ordering::SeqCst);
}

pub(crate) fn requested() -> bool {
    REQUESTED.load(Ordering::SeqCst)
}

/// Only the explicit standalone checkpoint mode installs this handler.
/// The external controller must bind SIGUSR1 to the exact admitted invocation.
pub(crate) struct SignalGuard(libc::sigaction);

impl SignalGuard {
    pub(crate) fn install() -> Result<Self, String> {
        if INSTALLED.swap(true, Ordering::SeqCst) {
            return Err("checkpoint signal handler is already installed".into());
        }
        REQUESTED.store(false, Ordering::SeqCst);
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        let mut previous: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = request_checkpoint as *const () as usize;
        action.sa_flags = libc::SA_RESTART;
        unsafe { libc::sigemptyset(&mut action.sa_mask) };
        if unsafe { libc::sigaction(libc::SIGUSR1, &action, &mut previous) } != 0 {
            INSTALLED.store(false, Ordering::SeqCst);
            return Err(format!(
                "install checkpoint signal: {}",
                std::io::Error::last_os_error()
            ));
        }
        if previous.sa_sigaction != libc::SIG_DFL {
            unsafe { libc::sigaction(libc::SIGUSR1, &previous, std::ptr::null_mut()) };
            INSTALLED.store(false, Ordering::SeqCst);
            return Err("checkpoint signal is owned by another handler".into());
        }
        Ok(Self(previous))
    }
}

impl Drop for SignalGuard {
    fn drop(&mut self) {
        unsafe { libc::sigaction(libc::SIGUSR1, &self.0, std::ptr::null_mut()) };
        INSTALLED.store(false, Ordering::SeqCst);
    }
}

pub(crate) struct Boundary<B> {
    first_recorded_slot: u64,
    intended_terminal: u64,
    selected: Mutex<Option<B>>,
}

impl<B: Copy + PartialEq> Boundary<B> {
    pub(crate) fn new(first_recorded_slot: u64, intended_terminal: u64) -> Result<Self, String> {
        if first_recorded_slot >= intended_terminal {
            return Err("pressure checkpoint requires a nonempty proper prefix".into());
        }
        Ok(Self {
            first_recorded_slot,
            intended_terminal,
            selected: Mutex::new(None),
        })
    }

    /// Called exclusively by the successful whole-source-batch acknowledgement.
    pub(crate) fn observe(&self, block: B, slot: u64, requested: bool) -> Result<bool, String> {
        let mut selected = self
            .selected
            .lock()
            .map_err(|_| "checkpoint selection poisoned")?;
        if selected.is_some() {
            return Err("source continued after selecting its checkpoint boundary".into());
        }
        if !requested || slot < self.first_recorded_slot || slot >= self.intended_terminal {
            return Ok(false);
        }
        *selected = Some(block);
        Ok(true)
    }

    pub(crate) fn verify(&self, block: B) -> Result<(), String> {
        if *self
            .selected
            .lock()
            .map_err(|_| "checkpoint selection poisoned")?
            != Some(block)
        {
            return Err("source quiescence does not match the selected checkpoint boundary".into());
        }
        Ok(())
    }

    pub(crate) fn validate_range(&self, first: u64, terminal: u64) -> Result<(), String> {
        if (first, terminal) != (self.first_recorded_slot, self.intended_terminal) {
            return Err("pressure checkpoint range differs from replay".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_during_warmup_waits_for_recorded_whole_block() {
        let boundary = Boundary::new(10, 20).unwrap();
        boundary.validate_range(10, 20).unwrap();
        assert!(boundary.validate_range(10, 21).is_err());
        assert!(!boundary.observe((9, [1; 32]), 9, true).unwrap());
        assert!(boundary.observe((12, [2; 32]), 12, true).unwrap());
        boundary.verify((12, [2; 32])).unwrap();
        assert!(boundary.verify((12, [3; 32])).is_err());
        assert!(boundary.observe((13, [4; 32]), 13, true).is_err());
    }

    #[test]
    fn no_request_or_terminal_completion_does_not_claim_a_pause() {
        let boundary = Boundary::new(10, 20).unwrap();
        assert!(!boundary.observe(12, 12, false).unwrap());
        assert!(!boundary.observe(20, 20, true).unwrap());
        assert!(boundary.verify(20).is_err());
        assert!(Boundary::<u64>::new(20, 20).is_err());
    }

    #[test]
    fn explicit_signal_requests_checkpoint_without_shared_shutdown() {
        let _serial = SIGNAL_TEST_LOCK.lock().unwrap();
        let _guard = SignalGuard::install().unwrap();
        assert!(!requested());
        assert_eq!(unsafe { libc::raise(libc::SIGUSR1) }, 0);
        assert!(requested());
        assert!(SignalGuard::install().is_err());
    }
}
