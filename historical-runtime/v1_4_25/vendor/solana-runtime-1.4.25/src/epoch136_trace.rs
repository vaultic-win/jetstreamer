//! Bounded, opt-in observation of the exact unresolved epoch-136 transaction.
//! No execution result, meter, budget, account or publication authority is changed here.
//!
//! Syscall site labels: 10=log, 11=log_u64, 12=log_compute_units, 13=log_pubkey,
//! 14=create_program_address before translation, 15=after translation,
//! 16=try_find_program_address, 17=sha256 base, 18=sha256 bytes,
//! 19=ristretto multiplication, 20=invoke_signed entry charge.
use solana_sdk::{message::Message, pubkey::Pubkey, signature::Signature};
use std::{
    cell::{Cell, RefCell},
    marker::PhantomData,
    rc::Rc,
};
const SLOT: u64 = 59_183_097;
const ENTRY: u64 = 197;
const SIGNATURE: &str =
    "2B96JV6WYJDwxNF3MS4KtS4jb1ToCcQ3xxhcKNysJsdK1jbZ45NCF1EiEWk5GK7Yr5LGVzrT1fBA6Jnvc9VU36L3";
const LIMIT: usize = 8192;
const RAW_DEBUG_LIMIT: usize = 512;
/// Rust 1.46 has no derived Debug/PartialEq implementation for arrays over 32 bytes.
#[derive(Clone, Copy)]
pub struct RawDebug([u8; RAW_DEBUG_LIMIT]);
impl std::fmt::Debug for RawDebug {
    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.0[..], formatter)
    }
}
impl PartialEq for RawDebug {
    fn eq(&self, other: &Self) -> bool {
        self.0[..] == other.0[..]
    }
}
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Outcome {
    Success,
    MeterExceeded,
    BorrowFailed,
    VmError { code: u16, detail: Option<u64> },
}
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Kind {
    SyscallCharge {
        site: u16,
        requested: u64,
        before: Option<u64>,
        after: Option<u64>,
        result: Outcome,
    },
    VmInstructionCharge {
        requested: u64,
        before: Option<u64>,
        after: Option<u64>,
        result: Outcome,
    },
    Meter {
        requested: u64,
        before: u64,
        after: u64,
        exceeded: bool,
    },
    PdaEntered,
    PdaInputsTranslated,
    CpiEntered,
    CpiTranslated {
        callee: Pubkey,
    },
    CpiDispatch {
        callee: Pubkey,
    },
    VmEnter {
        remaining: u64,
    },
    VmReturn {
        remaining: u64,
        result: Outcome,
        raw_debug: RawDebug,
        raw_debug_len: u16,
        raw_debug_overflow: bool,
    },
}
impl Kind {
    fn failure(self) -> bool {
        match self {
            Kind::SyscallCharge { result, .. }
            | Kind::VmInstructionCharge { result, .. }
            | Kind::VmReturn { result, .. } => result != Outcome::Success,
            Kind::Meter { exceeded, .. } => exceeded,
            _ => false,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Frame {
    pub program_id: Pubkey,
    pub invoke_depth: usize,
}
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Event {
    pub sequence: u64,
    pub instruction: usize,
    pub frame: Option<Frame>,
    pub kind: Kind,
}
#[derive(Clone, Copy, Default)]
struct Context {
    transaction: bool,
    instruction: Option<usize>,
    frame: Option<Frame>,
    depth: usize,
}
struct Capture {
    serial: u64,
    signature: Signature,
    message: Message,
    context: Context,
    matched: bool,
    invalid: bool,
    total: u64,
    overflow: bool,
    raw_debug_overflow: bool,
    first_failure: Option<Event>,
    events: Vec<Event>,
    limit: usize,
}
#[derive(Debug)]
pub struct Report {
    pub revision: &'static str,
    pub signature: Signature,
    pub message: Message,
    pub transaction_matched: bool,
    pub complete: bool,
    pub overflow: bool,
    pub raw_debug_overflow: bool,
    pub borrow_conflict: bool,
    pub total_events: u64,
    pub first_failure: Option<Event>,
    pub events: Vec<Event>,
    pub publication_authorized: bool,
}
thread_local! {
    static TRACE: RefCell<Option<Capture>> = RefCell::new(None);
    static SERIAL: Cell<u64> = Cell::new(0);
    static CONFLICT: Cell<bool> = Cell::new(false);
}
fn conflict() {
    let _ = CONFLICT.try_with(|v| v.set(true));
}
fn visit<F: FnOnce(&mut Capture)>(f: F) {
    let _ = TRACE.try_with(|cell| match cell.try_borrow_mut() {
        Ok(mut trace) => {
            if let Some(ref mut current) = *trace {
                f(current);
            }
        }
        Err(_) => conflict(),
    });
}
/// This guard cannot move to another Rayon thread.
pub struct Request {
    serial: u64,
    done: bool,
    _not_send: PhantomData<Rc<()>>,
}
pub struct Scope {
    serial: u64,
    previous: Context,
    _not_send: PhantomData<Rc<()>>,
}
pub fn arm(slot: u64, entry: u64, signature: &Signature, message: &Message) -> Option<Request> {
    arm_with_limit(slot, entry, signature, message, LIMIT)
}
fn arm_with_limit(
    slot: u64,
    entry: u64,
    signature: &Signature,
    message: &Message,
    limit: usize,
) -> Option<Request> {
    if slot != SLOT
        || entry != ENTRY
        || signature.to_string() != SIGNATURE
        || limit == 0
        || limit > LIMIT
    {
        return None;
    }
    TRACE
        .try_with(|cell| {
            let mut trace = match cell.try_borrow_mut() {
                Ok(v) => v,
                Err(_) => {
                    conflict();
                    return None;
                }
            };
            if let Some(ref mut active) = *trace {
                active.invalid = true;
                return None;
            }
            let serial = SERIAL.with(|v| {
                let next = v.get().checked_add(1);
                if let Some(n) = next {
                    v.set(n);
                }
                next
            })?;
            CONFLICT.with(|v| v.set(false));
            *trace = Some(Capture {
                serial,
                signature: signature.clone(),
                message: message.clone(),
                context: Context::default(),
                matched: false,
                invalid: false,
                total: 0,
                overflow: false,
                raw_debug_overflow: false,
                first_failure: None,
                events: Vec::with_capacity(limit),
                limit,
            });
            Some(Request {
                serial,
                done: false,
                _not_send: PhantomData,
            })
        })
        .ok()
        .flatten()
}
fn scope<F: FnOnce(&mut Capture) -> bool>(f: F) -> Option<Scope> {
    let mut result = None;
    visit(|capture| {
        let previous = capture.context;
        if !f(capture) {
            return;
        }
        match previous.depth.checked_add(1) {
            Some(depth) => {
                capture.context.depth = depth;
                result = Some(Scope {
                    serial: capture.serial,
                    previous,
                    _not_send: PhantomData,
                });
            }
            None => {
                capture.invalid = true;
                capture.context = previous;
            }
        }
    });
    result
}
pub fn transaction(signature: &Signature, message: &Message) -> Option<Scope> {
    scope(|capture| {
        if &capture.signature != signature {
            return false;
        }
        if &capture.message != message || capture.context.transaction {
            capture.invalid = true;
            return false;
        }
        capture.matched = true;
        capture.context.transaction = true;
        capture.context.instruction = None;
        capture.context.frame = None;
        true
    })
}
pub fn instruction(index: usize) -> Option<Scope> {
    scope(|capture| {
        if !capture.context.transaction {
            return false;
        }
        capture.context.instruction = Some(index);
        capture.context.frame = None;
        true
    })
}
pub fn frame(program_id: Pubkey, invoke_depth: usize) -> Option<Scope> {
    scope(|capture| {
        if !capture.context.transaction || capture.context.instruction != Some(2) {
            return false;
        }
        capture.context.frame = Some(Frame {
            program_id,
            invoke_depth,
        });
        true
    })
}
#[cfg(feature = "epoch136-charge-trace")]
pub fn syscall_charge(
    site: u16,
    requested: u64,
    before: Option<u64>,
    after: Option<u64>,
    result: Outcome,
) {
    record(Kind::SyscallCharge {
        site,
        requested,
        before,
        after,
        result,
    });
}
#[cfg(feature = "epoch136-charge-trace")]
pub fn instruction_charge(
    requested: u64,
    before: Option<u64>,
    after: Option<u64>,
    result: Outcome,
) {
    record(Kind::VmInstructionCharge {
        requested,
        before,
        after,
        result,
    });
}
#[cfg(feature = "epoch136-charge-trace")]
pub fn meter_charge(requested: u64, before: u64, after: u64, exceeded: bool) {
    record(Kind::Meter {
        requested,
        before,
        after,
        exceeded,
    });
}
pub fn vm_enter(remaining: u64) {
    record(Kind::VmEnter { remaining });
}
/// Avoid evaluating diagnostic formatting outside the exact selected instruction.
pub fn capturing_instruction() -> bool {
    TRACE
        .try_with(|cell| {
            cell.try_borrow()
                .map(|trace| {
                    trace.as_ref().map_or(false, |capture| {
                        capture.context.transaction && capture.context.instruction == Some(2)
                    })
                })
                .unwrap_or(false)
        })
        .unwrap_or(false)
}
pub fn vm_return(remaining: u64, result: Outcome, raw_debug: Option<String>) {
    let mut raw = [0u8; RAW_DEBUG_LIMIT];
    let mut raw_len = 0usize;
    let mut raw_overflow = false;
    if let Some(text) = raw_debug {
        let bytes = text.as_bytes();
        raw_len = std::cmp::min(bytes.len(), RAW_DEBUG_LIMIT);
        raw[..raw_len].copy_from_slice(&bytes[..raw_len]);
        raw_overflow = bytes.len() > RAW_DEBUG_LIMIT;
    }
    record(Kind::VmReturn {
        remaining,
        result,
        raw_debug: RawDebug(raw),
        raw_debug_len: raw_len as u16,
        raw_debug_overflow: raw_overflow,
    });
}
pub fn record(kind: Kind) {
    visit(|capture| {
        if !capture.context.transaction || capture.context.instruction != Some(2) {
            return;
        }
        // Caller-side meter/syscall events may occur before BPF frame entry.
        // They remain bound by the selected transaction and instruction scopes.
        if let Kind::VmReturn {
            raw_debug_overflow: true,
            ..
        } = kind
        {
            capture.raw_debug_overflow = true;
        }
        capture.total = capture.total.saturating_add(1);
        let event = Event {
            sequence: capture.total,
            instruction: 2,
            frame: capture.context.frame,
            kind,
        };
        if kind.failure() && capture.first_failure.is_none() {
            capture.first_failure = Some(event);
        }
        if capture.events.len() < capture.limit {
            capture.events.push(event);
        } else {
            capture.overflow = true;
        }
    });
}
impl Drop for Scope {
    fn drop(&mut self) {
        let unwinding = std::thread::panicking();
        visit(|capture| {
            if capture.serial != self.serial {
                return;
            }
            if unwinding {
                capture.invalid = true;
            }
            if capture.context.depth != self.previous.depth + 1 {
                capture.invalid = true;
                capture.context = Context::default();
                return;
            }
            capture.context = self.previous;
        });
    }
}
impl Request {
    /// Format or persist only this returned report, after original execution returns.
    pub fn finish(mut self) -> Option<Report> {
        let result = TRACE
            .try_with(|cell| {
                let mut trace = match cell.try_borrow_mut() {
                    Ok(v) => v,
                    Err(_) => {
                        conflict();
                        return None;
                    }
                };
                if trace.as_ref().map(|c| c.serial) != Some(self.serial) {
                    return None;
                }
                let capture = trace.take()?;
                let borrowed = CONFLICT.with(|v| v.get());
                Some(Report {
                    revision: "epoch136-charge-trace-v1",
                    signature: capture.signature,
                    message: capture.message,
                    transaction_matched: capture.matched,
                    complete: capture.matched
                        && !capture.invalid
                        && !capture.overflow
                        && !capture.raw_debug_overflow
                        && !borrowed
                        && capture.context.depth == 0,
                    overflow: capture.overflow,
                    raw_debug_overflow: capture.raw_debug_overflow,
                    borrow_conflict: borrowed,
                    total_events: capture.total,
                    first_failure: capture.first_failure,
                    events: capture.events,
                    publication_authorized: false,
                })
            })
            .ok()
            .flatten();
        self.done = result.is_some();
        result
    }
}
impl Drop for Request {
    fn drop(&mut self) {
        if self.done {
            return;
        }
        let _ = TRACE.try_with(|cell| match cell.try_borrow_mut() {
            Ok(mut trace) => {
                if trace.as_ref().map(|c| c.serial) == Some(self.serial) {
                    *trace = None;
                }
            }
            Err(_) => conflict(),
        });
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    fn signature() -> Signature {
        Signature::from_str(SIGNATURE).unwrap()
    }
    fn event() -> Kind {
        Kind::Meter {
            requested: 2,
            before: 2,
            after: 0,
            exceeded: false,
        }
    }
    #[test]
    fn wrong_scope_or_message_cannot_capture_and_next_request_starts_clean() {
        let sig = signature();
        let message = Message::default();
        assert!(arm(SLOT + 1, ENTRY, &sig, &message).is_none());
        assert!(arm(SLOT, ENTRY + 1, &sig, &message).is_none());
        let request = arm(SLOT, ENTRY, &sig, &message).unwrap();
        let mut wrong = message.clone();
        wrong.account_keys.push(Pubkey::new_unique());
        assert!(transaction(&sig, &wrong).is_none());
        record(event());
        let report = request.finish().unwrap();
        assert!(!report.complete && !report.transaction_matched && report.events.is_empty());
        assert!(arm(SLOT, ENTRY, &sig, &message).is_some());
    }
    #[test]
    fn nested_frames_restore_and_ordinary_instructions_emit_nothing() {
        let sig = signature();
        let message = Message::default();
        let request = arm(SLOT, ENTRY, &sig, &message).unwrap();
        {
            let _tx = transaction(&sig, &message).unwrap();
            {
                let _i = instruction(0).unwrap();
                record(event());
            }
            let _i = instruction(2).unwrap();
            let parent = Pubkey::new_unique();
            let child = Pubkey::new_unique();
            {
                let _p = frame(parent, 1).unwrap();
                record(event());
                {
                    let _c = frame(child, 2).unwrap();
                    record(event());
                }
                record(event());
            }
        }
        let report = request.finish().unwrap();
        assert!(report.complete);
        assert_eq!(report.events.len(), 3);
        assert_eq!(report.events[0].frame, report.events[2].frame);
        assert_ne!(report.events[0].frame, report.events[1].frame);
    }
    #[test]
    fn overflow_retains_the_first_failure_and_explicitly_invalidates_completeness() {
        let sig = signature();
        let message = Message::default();
        let request = arm_with_limit(SLOT, ENTRY, &sig, &message, 1).unwrap();
        {
            let _tx = transaction(&sig, &message).unwrap();
            let _i = instruction(2).unwrap();
            let _p = frame(Pubkey::new_unique(), 1).unwrap();
            record(event());
            record(Kind::Meter {
                requested: 1,
                before: 0,
                after: 0,
                exceeded: true,
            });
            record(event());
        }
        let report = request.finish().unwrap();
        assert!(!report.complete && report.overflow);
        assert_eq!(report.total_events, 3);
        assert_eq!(report.events.len(), 1);
        assert_eq!(report.first_failure.unwrap().sequence, 2);
    }
    #[test]
    fn raw_vm_debug_is_bounded_and_marks_overflow() {
        let sig = signature();
        let message = Message::default();
        let request = arm(SLOT, ENTRY, &sig, &message).unwrap();
        {
            let _tx = transaction(&sig, &message).unwrap();
            let _i = instruction(2).unwrap();
            let _p = frame(Pubkey::new_unique(), 1).unwrap();
            vm_return(
                538,
                Outcome::VmError {
                    code: 1,
                    detail: Some(538),
                },
                Some("x".repeat(RAW_DEBUG_LIMIT + 1)),
            );
        }
        let report = request.finish().unwrap();
        match report.events[0].kind {
            Kind::VmReturn {
                raw_debug_len,
                raw_debug_overflow,
                ..
            } => {
                assert_eq!(raw_debug_len as usize, RAW_DEBUG_LIMIT);
                assert!(raw_debug_overflow);
            }
            _ => panic!("expected VM return"),
        }
        assert!(report.raw_debug_overflow);
        assert!(!report.complete);
    }
    #[test]
    fn conflicting_trace_borrow_marks_the_capture_incomplete_without_panicking() {
        let sig = signature();
        let message = Message::default();
        let request = arm(SLOT, ENTRY, &sig, &message).unwrap();
        {
            let _tx = transaction(&sig, &message).unwrap();
            let _i = instruction(2).unwrap();
            TRACE.with(|cell| {
                let _borrow = cell.borrow_mut();
                record(event());
            });
        }
        let report = request.finish().unwrap();
        assert!(report.borrow_conflict);
        assert!(!report.complete);
        assert!(report.events.is_empty());
    }
    #[test]
    fn out_of_order_scope_drop_is_explicitly_incomplete() {
        let sig = signature();
        let message = Message::default();
        let request = arm(SLOT, ENTRY, &sig, &message).unwrap();
        let transaction = transaction(&sig, &message).unwrap();
        let instruction = instruction(2).unwrap();
        drop(transaction);
        drop(instruction);
        assert!(!request.finish().unwrap().complete);
    }
    #[test]
    fn thread_handoff_cannot_capture_another_threads_request() {
        let sig = signature();
        let message = Message::default();
        let request = arm(SLOT, ENTRY, &sig, &message).unwrap();
        std::thread::spawn(move || {
            assert!(transaction(&sig, &message).is_none());
            assert!(instruction(2).is_none());
            record(event());
        })
        .join()
        .unwrap();
        let report = request.finish().unwrap();
        assert!(!report.complete && !report.transaction_matched);
        assert!(report.events.is_empty());
    }
    #[test]
    fn early_unwind_restores_scope_without_changing_execution_failure() {
        let sig = signature();
        let message = Message::default();
        let request = arm(SLOT, ENTRY, &sig, &message).unwrap();
        let error = std::panic::catch_unwind(|| {
            let _tx = transaction(&sig, &message).unwrap();
            let _i = instruction(2).unwrap();
            let _p = frame(Pubkey::new_unique(), 1).unwrap();
            record(event());
            panic!("original execution failure");
        });
        assert!(error.is_err());
        assert!(!request.finish().unwrap().complete);
    }
}
