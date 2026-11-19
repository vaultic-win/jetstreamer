//! Native-test-only syscall fault injection. Never install in a replay service.
//! Every ordinary call passes directly to the kernel. Only exact fixture modes
//! and exact capture member basenames trigger an injected failure.
use std::{
    ffi::CStr,
    sync::atomic::{AtomicBool, Ordering},
};

static TRIGGERED: AtomicBool = AtomicBool::new(false);
static REGRESS_REALTIME: AtomicBool = AtomicBool::new(false);
static REGRESSION_OBSERVED: AtomicBool = AtomicBool::new(false);

fn mode() -> &'static [u8] {
    let ptr = unsafe { libc::getenv(c"HORIZON168_NATIVE_FAULT".as_ptr()) };
    if ptr.is_null() {
        b""
    } else {
        unsafe { CStr::from_ptr(ptr).to_bytes() }
    }
}

fn member(fd: libc::c_int, suffix: &[u8]) -> bool {
    let name = format!("/proc/self/fd/{fd}");
    let Ok(name) = std::ffi::CString::new(name) else {
        return false;
    };
    let mut buffer = [0u8; 4096];
    let len = unsafe {
        libc::syscall(
            libc::SYS_readlinkat,
            libc::AT_FDCWD,
            name.as_ptr(),
            buffer.as_mut_ptr(),
            buffer.len(),
        )
    };
    len > 0 && (len as usize) < buffer.len() && buffer[..len as usize].ends_with(suffix)
}

fn announce(label: &[u8]) {
    let prefix = b"epoch168-native-fault: ";
    unsafe {
        libc::syscall(
            libc::SYS_write,
            libc::STDERR_FILENO,
            prefix.as_ptr(),
            prefix.len(),
        );
        libc::syscall(
            libc::SYS_write,
            libc::STDERR_FILENO,
            label.as_ptr(),
            label.len(),
        );
        libc::syscall(libc::SYS_write, libc::STDERR_FILENO, b"\n".as_ptr(), 1usize);
    }
}

fn fail(errno: libc::c_int) -> libc::c_int {
    unsafe {
        *libc::__errno_location() = errno;
    }
    -1
}

fn delay_past_deadline() -> bool {
    let value = unsafe { libc::getenv(c"HORIZON168_NATIVE_DEADLINE_MS".as_ptr()) };
    if value.is_null() {
        return false;
    }
    let Ok(value) = unsafe { CStr::from_ptr(value) }.to_str() else {
        return false;
    };
    let Ok(deadline) = value.parse::<u64>() else {
        return false;
    };
    let mut now: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::syscall(libc::SYS_clock_gettime, libc::CLOCK_REALTIME, &mut now) } != 0 {
        return false;
    }
    let millis = (now.tv_sec as u64).saturating_mul(1000) + now.tv_nsec as u64 / 1_000_000;
    let delay = deadline.saturating_add(100).saturating_sub(millis);
    if delay == 0 || delay > 5000 {
        return false;
    }
    let mut request = libc::timespec {
        tv_sec: (delay / 1000) as _,
        tv_nsec: ((delay % 1000) * 1_000_000) as _,
    };
    loop {
        let mut remainder = request;
        let result = unsafe { libc::syscall(libc::SYS_nanosleep, &request, &mut remainder) };
        if result == 0 {
            return true;
        }
        if unsafe { *libc::__errno_location() } != libc::EINTR {
            return false;
        }
        request = remainder;
    }
}

#[unsafe(no_mangle)]
/// Forwards a C write call except for the selected native control.
///
/// # Safety
/// The caller must provide a readable buffer of `length` bytes, as for libc write.
pub unsafe extern "C" fn write(
    fd: libc::c_int,
    bytes: *const libc::c_void,
    length: libc::size_t,
) -> libc::ssize_t {
    if mode() == b"slot-write-enospc"
        && member(fd, b"/slot-range.bin")
        && !TRIGGERED.swap(true, Ordering::SeqCst)
    {
        announce(b"slot-write-enospc");
        return fail(libc::ENOSPC) as _;
    }
    unsafe { libc::syscall(libc::SYS_write, fd, bytes, length) as _ }
}

#[unsafe(no_mangle)]
/// Forwards a C fsync call except for the selected native control.
///
/// # Safety
/// This entry point must be used with the libc ABI in the isolated test child.
pub unsafe extern "C" fn fsync(fd: libc::c_int) -> libc::c_int {
    let selected = mode();
    let slot_failure = selected == b"slot-fsync-eio" && member(fd, b"/slot-range.bin");
    let marker = member(fd, b"/COMPLETION.sha256");
    let marker_failure = marker
        && matches!(
            selected,
            b"marker-fsync-eio" | b"marker-kill" | b"marker-deadline" | b"marker-clock-regression"
        );
    if (slot_failure || marker_failure) && !TRIGGERED.swap(true, Ordering::SeqCst) {
        if selected == b"slot-fsync-eio" || selected == b"marker-fsync-eio" {
            announce(selected);
            return fail(libc::EIO);
        }
        let result = unsafe { libc::syscall(libc::SYS_fsync, fd) as libc::c_int };
        if result != 0 {
            return result;
        }
        announce(selected);
        if selected == b"marker-kill" {
            unsafe {
                libc::syscall(libc::SYS_kill, libc::getpid(), libc::SIGKILL);
            }
            return fail(libc::EINTR);
        }
        if selected == b"marker-clock-regression" {
            REGRESS_REALTIME.store(true, Ordering::SeqCst);
        }
        if !delay_past_deadline() {
            announce(b"deadline-injection-not-exercised");
            return fail(libc::EINVAL);
        }
        return 0;
    }
    unsafe { libc::syscall(libc::SYS_fsync, fd) as _ }
}

#[unsafe(no_mangle)]
/// Forwards clock_gettime; the regression control alters only the child's realtime result.
///
/// # Safety
/// `output` must point to writable timespec storage, as for libc clock_gettime.
pub unsafe extern "C" fn clock_gettime(
    clock: libc::clockid_t,
    output: *mut libc::timespec,
) -> libc::c_int {
    let result = unsafe { libc::syscall(libc::SYS_clock_gettime, clock, output) as libc::c_int };
    if result == 0 && clock == libc::CLOCK_REALTIME && REGRESS_REALTIME.load(Ordering::SeqCst) {
        unsafe {
            (*output).tv_sec -= 60;
        }
        if !REGRESSION_OBSERVED.swap(true, Ordering::SeqCst) {
            announce(b"realtime-regressed");
        }
    }
    result
}
