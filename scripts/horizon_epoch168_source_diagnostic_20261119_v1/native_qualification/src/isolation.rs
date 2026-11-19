use crate::{Error, Result, ensure};
use std::{ffi::CString, fs, os::unix::ffi::OsStrExt, path::Path};

fn syscall_ok(result: libc::c_int, label: &str) -> Result<()> {
    if result == 0 {
        Ok(())
    } else {
        Err(format!("{label}: {}", std::io::Error::last_os_error()).into())
    }
}

fn mount(source: &Path, destination: &Path, flags: libc::c_ulong) -> Result<()> {
    let source = CString::new(source.as_os_str().as_bytes())?;
    let destination = CString::new(destination.as_os_str().as_bytes())?;
    syscall_ok(
        unsafe {
            libc::mount(
                source.as_ptr(),
                destination.as_ptr(),
                std::ptr::null(),
                flags,
                std::ptr::null(),
            )
        },
        "private fixture mount",
    )
}

pub fn enter(hosts: &Path, certificates: &Path) -> Result<()> {
    ensure(
        unsafe { libc::geteuid() } == 0,
        "native fixture requires root",
    )?;
    // Run before creating threads. The invoking controller remains outside
    // these namespaces; no host resolver, CA store or interface is changed.
    syscall_ok(
        unsafe { libc::unshare(libc::CLONE_NEWNET | libc::CLONE_NEWNS) },
        "unshare network/mount namespaces",
    )?;
    let root = CString::new("/")?;
    syscall_ok(
        unsafe {
            libc::mount(
                std::ptr::null(),
                root.as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null(),
            )
        },
        "private mount propagation",
    )?;
    ensure(
        Path::new("/etc/hosts").is_file(),
        "host /etc/hosts mount target absent",
    )?;
    ensure(
        Path::new("/etc/ssl/certs").is_dir(),
        "Debian/Ubuntu CA directory mount target absent",
    )?;
    mount(hosts, Path::new("/etc/hosts"), libc::MS_BIND)?;
    mount(
        hosts,
        Path::new("/etc/hosts"),
        libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY,
    )?;
    mount(certificates, Path::new("/etc/ssl/certs"), libc::MS_BIND)?;
    mount(
        certificates,
        Path::new("/etc/ssl/certs"),
        libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY,
    )?;
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    ensure(fd >= 0, "loopback control socket")?;
    let result = (|| {
        let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
        request.ifr_name[0] = b'l' as libc::c_char;
        request.ifr_name[1] = b'o' as libc::c_char;
        syscall_ok(
            unsafe { libc::ioctl(fd, libc::SIOCGIFFLAGS, &mut request) },
            "read private loopback flags",
        )?;
        unsafe {
            request.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short;
        }
        syscall_ok(
            unsafe { libc::ioctl(fd, libc::SIOCSIFFLAGS, &request) },
            "enable private loopback",
        )
    })();
    unsafe {
        libc::close(fd);
    }
    result
}

pub fn namespace_id(kind: &str) -> Result<String> {
    // Evidence only; callers never treat a path label as a capability grant.
    fs::read_link(format!("/proc/self/ns/{kind}"))
        .map(|p| p.to_string_lossy().into_owned())
        .map_err(|e| -> Error { e.into() })
}
