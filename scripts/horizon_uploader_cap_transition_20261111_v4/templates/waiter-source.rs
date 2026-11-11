//! Disposable native no-work race witness; never a production uploader.
#![deny(warnings)]
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::Path,
    thread,
    time::Duration,
};

fn mark(root: &str, name: &str) {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(Path::new(root).join(name))
        .expect("fixture witness");
    f.write_all(b"genuine native witness\n").unwrap();
    f.sync_all().unwrap();
}
fn main() {
    let a = std::env::args().skip(1).collect::<Vec<_>>();
    assert!(
        a.len() == 1
            && matches!(
                a[0].as_str(),
                "idle"
                    | "work-fd"
                    | "live-child"
                    | "extra-thread"
                    | "caught-term"
                    | "ignored-term"
                    | "late-work"
                    | "late-term"
            )
    );
    let case = if a[0] == "idle" {
        "positive"
    } else {
        a[0].as_str()
    };
    let root = format!(
        "/var/lib/jetstreamer/horizon-uploader-freeze-fixture-{case}-20261103-v1-waiter-v5"
    );
    let root = root.as_str();
    match a[0].as_str() {
        "work-fd" => {
            let f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(Path::new(root).join("work.jet"))
                .unwrap();
            std::mem::forget(f);
        }
        "live-child" => {
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0);
            if pid == 0 {
                loop {
                    thread::sleep(Duration::from_secs(1));
                }
            }
        }
        "extra-thread" => {
            thread::spawn(|| {
                loop {
                    thread::sleep(Duration::from_secs(1));
                }
            });
        }
        "caught-term" => unsafe {
            libc::signal(libc::SIGTERM, term as *const () as libc::sighandler_t);
        },
        "ignored-term" => unsafe {
            libc::signal(libc::SIGTERM, libc::SIG_IGN);
        },
        _ => {}
    }
    mark(root, "started");
    loop {
        thread::sleep(Duration::from_millis(50));
        if a[0] == "late-work" && Path::new(root).join("release-work").exists() {
            let f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(Path::new(root).join("late-work.jet"))
                .unwrap();
            std::mem::forget(f);
            mark(root, "work-opened");
            loop {
                thread::sleep(Duration::from_secs(1));
            }
        }
        if a[0] == "late-term" && Path::new(root).join("release-work").exists() {
            unsafe {
                libc::signal(libc::SIGTERM, libc::SIG_IGN);
            }
            mark(root, "term-ignored");
            loop {
                thread::sleep(Duration::from_secs(1));
            }
        }
        if a[0] == "idle" && Path::new(root).join("release-work").exists() {
            mark(root, "unexpected-post-freeze-user-progress");
            loop {
                thread::sleep(Duration::from_secs(1));
            }
        }
        let _ = fs::metadata(root);
    }
}
extern "C" fn term(_: libc::c_int) {}
