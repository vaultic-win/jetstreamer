#[path="source/native_guards.rs"] mod native_guards;
#[test]
fn root_actual_readonly_input_and_ledger_mounts_reject_even_root_writes(){
 assert_eq!(unsafe{libc::geteuid()},0);
 let root=std::path::PathBuf::from(std::env::var("JETSTREAMER_NATIVE163_READONLY_PROBE_ROOT").unwrap());
 for name in ["inputs","ledger"] {let dir=root.join(name);native_guards::readonly(&dir).unwrap();let error=std::fs::OpenOptions::new().write(true).create_new(true).open(dir.join("must-never-be-created")).unwrap_err();assert_eq!(error.raw_os_error(),Some(libc::EROFS));}
 let state=root.join("state");assert!(native_guards::readonly(&state).is_err());let own=state.join("owned-writable-control");std::fs::write(&own,b"control").unwrap();std::fs::remove_file(own).unwrap();
}
