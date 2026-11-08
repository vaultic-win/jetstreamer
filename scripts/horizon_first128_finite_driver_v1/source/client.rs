//! Own only the directly spawned metadata client; never signal systemd roles.
use anyhow::{Context,Result,ensure};
use std::{io::{Read,ErrorKind},os::fd::AsRawFd,process::{Child,ChildStdout,ChildStderr,Command,Stdio,ExitStatus},time::{Duration,Instant},thread};
use crate::io::{self,Deadline};
const LIMIT:usize=4<<20;
pub struct Client{child:Child,out:ChildStdout,err:ChildStderr,out_closed:bool,err_closed:bool,status:Option<ExitStatus>,stdout:Vec<u8>,stderr:Vec<u8>,cleaned:bool}
fn nonblock(fd:i32)->Result<()>{let flags=unsafe{libc::fcntl(fd,libc::F_GETFL)};ensure!(flags>=0&&unsafe{libc::fcntl(fd,libc::F_SETFL,flags|libc::O_NONBLOCK)}==0,"nonblocking owned pipe");Ok(())}
fn read<R:Read>(r:&mut R,dest:&mut Vec<u8>,closed:&mut bool)->Result<()>{if *closed{return Ok(())}let mut b=[0u8;8192];loop{match r.read(&mut b){Ok(0)=>{*closed=true;return Ok(())},Ok(n)=>{ensure!(dest.len()+n<=LIMIT,"owned descriptor output bound; no drain claimed");dest.extend_from_slice(&b[..n]);},Err(e)if e.kind()==ErrorKind::WouldBlock=>return Ok(()),Err(e)if e.kind()==ErrorKind::Interrupted=>continue,Err(e)=>return Err(e.into())}}}
impl Client{
 pub fn spawn(argv:&[String])->Result<Self>{ensure!(!argv.is_empty(),"empty owned client argv");let mut c=Command::new(&argv[0]);c.args(&argv[1..]).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());io::clean(&mut c);let mut child=c.spawn()?;let out=child.stdout.take().context("owned stdout")?;let err=child.stderr.take().context("owned stderr")?;let mut v=Self{child,out,err,out_closed:false,err_closed:false,status:None,stdout:Vec::new(),stderr:Vec::new(),cleaned:false};nonblock(v.out.as_raw_fd())?;nonblock(v.err.as_raw_fd())?;v.read_ready()?;Ok(v)}
 fn read_ready(&mut self)->Result<()>{read(&mut self.out,&mut self.stdout,&mut self.out_closed)?;read(&mut self.err,&mut self.stderr,&mut self.err_closed)?;if self.status.is_none(){self.status=self.child.try_wait()?;}Ok(())}
 pub fn pump(&mut self,d:&Deadline)->Result<bool>{d.left()?;self.read_ready()?;if self.status.is_some()&&self.out_closed&&self.err_closed{self.cleaned=true;return Ok(true)}let mut fds=[libc::pollfd{fd:if self.out_closed{-1}else{self.out.as_raw_fd()},events:libc::POLLIN,revents:0},libc::pollfd{fd:if self.err_closed{-1}else{self.err.as_raw_fd()},events:libc::POLLIN,revents:0}];let ms=d.left()?.as_millis().min(25) as i32;let result=unsafe{libc::poll(fds.as_mut_ptr(),2,ms)};ensure!(result>=0||std::io::Error::last_os_error().kind()==ErrorKind::Interrupted,"owned descriptor poll");self.read_ready()?;Ok(false)}
 pub fn stdout_chunk(&mut self)->Vec<u8>{std::mem::take(&mut self.stdout)}
 pub fn complete(mut self,d:&Deadline)->Result<(i32,Vec<u8>,Vec<u8>)>{while !self.pump(d)?{}self.cleaned=true;Ok((self.status.context("owned reaped status")?.code().unwrap_or(-1),std::mem::take(&mut self.stdout),std::mem::take(&mut self.stderr)))}
 pub fn stop_and_drain(&mut self)->Result<(Option<i32>,Vec<u8>)>{
  // Two seconds is cleanup only. It creates no success receipt and does not
  // extend admission/hold/reader/guard authority. No thread or pipe is detached.
  let _=self.child.kill();let cleanup=Instant::now()+Duration::from_secs(2);while Instant::now()<cleanup{self.read_ready()?;if self.status.is_some()&&self.out_closed&&self.err_closed{self.cleaned=true;return Ok((self.status.and_then(|s|s.code()),std::mem::take(&mut self.stderr)))}thread::sleep(Duration::from_millis(5));}anyhow::bail!("owned metadata client cleanup did not prove reap+EOF; no drain claim")
 }
}
impl Drop for Client{fn drop(&mut self){if !self.cleaned{let _=self.child.kill();let cleanup=Instant::now()+Duration::from_secs(2);while Instant::now()<cleanup{if self.child.try_wait().is_ok_and(|s|s.is_some()){break}thread::sleep(Duration::from_millis(5));}}}}
#[cfg(test)]mod tests{use super::*;
 #[test]fn actual_owned_child_is_reaped_when_original_deadline_expired(){let argv=vec!["/usr/bin/sleep".into(),"10".into()];let c=Client::spawn(&argv).unwrap();let pid=c.child.id();let at=Instant::now();assert!(c.complete(&Deadline::new(0)).is_err());assert!(at.elapsed()<Duration::from_secs(3));assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());}
 #[test]fn success_requires_real_wait_and_both_descriptor_eofs(){let argv=vec!["/usr/bin/printf".into(),"metadata-control".into()];let(code,out,err)=Client::spawn(&argv).unwrap().complete(&Deadline::new(2)).unwrap();assert_eq!(code,0);assert_eq!(out,b"metadata-control");assert!(err.is_empty());}
}
