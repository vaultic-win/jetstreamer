//! Exact epoch168 transport capture with fixed production endpoints and selector.
use reqwest::{Client, Response, header::{HeaderMap, ACCEPT_ENCODING, IF_MATCH, RANGE}};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs::{File, OpenOptions, Permissions}, io::{Read, Write},
    os::{fd::{AsRawFd, FromRawFd}, unix::{ffi::OsStrExt, fs::{MetadataExt, OpenOptionsExt, PermissionsExt}}},
    path::{Path, PathBuf}, time::{Duration, Instant, SystemTime, UNIX_EPOCH}};
type Res<T> = Result<T, Box<dyn std::error::Error>>;
const CAR: &str = "https://files.old-faithful.net/168/epoch-168.car";
const INDEX: &str = "https://files.old-faithful.net/168/epoch-168-slot-ranges.raw";
const INDEX_BYTES: usize = 5_184_000;
const RECORD: usize = 152_191 * 12;
const MAX_INPUT: usize = 256 << 20;
const MAX_HEADERS: usize = 64 << 10;
const MEMORY: u64 = 1 << 30;
const STORAGE: u64 = 544 << 20;
const SIGNATURE: &str = "3qysw2HZ4pE11jjL3HpXA9UJ6kxqPkY2se93agYERfzDNoweP6sxqvhPGPjBkmwmD2m9SrRB96y75Vbi3mACtrpz";
fn require(b: bool, s: &str) -> Res<()> { if b { Ok(()) } else { Err(s.into()) } }
fn hash(b: &[u8]) -> String { format!("{:x}", Sha256::digest(b)) }
fn now() -> Res<u64> { Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis().try_into()?) }
fn sha_text(s: &str) -> bool { s.len()==64 && s.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)) }
fn bound_file(mut f: File, expected: &str, maximum: usize) -> Res<Vec<u8>> {
    require(sha_text(expected),"invalid bound hash")?;
    let a=f.metadata()?;
    require(a.is_file() && a.uid()==0 && a.nlink()==1 && a.mode()&0o222==0 && a.len()>0 && a.len()<=maximum as u64,"unsafe bound member")?;
    let mut bytes=Vec::new(); (&mut f).take(maximum as u64+1).read_to_end(&mut bytes)?;
    let b=f.metadata()?;
    require((a.dev(),a.ino(),a.len(),a.mtime(),a.mtime_nsec(),a.ctime(),a.ctime_nsec())==
        (b.dev(),b.ino(),b.len(),b.mtime(),b.mtime_nsec(),b.ctime(),b.ctime_nsec()) && bytes.len()==a.len() as usize && hash(&bytes)==expected,"bound bytes changed")?;
    Ok(bytes)
}
fn bound(path: &Path, expected: &str, maximum: usize) -> Res<Vec<u8>> {
    require(path.is_absolute() && path.canonicalize()?==path, "noncanonical bound path")?;
    let f=OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW|libc::O_CLOEXEC).open(path)?;
    bound_file(f,expected,maximum)
}
fn running_image(expected: &str) -> Res<()> {
    // Deliberately follow only the kernel's running-image link, never its pathname target.
    let f=OpenOptions::new().read(true).custom_flags(libc::O_CLOEXEC).open("/proc/self/exe")?;
    bound_file(f,expected,256<<20)?;Ok(())
}
fn exact_keys(v: &Value, wanted: &[&str]) -> Res<()> {
    let m=v.as_object().ok_or("object required")?;
    require(m.len()==wanted.len() && wanted.iter().all(|k|m.contains_key(*k)),"unknown or missing plan field")
}
fn string<'a>(v: &'a Value, key: &str) -> Res<&'a str> { v[key].as_str().ok_or_else(||format!("missing string {key}").into()) }
fn number(v: &Value, key: &str) -> Res<u64> { v[key].as_u64().ok_or_else(||format!("missing integer {key}").into()) }
fn clock(f: &Value) -> Res<u64> {
    let start=number(f,"not_before_unix_millis")?; let end=number(f,"deadline_unix_millis")?;
    let n=now()?;
    require(start<=n && n<end && end.checked_sub(start).is_some_and(|d|(30_000..=900_000).contains(&d)),"original capture funding clock expired")?;
    Ok(end)
}
#[derive(Clone,Copy)]
struct Deadline { unix_millis: u64, monotonic: Instant }
impl Deadline {
    fn check(self) -> Res<()> {
        require(now()?<self.unix_millis && Instant::now()<self.monotonic,"capture original deadline expired")
    }
}
fn budget(f: &Value) -> Res<Deadline> {
    require(f["schema"]=="horizon168-exact-capture-funding-v1" && f["owner"]=="/root" &&
        f["all_original_memory_DATA_OS_native_promises_retained"]==true &&
        f["actual_capture_guard_and_allocation_accepted"]==true &&
        number(f,"reserved_capture_memory_bytes")? >= MEMORY && number(f,"reserved_capture_storage_bytes")? >= STORAGE &&
        f["resource_credit_bytes"]==0 && f["replay_launch_authorized"]==false && f["remote_mutations"]==false,
        "capture funding/guard contract missing")?;
    let end=clock(f)?;
    let remaining=end.checked_sub(now()?).ok_or("capture funding expired before launch")?;
    require(remaining>0,"capture funding expired before launch")?;
    Ok(Deadline{unix_millis:end,monotonic:Instant::now().checked_add(Duration::from_millis(remaining)).ok_or("monotonic deadline overflow")?})
}
struct Output { directory: File, path: PathBuf, members: BTreeMap<String,Value> }
impl Output {
    fn create(path: &Path) -> Res<Self> {
        require(path.is_absolute(),"absolute output required")?;
        let parent=path.parent().ok_or("output parent")?;
        require(parent.canonicalize()?==parent,"noncanonical output parent")?;
        let parent_f=OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC).open(parent)?;
        let m=parent_f.metadata()?;
        require(m.is_dir() && m.uid()==0 && m.mode()&0o7777==0o700,"output parent must be root0700")?;
        let name=std::ffi::CString::new(path.file_name().ok_or("output basename")?.as_bytes())?;
        require(unsafe{libc::mkdirat(parent_f.as_raw_fd(),name.as_ptr(),0o700)}==0,"occupied output")?;
        parent_f.sync_all()?;
        let fd=unsafe{libc::openat(parent_f.as_raw_fd(),name.as_ptr(),libc::O_RDONLY|libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC)};
        require(fd>=0,"open fresh output")?;
        Ok(Self{directory:unsafe{File::from_raw_fd(fd)},path:path.into(),members:BTreeMap::new()})
    }
    fn file(&self,name: &str) -> Res<File> {
        require(!name.is_empty() && !name.contains('/') && name!="." && name!="..","unsafe output member")?;
        let n=std::ffi::CString::new(name)?;
        let fd=unsafe{libc::openat(self.directory.as_raw_fd(),n.as_ptr(),libc::O_WRONLY|libc::O_CREAT|libc::O_EXCL|libc::O_NOFOLLOW|libc::O_CLOEXEC,0o600)};
        require(fd>=0,"occupied output member")?; Ok(unsafe{File::from_raw_fd(fd)})
    }
    fn finish(&mut self,name: &str,f: &File,bytes: &[u8]) -> Res<()> {
        f.sync_all()?; f.set_permissions(Permissions::from_mode(0o400))?; f.sync_all()?; self.directory.sync_all()?;
        self.members.insert(name.into(),json!({"bytes":bytes.len(),"sha256":hash(bytes)})); Ok(())
    }
    fn bytes(&mut self,name: &str,b: &[u8]) -> Res<()> { let mut f=self.file(name)?; f.write_all(b)?; self.finish(name,&f,b) }
    fn json(&mut self,name: &str,v: &Value) -> Res<()> {
        let mut b=serde_json::to_vec_pretty(v)?; b.push(b'\n'); require(b.len()<=1<<20,"metadata allowance exceeded")?; self.bytes(name,&b)
    }
}
fn single(h: &HeaderMap,key: &str) -> Res<String> {
    require(h.get_all(key).iter().count()==1,"missing or duplicated response identity/header")?;
    Ok(h.get(key).ok_or("header absent")?.to_str()?.to_owned())
}
fn strong_etag(s: &str) -> bool {
    s.len()>=2 && s.len()<=1024 && s.starts_with('"') && s.ends_with('"') &&
        s.as_bytes()[1..s.len()-1].iter().all(|&b|b==0x21||(0x23..=0x7e).contains(&b))
}
fn identity_encoding(h: &HeaderMap) -> Res<()> {
    require(!h.contains_key("transfer-encoding"),"transfer encoded response rejected")?;
    if h.contains_key("content-encoding") { require(single(h,"content-encoding")?=="identity","encoded representation rejected")?; }
    Ok(())
}
fn headers(h: &HeaderMap) -> Res<Value> {
    let mut n=0usize; let mut rows=Vec::new();
    for (name,value) in h { n=n.checked_add(name.as_str().len()+value.as_bytes().len()).ok_or("header overflow")?;
        require(n<=MAX_HEADERS,"response header bound")?;
        rows.push(json!({"name":name.as_str(),"original_value_bytes":value.as_bytes()})); }
    Ok(json!(rows))
}
#[derive(Clone,Debug,PartialEq)]
struct Representation { etag: String, length: u64, version: BTreeMap<String,String> }
fn representation(h: &HeaderMap) -> Res<Representation> {
    identity_encoding(h)?;
    let etag=single(h,"etag")?; require(strong_etag(&etag),"strong representation ETag required")?;
    let length: u64=single(h,"content-length")?.parse()?; require(length>0,"empty provider object")?;
    Ok(Representation{etag,length,version:version_headers(h)?})
}
fn version_headers(h: &HeaderMap) -> Res<BTreeMap<String,String>> {
    let mut version=BTreeMap::new();
    for key in ["x-amz-version-id","x-goog-generation"] { if h.contains_key(key) {version.insert(key.into(),single(h,key)?);} }
    Ok(version)
}
fn range_headers(h: &HeaderMap,p: &Representation,start: u64,length: u64) -> Res<()> {
    identity_encoding(h)?; let end=start.checked_add(length).ok_or("range overflow")?;
    require(length>0 && end<=p.length,"range outside representation")?;
    require(single(h,"etag")?==p.etag && single(h,"content-length")?.parse::<u64>()?==length &&
        single(h,"content-range")?==format!("bytes {start}-{}/{}",end-1,p.length),"conditional response range/identity differs")?;
    require(version_headers(h)?==p.version,"provider version headers changed/appeared/disappeared")?;
    Ok(())
}
fn varint(b: &[u8]) -> Res<(usize,usize)> {
    let mut n=0u64;
    for i in 0..10 { let x=*b.get(i).ok_or("truncated CAR header varint")?;
        require(i!=9||x<=1,"CAR header varint overflow")?; n|=u64::from(x&127)<<(i*7);
        if x&128==0 {require(i==0||x!=0,"nonminimal CAR header varint")?;
            require((1..=1024).contains(&n),"CAR header size bound")?;return Ok((usize::try_from(n)?,i+1));} }
    Err("unterminated CAR header varint".into())
}
fn target_range(index: &[u8],object_length: u64,header: usize) -> Res<(u64,u64)> {
    require(index.len()==INDEX_BYTES,"complete raw index length differs")?;
    let offset=u64::from_le_bytes(index[RECORD..RECORD+8].try_into()?);
    let length=u64::from(u32::from_le_bytes(index[RECORD+8..RECORD+12].try_into()?));
    require(length>0 && offset>=header as u64 && offset.checked_add(length).is_some_and(|e|e<=object_length) &&
        length<=MAX_INPUT.checked_sub(header).ok_or("header exceeds input bound")? as u64,"invalid/missing/oversized exact slot range")?;
    Ok((offset,length))
}
fn remaining(deadline: Deadline) -> Res<Duration> {
    deadline.check()?;
    let wall=Duration::from_millis(deadline.unix_millis.checked_sub(now()?).ok_or("capture deadline expired")?);
    let monotonic=deadline.monotonic.checked_duration_since(Instant::now()).ok_or("monotonic capture deadline expired")?;
    let d=wall.min(monotonic).min(Duration::from_secs(60));require(!d.is_zero(),"capture deadline expired")?;Ok(d)
}
async fn head(client: &Client,out: &mut Output,label: &str,url: &str,deadline: Deadline) -> Res<Representation> {
    let r=client.head(url).header(ACCEPT_ENCODING,"identity").timeout(remaining(deadline)?).send().await?;
    out.json(&format!("{label}.json"),&json!({"method":"HEAD","url":url,"status":r.status().as_u16(),"headers":headers(r.headers())?,"recorded_at_unix_millis":now()?}))?;
    require(r.status().as_u16()==200 && r.url().as_str()==url,"HEAD status/redirect differs")?; representation(r.headers())
}
async fn get(client: &Client,out: &mut Output,label: &str,url: &str,p: &Representation,range: (u64,u64),deadline: Deadline) -> Res<Vec<u8>> {
    let (start,length)=range;
    let end=start.checked_add(length).ok_or("request overflow")?; require(length>0 && end<=p.length && length<=MAX_INPUT as u64,"request bound")?;
    let range=format!("bytes={start}-{}",end-1);
    let mut r: Response=client.get(url).header(ACCEPT_ENCODING,"identity").header(IF_MATCH,&p.etag).header(RANGE,&range)
        .timeout(remaining(deadline)?).send().await?;
    out.json(&format!("{label}-response.json"),&json!({"method":"GET","url":url,"request_range":range,"request_if_match":p.etag,
        "status":r.status().as_u16(),"headers":headers(r.headers())?,"recorded_at_unix_millis":now()?}))?;
    require(r.status().as_u16()==206 && r.url().as_str()==url,"exact range requires206 without redirects")?;
    range_headers(r.headers(),p,start,length)?;
    let name=format!("{label}.bin"); let mut file=out.file(&name)?;
    let mut body=Vec::with_capacity(usize::try_from(length)?);
    let transfer:Res<()> = async {
        loop {
            deadline.check()?;
            let Some(chunk)=r.chunk().await? else {break};
            require(body.len().checked_add(chunk.len()).is_some_and(|n|n<=length as usize),"provider body exceeds exact range")?;
            file.write_all(&chunk)?; body.extend_from_slice(&chunk);
        }
        Ok(())
    }.await;
    // Best effort on every transfer failure; no partial bytes are removed or promoted.
    let durability=file.sync_all().and_then(|()|out.directory.sync_all());
    if let Err(e)=transfer {let _=durability;return Err(e);}
    durability?;
    require(body.len()==length as usize,"truncated provider body")?;
    out.finish(&name,&file,&body)?; Ok(body)
}
async fn capture(client: &Client,out: &mut Output,deadline: Deadline,plan_bytes: &[u8],funding_bytes: &[u8]) -> Res<()> {
    out.bytes("capture-plan.json",plan_bytes)?;out.bytes("funding.json",funding_bytes)?;
    let car=head(client,out,"car-before",CAR,deadline).await?;
    let index=head(client,out,"index-before",INDEX,deadline).await?;
    require(index.length==INDEX_BYTES as u64 && car.length>=10,"provider size contract differs")?;
    let raw_index=get(client,out,"raw-index",INDEX,&index,(0,index.length),deadline).await?;
    let probe=get(client,out,"car-header-probe",CAR,&car,(0,10),deadline).await?;
    let (n,prefix)=varint(&probe)?; let header_len=n+prefix;
    let header=get(client,out,"car-header",CAR,&car,(0,header_len as u64),deadline).await?;
    require(header[..probe.len().min(header.len())]==probe[..probe.len().min(header.len())],"header bytes changed between conditional requests")?;
    let (offset,length)=target_range(&raw_index,car.length,header.len())?;drop(raw_index);
    let segment=get(client,out,"slot-range",CAR,&car,(offset,length),deadline).await?;
    require(head(client,out,"car-after",CAR,deadline).await?==car && head(client,out,"index-after",INDEX,deadline).await?==index,"provider identity changed after capture")?;
    deadline.check()?;
    let mut f=out.file("input.car")?;f.write_all(&header)?;f.write_all(&segment)?;f.sync_all()?;
    let mut digest=Sha256::new();digest.update(&header);digest.update(&segment);let input_sha=format!("{:x}",digest.finalize());
    let input_len=header.len()+segment.len();require(input_len<=MAX_INPUT,"combined input bound")?;
    f.set_permissions(Permissions::from_mode(0o400))?;f.sync_all()?;out.directory.sync_all()?;
    deadline.check()?;
    out.members.insert("input.car".into(),json!({"bytes":input_len,"sha256":input_sha}));
    let input=json!({"path":out.path.join("input.car"),"sha256":input_sha,"bytes":input_len});
    out.json("acquisition.json",&json!({"schema":"horizon168-conditional-original-byte-capture-v1","epoch":168,"slot":72728191,
        "car_url":CAR,"raw_index_url":INDEX,"car_strong_etag":car.etag,"car_object_bytes":car.length,"car_version_headers":car.version,
        "index_strong_etag":index.etag,"index_version_headers":index.version,"index_record":152191,"index_record_byte_range_inclusive":[1826292,1826303],
        "actual_car_offset":offset,"actual_car_length":length,"input":input,"original_car_header_bytes":header.len(),
        "input_composition":"unchanged originalCARheader bytes followed by unchanged exact indexed slot-range bytes; original header roots not rewritten",
        "conditional_representation_identity_stable":true,"provider_generation_authenticated":false,"semantic_complete_target_not_yet_proven":true,
        "canonical_archive":false,"canonical_state_proven":false,"replay_launch_authorized":false,"runtime_promotion_authorized":false,"remote_mutations":false}))?;
    let receipt=out.members["acquisition.json"].clone();
    out.json("extract-plan.candidate.json",&json!({"schema":"jetstreamer-epoch168-target-source-extract-plan-v1","input":input,
        "acquisition_receipt":{"path":out.path.join("acquisition.json"),"sha256":receipt["sha256"],"bytes":receipt["bytes"]},
        "output_directory":out.path.join("diagnostic"),"epoch":168,"slot":72728191,"entry_index":433,"transaction_slot_index":532,"signature":SIGNATURE}))?;
    deadline.check()?;
    let members=out.members.clone();
    out.json("completion.json",&json!({"schema":"horizon168-capture-transport-completion-v1","members":members,"transport_only":true,
        "marker_alone_is_not_acceptance":true,"successful_guarded_native_exit_before_original_deadline_required":true,"original_deadline_unix_millis":deadline.unix_millis,
        "exact_slot_semantics_accepted":false,"provider_generation_authenticated":false,"resource_credit_bytes":0,"remote_mutations":false,"replay_launch_authorized":false}))?;
    let completion=out.members["completion.json"]["sha256"].as_str().ok_or("completion digest")?.to_owned();
    // A marker alone is never acceptance: Root must bind successful native exit before
    // the original deadline, the guard receipt, all hashes and absence of failure.json.
    out.bytes("COMPLETION.sha256",format!("{completion}  completion.json\n").as_bytes())?;deadline.check()?;Ok(())
}
fn client_builder() -> reqwest::ClientBuilder {
    Client::builder().https_only(true).http1_only().redirect(reqwest::redirect::Policy::none()).retry(reqwest::retry::never()).no_proxy()
        .no_gzip().no_brotli().no_deflate().no_zstd().connect_timeout(Duration::from_secs(10)).read_timeout(Duration::from_secs(30))
        .timeout(Duration::from_secs(60)).user_agent("jetstreamer-epoch168-diagnostic-capture/1")
}
fn run() -> Res<()> {
    let a:Vec<_>=std::env::args().collect();
    require(a.len()==6 && a[2]=="--plan-sha256" && a[4]=="--self-sha256","usage: capture168 PLAN --plan-sha256 HEX --self-sha256 HEX")?;
    require(unsafe{libc::geteuid()}==0,"root capture requires private charged state")?;
    running_image(&a[5])?;
    let plan_bytes=bound(Path::new(&a[1]),&a[3],65536)?; let p:Value=serde_json::from_slice(&plan_bytes)?;
    exact_keys(&p,&["schema","output_directory","current_funding"])?;
    require(p["schema"]=="horizon168-exact-capture-plan-v1","wrong fixed capture plan")?;
    exact_keys(&p["current_funding"],&["path","sha256"])?;
    let funding_bytes=bound(Path::new(string(&p["current_funding"],"path")?),string(&p["current_funding"],"sha256")?,1<<20)?;
    let funding:Value=serde_json::from_slice(&funding_bytes)?;let deadline=budget(&funding)?;
    let mut out=Output::create(Path::new(string(&p,"output_directory")?))?;
    let client=client_builder().build()?;
    let rt=tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let result=rt.block_on(capture(&client,&mut out,deadline,&plan_bytes,&funding_bytes));
    if let Err(ref e)=result {let _=out.json("failure.json",&json!({"schema":"horizon168-capture-failure-v1","error":e.to_string().chars().take(8192).collect::<String>(),"complete":false,"replay_launch_authorized":false,"resource_credit_bytes":0}));}
    result
}
fn main(){if let Err(e)=run(){eprintln!("exact168 capture rejected: {e}");std::process::exit(1);}}
#[cfg(test)]mod tests;
#[cfg(all(test, feature = "native-transport-tests"))]
mod native_transport_tests;
