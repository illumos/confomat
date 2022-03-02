/*
 * Copyright 2020 Oxide Computer Company
 */

use std::path::{Path, PathBuf};
use std::fs::{DirBuilder, File};
use std::os::unix::fs::DirBuilderExt;
use std::ffi::CString;
use std::io::{Read, BufRead, Write, BufReader, BufWriter};
use std::process::{Command, Stdio};
use std::time::Duration;
use digest::Digest;
use slog::{Logger, info, warn, error};
use anyhow::{Result, bail, anyhow};
use super::os;

#[allow(dead_code)]
#[derive(Debug, PartialEq)]
pub enum HashType {
    SHA1,
    MD5,
    None,
}

#[derive(Debug, PartialEq)]
pub enum FileType {
    Directory,
    File,
    Link,
}

#[derive(Debug, PartialEq)]
pub enum Id {
    Name(String),
    Id(u32),
}

#[derive(Debug, PartialEq)]
pub struct FileInfo {
    pub filetype: FileType,
    pub perms: u32,
    pub owner: Id,
    pub group: Id,
    pub target: Option<PathBuf>, /* for symbolic links */
}

impl FileInfo {
    pub fn is_user_executable(&self) -> bool {
        (self.perms & libc::S_IXUSR) != 0
    }
}

pub fn check<P: AsRef<Path>>(p: P) -> Result<Option<FileInfo>> {
    let name: &str = p.as_ref().to_str().unwrap();
    let cname = CString::new(name.to_string())?;
    let st = Box::into_raw(Box::new(unsafe {
        std::mem::zeroed::<libc::stat>()
    }));
    let (r, e, st) = unsafe {
        let r = libc::lstat(cname.as_ptr(), st);
        let e = os::errno();
        (r, e, Box::from_raw(st))
    };
    if r != 0 {
        if e == libc::ENOENT {
            return Ok(None);
        }

        bail!("lstat({}): errno {}", name, e);
    }

    let fmt = st.st_mode & libc::S_IFMT;

    let filetype = if fmt == libc::S_IFDIR {
        FileType::Directory
    } else if fmt == libc::S_IFREG {
        FileType::File
    } else if fmt == libc::S_IFLNK {
        FileType::Link
    } else {
        bail!("lstat({}): unexpected file type: {:x}", name, fmt);
    };

    let target = if filetype == FileType::Link {
        Some(std::fs::read_link(p)?)
    } else {
        None
    };

    let owner = if let Some(p) = super::unix::get_passwd_by_id(st.st_uid)? {
        Id::Name(p.name.unwrap())
    } else {
        Id::Id(st.st_uid)
    };

    let group = if let Some(g) = super::unix::get_group_by_id(st.st_gid)? {
        Id::Name(g.name.unwrap())
    } else {
        Id::Id(st.st_gid)
    };

    let perms = st.st_mode & 0o7777; /* as per mknod(2) */

    Ok(Some(FileInfo {
        filetype,
        perms,
        owner,
        group,
        target,
    }))
}

pub fn chown<P: AsRef<Path>>(path: P, owner: &str, group: &str) -> Result<()> {
    let (o, g) = match (super::unix::get_passwd_by_name(owner)?,
        super::unix::get_group_by_name(group)?)
    {
        (Some(o), Some(g)) => (o.uid, g.gid),
        _ => bail!("{}:{} not real user/group", owner, group),
    };

    let cname = CString::new(path.as_ref().to_str().unwrap().to_string())?;
    let (r, e) = unsafe {
        let r = libc::lchown(cname.as_ptr(), o, g);
        let e = os::errno();
        (r, e)
    };
    if r != 0 {
        bail!("lchown({}, {}, {}): errno {}", path.as_ref().display(),
            owner, group, e);
    }

    Ok(())
}

pub fn perms<P: AsRef<Path>>(log: &Logger, p: P, owner: &str, group: &str,
    perms: u32)
    -> Result<bool>
{
    let p = p.as_ref();
    let log = log.new(slog::o!("path" => p.display().to_string()));
    let mut did_work = false;

    let fi = if let Some(fi) = check(p)? {
        fi
    } else {
        bail!("{} does not exist", p.display());
    };

    /*
     * Check permissions and ownership on the path.  Note that symbolic links do
     * not actually have permissions, so we skip those completely.
     */
    if fi.filetype != FileType::Link && fi.perms != perms {
        did_work = true;
        info!(log, "perms are {:o}, should be {:o}", fi.perms, perms);

        let cname = CString::new(p.to_str().unwrap().to_string())?;
        let (r, e) = unsafe {
            let r = libc::chmod(cname.as_ptr(), perms);
            let e = os::errno();
            (r, e)
        };
        if r != 0 {
            bail!("lchmod({}, {:o}): errno {}", p.display(), perms, e);
        }

        info!(log, "chmod ok");
    }

    match (fi.owner, fi.group) {
        (Id::Name(o), Id::Name(g)) if o == owner && g == group => {
            info!(log, "ownership already OK ({}:{})", o, g);
        }
        (o, g) => {
            did_work = true;
            info!(log, "ownership wrong ({:?}:{:?}, not {}:{})", o, g,
                owner, group);
            chown(p, owner, group)?;

            info!(log, "chown ok");
        }
    };

    Ok(did_work)
}

pub fn directory<P: AsRef<Path>>(log: &Logger, dir: P, owner: &str,
    group: &str, mode: u32)
    -> Result<bool>
{
    let dir = dir.as_ref();
    let mut did_work = false;

    if let Some(fi) = check(dir)? {
        /*
         * The path exists already.  Make sure it is a directory.
         */
        if fi.filetype != FileType::Directory {
            bail!("{} is {:?}, not a directory", dir.display(), fi.filetype);
        }
    } else {
        /*
         * Create the directory, and all missing parents:
         */
        did_work = true;
        info!(log, "creating directory: {}", dir.display());
        DirBuilder::new()
            .recursive(true)
            .mode(mode)
            .create(dir)?;

        /*
         * Check the path again, to make sure we have up-to-date information:
         */
        check(dir)?.expect("directory should now exist");
    }

    if perms(log, dir, owner, group, mode)? {
        did_work = true;
    }

    Ok(did_work)
}

#[derive(Debug, PartialEq)]
pub enum Create {
    IfMissing,
    Always,
}

fn open<P: AsRef<Path>>(p: P) -> Result<File> {
    let p = p.as_ref();

    match File::open(p) {
        Ok(f) => Ok(f),
        Err(e) => Err(anyhow!("opening \"{}\": {}", p.display(), e)),
    }
}

fn comparestr<P: AsRef<Path>>(src: &str, dst: P) -> Result<bool> {
    let dstf = open(dst)?;
    let mut dstr = BufReader::new(dstf);

    /*
     * Assume that if the file can be passed in as a string slice, it can also
     * be loaded into memory fully for comparison.
     */
    let mut dstbuf = Vec::<u8>::new();
    dstr.read_to_end(&mut dstbuf)?;

    Ok(dstbuf == src.as_bytes())
}

fn compare<P1: AsRef<Path>, P2: AsRef<Path>>(src: P1, dst: P2) -> Result<bool> {
    let srcf = open(src)?;
    let dstf = open(dst)?;
    let mut srcr = BufReader::new(srcf);
    let mut dstr = BufReader::new(dstf);

    loop {
        let mut srcbuf = [0u8; 1];
        let mut dstbuf = [0u8; 1];
        let srcsz = srcr.read(&mut srcbuf)?;
        let dstsz = dstr.read(&mut dstbuf)?;

        if srcsz != dstsz {
            /*
             * Files are not the same size...
             */
            return Ok(false);
        }

        if srcsz == 0 {
            /*
             * End-of-file reached, without a mismatched comparison.  These
             * files are equal in contents.
             */
            return Ok(true);
        }

        if srcbuf != dstbuf {
            /*
             * This portion of the read files are not the same.
             */
            return Ok(false);
        }
    }
}

pub fn removed<P: AsRef<Path>>(log: &Logger, dst: P) -> Result<()> {
    let dst = dst.as_ref();

    if let Some(fi) = check(dst)? {
        match fi.filetype {
            FileType::File | FileType::Link => {
                info!(log, "file {} exists (as {:?}), removing",
                    dst.display(), fi.filetype);

                std::fs::remove_file(dst)?;
            }
            t => {
                bail!("file {} exists as {:?}, unexpected type",
                    dst.display(), t);
            }
        }
    } else {
        info!(log, "file {} does not already exist, skipping removal",
            dst.display());
    }

    Ok(())
}

pub fn file_str<P: AsRef<Path>>(log: &Logger, contents: &str, dst: P,
    owner: &str, group: &str, mode: u32, create: Create) -> Result<bool>
{
    let dst = dst.as_ref();
    let mut did_work = false;

    let do_copy = if let Some(fi) = check(dst)? {
        /*
         * The path exists already.
         */
        match create {
            Create::IfMissing if fi.filetype == FileType::File => {
                info!(log, "file {} exists, skipping population",
                    dst.display());
                false
            }
            Create::IfMissing if fi.filetype == FileType::Link => {
                warn!(log, "symlink {} exists, skipping population",
                    dst.display());
                false
            }
            Create::IfMissing => {
                /*
                 * Avoid clobbering an unexpected entry when we have been asked
                 * to preserve in the face of modifications.
                 */
                bail!("{} should be a file, but is a {:?}",
                    dst.display(), fi.filetype);
            }
            Create::Always if fi.filetype == FileType::File => {
                /*
                 * Check the contents of the file to make sure it matches
                 * what we expect.
                 */
                if comparestr(contents, dst)? {
                    info!(log, "file {} exists, with correct contents",
                        dst.display());
                    false
                } else {
                    warn!(log, "file {} exists, with wrong contents, unlinking",
                        dst.display());
                    std::fs::remove_file(dst)?;
                    true
                }
            }
            Create::Always => {
                /*
                 * We found a file type we don't expect.  Try to unlink it
                 * anyway.
                 */
                warn!(log, "file {} exists, of type {:?}, unlinking",
                    dst.display(), fi.filetype);
                std::fs::remove_file(dst)?;
                true
            }
        }
    } else {
        info!(log, "file {} does not exist", dst.display());
        true
    };

    if do_copy {
        did_work = true;
        info!(log, "writing {} ...", dst.display());

        let mut f = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&dst)?;
        f.write_all(contents.as_bytes())?;
        f.flush()?;
    }

    if perms(log, dst, owner, group, mode)? {
        did_work = true;
    }

    info!(log, "ok!");
    Ok(did_work)
}

pub fn file<P1: AsRef<Path>, P2: AsRef<Path>>(log: &Logger, src: P1, dst: P2,
    owner: &str, group: &str, mode: u32, create: Create) -> Result<bool>
{
    let src = src.as_ref();
    let dst = dst.as_ref();
    let mut did_work = false;

    let do_copy = if let Some(fi) = check(dst)? {
        /*
         * The path exists already.
         */
        match create {
            Create::IfMissing if fi.filetype == FileType::File => {
                info!(log, "file {} exists, skipping population",
                    dst.display());
                false
            }
            Create::IfMissing if fi.filetype == FileType::Link => {
                warn!(log, "symlink {} exists, skipping population",
                    dst.display());
                false
            }
            Create::IfMissing => {
                /*
                 * Avoid clobbering an unexpected entry when we have been asked
                 * to preserve in the face of modifications.
                 */
                bail!("{} should be a file, but is a {:?}",
                    dst.display(), fi.filetype);
            }
            Create::Always if fi.filetype == FileType::File => {
                /*
                 * Check the contents of the file to make sure it matches
                 * what we expect.
                 */
                if compare(src, dst)? {
                    info!(log, "file {} exists, with correct contents",
                        dst.display());
                    false
                } else {
                    warn!(log, "file {} exists, with wrong contents, unlinking",
                        dst.display());
                    std::fs::remove_file(dst)?;
                    true
                }
            }
            Create::Always => {
                /*
                 * We found a file type we don't expect.  Try to unlink it
                 * anyway.
                 */
                warn!(log, "file {} exists, of type {:?}, unlinking",
                    dst.display(), fi.filetype);
                std::fs::remove_file(dst)?;
                true
            }
        }
    } else {
        info!(log, "file {} does not exist", dst.display());
        true
    };

    if do_copy {
        did_work = true;
        info!(log, "copying {} -> {} ...", src.display(), dst.display());
        std::fs::copy(src, dst)?;
    }

    if perms(log, dst, owner, group, mode)? {
        did_work = true;
    }

    info!(log, "ok!");
    Ok(did_work)
}

pub fn symlink<P1: AsRef<Path>, P2: AsRef<Path>>(log: &Logger, dst: P1,
    target: P2, owner: &str, group: &str)
    -> Result<bool>
{
    let dst = dst.as_ref();
    let target = target.as_ref();
    let mut did_work = false;

    let do_link = if let Some(fi) = check(dst)? {
        if fi.filetype == FileType::Link {
            let fitarget = fi.target.unwrap();
            if fitarget == target {
                info!(log, "link target ok ({})", target.display());
                false
            } else {
                warn!(log, "link target wrong: want {}, got {}; unlinking",
                    target.display(), fitarget.display());
                std::fs::remove_file(dst)?;
                true
            }
        } else {
            /*
             * File type not correct.  Unlink.
             */
            warn!(log, "file {} exists, of type {:?}, unlinking",
                dst.display(), fi.filetype);
            std::fs::remove_file(dst)?;
            true
        }
    } else {
        info!(log, "link {} does not exist", dst.display());
        true
    };

    if do_link {
        did_work = true;
        info!(log, "linking {} -> {} ...", dst.display(), target.display());
        std::os::unix::fs::symlink(target, dst)?;
    }

    if perms(log, dst, owner, group, 0)? {
        did_work = true;
    }

    info!(log, "ok!");
    Ok(did_work)
}

pub fn hash_file<P: AsRef<Path>>(p: P, hashtype: &HashType) -> Result<String> {
    let p = p.as_ref();

    if let HashType::None = hashtype {
        return Ok("".to_string());
    }

    let f = File::open(p)?;
    let mut r = BufReader::new(f);
    let mut buf = [0u8; 128 * 1024];

    let mut digest: Box<dyn digest::DynDigest> = match hashtype {
        HashType::MD5 => Box::new(md5::Md5::new()),
        HashType::SHA1 => Box::new(sha1::Sha1::new()),
        HashType::None => panic!("None unexpected"),
    };

    loop {
        let sz = r.read(&mut buf)?;
        if sz == 0 {
            break;
        }

        digest.input(&buf[0..sz]);
    }

    let mut out = String::new();
    let hash = digest.result();
    for byt in hash.iter() {
        out.push_str(&format!("{:02x}", byt));
    }

    Ok(out)
}

fn sleep(s: u64) {
    std::thread::sleep(Duration::from_secs(s));
}

pub fn download_file<P: AsRef<Path>>(log: &Logger, url: &str, p: P, hash: &str,
    hashtype: HashType) -> Result<bool>
{
    let p = p.as_ref();
    let mut did_work = false;

    let client = reqwest::blocking::ClientBuilder::new()
        .user_agent("confomat")
        .connect_timeout(Duration::from_secs(15))
        .build()?;

    loop {
        /*
         * Check to see if the file exists already.
         */
        if let Some(fi) = check(p)? {
            if fi.filetype != FileType::File {
                warn!(log, "type {:?} unexpected; unlinking", fi.filetype);
                std::fs::remove_file(p)?;
                continue;
            }

            info!(log, "file {} exists; checking hash...", p.display());

            let actual_hash = hash_file(p, &hashtype)?;
            info!(log, " got hash {}", actual_hash);
            info!(log, "want hash {}", hash);

            if hash == actual_hash {
                info!(log, "hash match!  done");
                break;
            } else {
                warn!(log, "does not match; unlinking");
                std::fs::remove_file(p)?;
                continue;
            }
        }

        did_work = true;
        info!(log, "file {} does not exist; downloading from {}", p.display(),
            url);

        let mut res = client.get(url).send()?;

        if !res.status().is_success() {
            warn!(log, "HTTP {:?}; retrying...", res.status());
            sleep(5);
            continue;
        }

        let f = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(p)?;
        let mut w = BufWriter::new(f);

        let sz = match std::io::copy(&mut res, &mut w) {
            Ok(sz) => sz,
            Err(e) => {
                std::fs::remove_file(p)?;
                warn!(log, "download error (retrying): {}", e);
                sleep(5);
                continue;
            }
        };

        info!(log, "downloaded {} bytes", sz);
    }

    Ok(did_work)
}

fn spawn_reader<T>(log: &Logger, name: &str, stream: Option<T>)
    -> Option<std::thread::JoinHandle<()>>
where
    T: Read + Send + 'static,
{
    let name = name.to_string();
    let stream = match stream {
        Some(stream) => stream,
        None => return None,
    };

    let log = log.clone();

    Some(std::thread::spawn(move || {
        let mut r = BufReader::new(stream);

        loop {
            let mut buf = String::new();

            match r.read_line(&mut buf) {
                Ok(0) => {
                    /*
                     * EOF.
                     */
                    return;
                }
                Ok(_) => {
                    let s = buf.trim();

                    if !s.is_empty() {
                        info!(log, "{}| {}", name, s);
                    }
                }
                Err(e) => {
                    error!(log, "failed to read {}: {}", name, e);
                    std::process::exit(100);
                }
            }
        }
    }))
}

pub fn run<S: AsRef<str>>(log: &Logger, args: &[S]) -> Result<()> {
    let args: Vec<&str> = args.iter().map(|s| s.as_ref()).collect();

    let mut cmd = Command::new(&args[0]);
    cmd.env_remove("LANG");
    cmd.env_remove("LC_CTYPE");
    cmd.env_remove("LC_NUMERIC");
    cmd.env_remove("LC_TIME");
    cmd.env_remove("LC_COLLATE");
    cmd.env_remove("LC_MONETARY");
    cmd.env_remove("LC_MESSAGES");
    cmd.env_remove("LC_ALL");

    if args.len() > 1 {
        cmd.args(&args[1..]);
    }

    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    info!(log, "exec: {:?}", &args);

    let mut child = cmd.spawn()?;

    let readout = spawn_reader(log, "O", child.stdout.take());
    let readerr = spawn_reader(log, "E", child.stderr.take());

    if let Some(t) = readout {
        t.join().expect("join stdout thread");
    }
    if let Some(t) = readerr {
        t.join().expect("join stderr thread");
    }

    match child.wait() {
        Err(e) => Err(e.into()),
        Ok(es) => {
            if !es.success() {
                Err(anyhow!("exec {:?}: failed {:?}", &args, &es))
            } else {
                Ok(())
            }
        }
    }
}
