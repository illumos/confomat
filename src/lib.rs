/*
 * Copyright 2020 Oxide Computer Company
 */

use jmclib::dirs::rootdir;

use std::process::exit;
use std::io::{Read, Write};
use std::path::{PathBuf, Path};
use std::fmt::Debug;
use std::collections::HashMap;

use slog::Logger;

use anyhow::{Result, bail};

pub mod os;
pub mod unix;
pub mod digitalocean;

/*
 * For backwards compatibility with prior versions of the code:
 */
pub mod illumos {
    pub use super::unix::{
        get_group_by_id,
        get_passwd_by_id,
        get_passwd_by_name,
        get_group_by_name,
    };
    #[cfg(target_os = "illumos")]
    pub use super::os::{
        get_user_attr_by_name,
    };
}

mod common;
use common::*;

mod ensure;
pub use ensure::{Create, FileType, FileInfo, HashType};

/*
 * Constants for commonly used User and Group names:
 */
pub const ROOT: &str = "root";
pub const BIN: &str = "bin";
pub const SYS: &str = "sys";

pub enum InstancePosture {
    Prohibited,
    Required,
}

pub type RoleFunc = fn(c: &Context) -> Result<()>;

pub struct RoleProvider {
    /**
     * The operator-visible name of this role.  This name will be used on the
     * command line and in paths within a confomat data directory, so should be
     * lower case with no spaces; e.g., "homedir" not "Home Dir".
     */
    pub name: &'static str,

    /**
     * This function will be called by confomat when the role is applied to the
     * running system.  This function must alter the system and should be
     * idempotent.
     */
    pub func: RoleFunc,

    /**
     * Does this role require an instance or not?
     */
    pub instance_posture: InstancePosture,
}

#[derive(Debug, PartialEq)]
pub enum OS {
    OmniOS,
    OpenIndiana,
    SmartOS,
}

#[derive(Debug, PartialEq)]
pub enum HomeDir {
    ZFS(String), /* Create home directories as children of this dataset */
    NFS, /* Home directories are mounted via autofs */
    Bare, /* Create home directories with mkdir(2) and no special handling */
}

pub struct Context<'a> {
    confomat: &'a Confomat,
    role: &'a Role,
    instance: Option<String>,
    log: Logger,
}

struct Role {
    name: String,
    func: RoleFunc,
    allow_instance: bool,
}

pub struct Confomat {
    os: OS,
    dir: PathBuf,
    nodename: String,
    #[cfg(target_os = "illumos")]
    zoneid: i32,
    #[cfg(target_os = "illumos")]
    zonename: String,
    log: Logger,
    roles: HashMap<String, Role>,
    freeargs: Vec<String>,
}

impl Confomat {
    pub fn register(&mut self, provider: &RoleProvider) -> Result<()> {
        if self.roles.contains_key(provider.name) {
            bail!("duplicate role name: {}", provider.name);
        }

        let allow_instance = match provider.instance_posture {
            InstancePosture::Prohibited => false,
            InstancePosture::Required => true,
        };

        self.roles.insert(provider.name.to_string(), Role {
            name: provider.name.to_string(),
            func: provider.func,
            allow_instance,
        });

        Ok(())
    }

    pub fn apply(&mut self) -> Result<()> {
        let log = &self.log;

        for arg in self.freeargs.iter() {
            /*
             * Check for an instance name in the role selector:
             */
            let t: Vec<&str> = arg.splitn(2, ':').collect();
            let rolename = t[0].to_string();
            let instance = if t.len() == 2 {
                info!(log, "PROCESSING ROLE {} INSTANCE {}", rolename, t[1]);
                Some(t[1].to_string())
            } else {
                info!(log, "PROCESSING ROLE {}", rolename);
                None
            };

            let role = if let Some(role) = self.roles.get(&rolename) {
                role
            } else {
                bail!("invalid role \"{}\"", rolename);
            };

            if !role.allow_instance && instance.is_some() {
                bail!("role \"{}\" does not allow instances", rolename);
            }
            if role.allow_instance && instance.is_none() {
                bail!("role \"{}\" requires an instance", rolename);
            }

            let log0 = if let Some(i) = &instance {
                log.new(o!("role" => rolename,
                    "instance" => i.to_string()))
            } else {
                log.new(o!("role" => rolename))
            };

            let ctx = Context {
                confomat: self,
                log: log0,
                role,
                instance,
            };

            if let Err(e) = (role.func)(&ctx) {
                bail!("role \"{}\" failed: {}", role.name, e);
            } else {
                info!(log, "PROCESSING ROLE {} COMPLETE", role.name);
            }
        }

        info!(log, "PROCESSING COMPLETE");

        Ok(())
    }
}

impl<'a> Context<'a> {
    pub fn log(&self) -> &Logger {
        &self.log
    }

    pub fn nodename(&self) -> &str {
        &self.confomat.nodename
    }

    pub fn os(&self) -> &OS {
        &self.confomat.os
    }

    pub fn config<C>(&self) -> Result<C>
        where for<'de> C: serde::Deserialize<'de>
    {
        let mut r = self.confomat.dir.clone();
        r.push("config");
        r.push(&format!("{}.toml", self.role.name));

        match jmclib::toml::read_file(&r) {
            Ok(Some(c)) => Ok(c),
            Ok(None) => bail!("config file {} not found", r.display()),
            Err(e) => bail!("reading config {}: {}", r.display(), e),
        }
    }

    pub fn file<P: AsRef<Path>>(&self, path: P) -> Result<PathBuf> {
        match self.file_maybe(path.as_ref())?  {
            Some(r) => Ok(r),
            None => bail!("role file ({:?}, {}, {}) does not exist",
                &self.instance, &self.role.name,
                path.as_ref().display()),
        }
    }

    pub fn file_maybe<P: AsRef<Path>>(&self, path: P)
        -> Result<Option<PathBuf>>
    {
        let log = &self.log;
        let p = path.as_ref();

        if let Some(i) = &self.instance {
            /*
             * First, try an instance-specific path:
             */
            let mut r = self.confomat.dir.clone();
            r.push("files");
            r.push(&self.role.name);
            r.push("instances");
            r.push(&i);
            r.push(p);

            debug!(log, "check instance-level path: {}", r.display());

            match ensure::check(&r)? {
                Some(fi) if fi.filetype == FileType::File => return Ok(Some(r)),
                Some(fi) => bail!("path {} is a {:?}, not a file",
                    r.display(), fi.filetype),
                None => (),
            };
        }

        /*
         * Otherwise, fall back to the role-level path:
         */
        let mut r = self.confomat.dir.clone();
        r.push("files");
        r.push(&self.role.name);
        r.push(p);

        debug!(log, "check role-level path: {}", r.display());

        match ensure::check(&r)? {
            Some(fi) if fi.filetype == FileType::File => Ok(Some(r)),
            Some(fi) => bail!("path {} is a {:?}, not a file",
                r.display(), fi.filetype),
            None => Ok(None),
        }
    }

    pub fn files<P: AsRef<Path>>(&self, path: P) -> Result<Vec<PathBuf>> {
        match self.files_maybe(path.as_ref())?  {
            Some(r) => Ok(r),
            None => bail!("role files directory ({:?}, {}, {}) \
                does not exist", &self.instance, &self.role.name,
                path.as_ref().display()),
        }
    }

    pub fn files_maybe<P: AsRef<Path>>(&self, path: P)
        -> Result<Option<Vec<PathBuf>>>
    {
        let log = &self.log;
        let p = path.as_ref();

        fn enum_files(r: &Path) -> Result<Option<Vec<PathBuf>>> {
            let mut out = Vec::new();
            let mut rd = std::fs::read_dir(&r)?;
            while let Some(ent) = rd.next().transpose()? {
                let path = ent.path();

                if !ent.file_type()?.is_file() {
                    bail!("resource path {} should contain just \
                        files, but {} is of another type", r.display(),
                        path.display());
                }

                out.push(path);
            }
            Ok(Some(out))
        }

        if let Some(i) = &self.instance {
            /*
             * First, try an instance-specific path:
             */
            let mut r = self.confomat.dir.clone();
            r.push("files");
            r.push(&self.role.name);
            r.push("instances");
            r.push(i);
            r.push(p);

            debug!(log, "check instance-level path: {}", r.display());

            match ensure::check(&r)? {
                Some(fi) if fi.filetype == FileType::Directory =>
                    return enum_files(&r),
                Some(fi) => bail!("path {} is a {:?}, not a dir",
                    r.display(), fi.filetype),
                None => (),
            }
        }

        /*
         * Otherwise, fall back to the role-level path:
         */
        let mut r = self.confomat.dir.clone();
        r.push("files");
        r.push(&self.role.name);
        r.push(p);

        debug!(log, "check role-level path: {}", r.display());

        match ensure::check(&r)? {
            Some(fi) if fi.filetype == FileType::Directory => enum_files(&r),
            Some(fi) => bail!("path {} is a {:?}, not a dir",
                r.display(), fi.filetype),
            None => Ok(None),
        }
    }

    pub fn homedir(&self) -> Result<HomeDir> {
        let log = &self.log;

        /*
         * First, determine whether the automounter is online or disabled.
         */
        let autofs = match
            instance_state("svc:/system/filesystem/autofs:default")?
        {
            (SMFState::Disabled, None) => false,
            (SMFState::Online, None) => true,
            x => bail!("autofs not in stable state: {:?}", x),
        };

        if autofs {
            /*
             * Make sure the automounter is up-to-date with any changes to the
             * map files.
             */
            self.run(&["/usr/sbin/automount"])?;
        }

        /*
         * Determine whether /home is a ZFS dataset, or automounted.
         */
        let mnttab = self.read_lines("/etc/mnttab")?.expect("mnttab lines");
        let x: Vec<Vec<_>> = mnttab.iter()
            .map(|m| { m.split('\t').collect() })
            .collect();
        let homedir = if let Some(h) = x.iter().find(|x| x[1] == "/home") {
            debug!(log, "/home mnttab entry: {:?}", h);
            if h[2] == "zfs" {
                HomeDir::ZFS(h[0].to_string())
            } else if h[2] == "autofs" {
                if !autofs {
                    bail!("autofs disabled, but autofs /home detected");
                }
                HomeDir::NFS
            } else {
                bail!("unknown /home type: {:?}", h);
            }
        } else {
            /*
             * If neither a ZFS dataset nor the automounter are anchored at
             * /home, treat this is a bare directory.
             */
            HomeDir::Bare
        };
        info!(log, "home directory type: {:?}", homedir);
        Ok(homedir)
    }

    #[cfg(target_os = "illumos")]
    pub fn is_gz(&self) -> bool {
        self.confomat.zoneid == 0
    }

    #[cfg(target_os = "linux")]
    pub fn is_gz(&self) -> bool {
        true
    }

    #[cfg(target_os = "illumos")]
    pub fn data_dataset(&self) -> Result<String> {
        match self.confomat.os {
            OS::SmartOS => if self.is_gz() {
                bail!("do not know where to put data in SmartOS GZ");
            } else {
                /*
                 * Assume a delegated dataset is configured with the usual name
                 * it would get under Triton, or using the "delegate_dataset"
                 * property supported by vmadm(1M).
                 */
                Ok(format!("zones/{}/data", self.confomat.zonename))
            }
            OS::OmniOS | OS::OpenIndiana => if self.is_gz() {
                Ok("rpool/data".to_string())
            } else {
                /*
                 * XXX This is really a policy decision made for a specific set
                 * of zones on a specific set of OmniOS hosts, but it will have
                 * to do for now:
                 */
                Ok(format!("rpool/data/{}/data", self.confomat.zonename))
            }
        }
    }

    #[cfg(target_os = "linux")]
    pub fn data_dataset(&self) -> Result<String> {
        bail!("do not know where to put data on Linux");
    }

    pub fn check<P: AsRef<Path>>(&self, path: P) -> Result<Option<FileInfo>> {
        ensure::check(path)
    }

    pub fn ensure_dataset(&self, dsname: &str, opts: &[&str]) -> Result<()> {
        /*
         * XXX Assume failure here means we should try to create the dataset.
         */
        if self.run(&["/usr/sbin/zfs", "list", "-H", "-o", "name",
            &dsname]).is_ok()
        {
            info!(self.log, "dataset {} exists already", dsname);
            return Ok(());
        }

        info!(self.log, "create dataset: {}", dsname);

        let mut args: Vec<&str> = vec![
            "/usr/sbin/zfs",
            "create",
        ];
        for opt in opts.iter() {
            args.push("-o");
            args.push(opt);
        }
        args.push(dsname);

        ensure::run(&self.log, &args)?;
        Ok(())
    }

    pub fn update_packages_ips(&self) -> Result<()> {
        info!(self.log, "updating IPS publishers");
        self.run(&["/usr/bin/pkg", "refresh"])?;

        Ok(())
    }

    pub fn ensure_packages_ips(&self, names: &[&str]) -> Result<()> {
        let install: Vec<&str> = names.iter().filter(|name| {
            /*
             * The "install" command appears to fail if no update was required
             * to the image, so first check to see if the package is already
             * installed.
             */
            match self.run(&["/usr/bin/pkg", "info", "-q", name]) {
                Ok(_) => {
                    info!(self.log, "IPS package {} already installed", name);
                    false
                }
                Err(_) => {
                    info!(self.log, "IPS package {} must be installed", name);
                    true
                }
            }
        }).copied().collect();

        if install.is_empty() {
            return Ok(());
        }

        info!(self.log, "installing IPS packages: {:?}", install);
        let mut args: Vec<&str> = vec!["/usr/bin/pkg", "install"];
        for i in &install {
            args.push(i);
        }

        self.run(&args)?;
        Ok(())
    }

    pub fn update_packages(&self) -> Result<()> {
        info!(self.log, "updating pkgsrc database");
        run_pkgsrc(&self.log, &["update"])?;

        info!(self.log, "updating pkgsrc packages");
        run_pkgsrc(&self.log, &["full-upgrade"])?;

        Ok(())
    }

    pub fn ensure_packages(&self, names: &[&str]) -> Result<()> {
        let install: Vec<&str> = names.iter().filter(|name| {
            match ensure::run(&self.log,
                &["/opt/local/sbin/pkg_admin", "-q", "check", name])
            {
                Ok(_) => {
                    info!(self.log, "pkgsrc package {} already installed",
                        name);
                    false
                }
                Err(_) => {
                    info!(self.log, "pkgsrc package {} must be installed",
                        name);
                    true
                }
            }
        }).copied().collect();

        if install.is_empty() {
            return Ok(());
        }

        info!(self.log, "updating pkgsrc database");
        run_pkgsrc(&self.log, &["update"])?;

        info!(self.log, "updating pkgsrc packages");
        run_pkgsrc(&self.log, &["full-upgrade"])?;

        info!(self.log, "installing pkgsrc packages: {:?}", install);
        let mut args: Vec<&str> = vec!["install"];
        for i in &install {
            args.push(i);
        }
        run_pkgsrc(&self.log, &args)?;

        Ok(())
    }

    pub fn ensure_removed<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        ensure::removed(&self.log, path)
    }

    pub fn ensure_download<P: AsRef<Path>>(&self, url: &str, path: P,
        hash: &str, hashtype: HashType) -> Result<()>
    {
        ensure::download_file(&self.log, url, path, hash, hashtype)
    }

    pub fn ensure_dir<P: AsRef<Path>>(&self, dir: P,
        owner: &str, group: &str, perms: u32)
        -> Result<bool>
    {
        ensure::directory(&self.log, dir, owner, group, perms)
    }

    pub fn ensure_symlink<L: AsRef<Path>, T: AsRef<Path>>(&self,
        link: L, target: T, owner: &str, group: &str)
        -> Result<bool>
    {
        ensure::symlink(&self.log, link, target, owner, group)
    }

    pub fn ensure_file<S: AsRef<Path>, D: AsRef<Path>>(&self,
        src: S, dst: D, owner: &str, group: &str, perms: u32,
        create: Create)
        -> Result<bool>
    {
        ensure::file(&self.log, src, dst, owner, group, perms, create)
    }

    pub fn ensure_file_str<S: AsRef<str>, D: AsRef<Path>>(&self,
        contents: S, dst: D, owner: &str, group: &str, perms: u32,
        create: Create)
        -> Result<bool>
    {
        ensure::file_str(&self.log, contents.as_ref(), dst, owner, group,
            perms, create)
    }

    pub fn ensure_perms<P: AsRef<Path>>(&self, path: P,
        owner: &str, group: &str, perms: u32)
        -> Result<bool>
    {
        ensure::perms(&self.log, path, owner, group, perms)
    }

    pub fn run<S: AsRef<str>>(&self, args: &[S]) -> Result<()> {
        ensure::run(&self.log, args)
    }

    pub fn ensure_disabled(&self, fmri: &str) -> Result<()> {
        loop {
            match instance_state(fmri)? {
                (SMFState::Disabled, None) => {
                    info!(self.log, "smf instance {}: disabled!", fmri);
                    return Ok(());
                }
                (SMFState::Maintenance, None) => {
                    info!(self.log, "smf instance {}: in maintenance, \
                        disabling and clearing...", fmri);
                    self.run(&["/usr/sbin/svcadm", "disable", fmri])?;
                    self.run(&["/usr/sbin/svcadm", "clear", fmri])?;
                }
                (SMFState::Offline, None) => {
                    info!(self.log, "smf instance {}: offline, \
                        disabling...", fmri);
                    self.run(&["/usr/sbin/svcadm", "disable", fmri])?;
                }
                x => {
                    warn!(self.log, "smf instance {}: unexpected state {:?}",
                        fmri, x);
                }
            }

            sleep(1);
        }
    }

    pub fn ensure_online(&self, fmri: &str, need_restart: bool)
        -> Result<()>
    {
        if need_restart {
            /*
             * Restarts are posted, and merely have no effect in the event that
             * the service is disabled or in maintenance.
             */
            self.run(&["/usr/sbin/svcadm", "restart", fmri])?;
        }

        loop {
            match instance_state(fmri)? {
                (SMFState::Online, None) => {
                    info!(self.log, "smf instance {}: online!", fmri);
                    return Ok(());
                }
                (SMFState::Maintenance, None) => {
                    info!(self.log, "smf instance {}: in maintenance, \
                        clearing...", fmri);
                    self.run(&["/usr/sbin/svcadm", "clear", fmri])?;
                }
                (SMFState::Disabled, None) => {
                    info!(self.log, "smf instance {}: disabled, \
                        enabling...", fmri);
                    self.run(&["/usr/sbin/svcadm", "enable", fmri])?;
                }
                x => {
                    warn!(self.log, "smf instance {}: unexpected state {:?}",
                        fmri, x);
                }
            }

            sleep(1);
        }
    }

    pub fn exists_file<P: AsRef<Path>>(&self, path: P) -> Result<bool> {
        let p = path.as_ref();

        debug!(self.log, "exists_file({})", p.display());
        let f = match std::fs::metadata(p) {
            Ok(f) => f,
            Err(e) => match e.kind() {
                std::io::ErrorKind::NotFound => {
                    debug!(self.log, "not found!");
                    return Ok(false);
                }
                _ => bail!("checking for \"{}\": {}", p.display(), e),
            }
        };
        Ok(f.is_file())
    }

    pub fn dir_empty<P: AsRef<Path>>(&self, p: P) -> Result<bool> {
        let p = p.as_ref();
        let mut rd = std::fs::read_dir(p)?;
        if let Some(_ent) = rd.next().transpose()? {
            info!(self.log, "directory {} is NOT empty", p.display());
            return Ok(false);
        }
        info!(self.log, "directory {} IS empty", p.display());
        Ok(true)
    }

    pub fn beadm_list(&self) -> Result<Vec<BootEnvironment>> {
        let out = std::process::Command::new("/usr/sbin/beadm")
            .env_clear()
            .arg("list")
            .arg("-H")
            .output()?;
        if !out.status.success() {
            bail!("beadm list failed: {}", out.info());
        }
        let val = String::from_utf8(out.stdout)?;
        let lines: Vec<&str> = val.lines().collect();
        if lines.is_empty() {
            bail!("unexpected output: {:?}", lines);
        }

        let mut bes = Vec::new();

        for l in lines.iter() {
            let t: Vec<&str> = l.split(';').collect();

            if t.len() < 7 {
                bail!("unexpected line: {:?}", t);
            }

            let mountpoint = if t[3] == "-" {
                None
            } else {
                Some(t[3].to_string())
            };

            bes.push(BootEnvironment {
                name: t[0].to_string(),
                uuid: t[1].to_string(),
                active: t[2].to_string(),
                mountpoint,
                space: t[4].parse()?,
                policy: t[5].to_string(),
                created: t[6].parse()?,
            });
        }

        Ok(bes)
    }

    pub fn pkg_publishers(&self) -> Result<Vec<PkgPublisher>> {
        let out = std::process::Command::new("/usr/bin/pkg")
            .env_clear()
            .arg("publisher")
            .arg("-F").arg("tsv")
            .output()?;
        if !out.status.success() {
            bail!("pkg publisher failed: {}", out.info());
        }
        let val = String::from_utf8(out.stdout)?;
        let lines: Vec<&str> = val.lines().collect();
        if lines.len() < 2 {
            bail!("unexpected output: {:?}", lines);
        }

        /*
         * First, check that the header row matches our expectations:
         */
        let hdr: Vec<&str> = lines.get(0).unwrap().split('\t').collect();
        if hdr != ["PUBLISHER", "STICKY", "SYSPUB", "ENABLED", "TYPE",
            "STATUS", "URI", "PROXY"]
        {
            bail!("unexpected header: {:?}", hdr);
        }

        let mut pubs = Vec::new();

        for l in lines.iter().skip(1) {
            let t: Vec<&str> = l.split('\t').collect();

            if t.len() != hdr.len() {
                bail!("unexpected line: {:?}", t);
            }

            pubs.push(PkgPublisher {
                name: t[0].to_string(),
                sticky: t[1].parse()?,
                syspub: t[2].parse()?,
                enabled: t[3].parse()?,
                type_: t[4].to_string(),
                status: t[5].to_string(),
                uri: t[6].to_string(),
                proxy: t[7].to_string(),
            });
        }

        Ok(pubs)
    }

    pub fn read_lines<P: AsRef<Path>>(&self, path: P)
        -> Result<Option<Vec<String>>>
    {
        read_lines(path)
    }

    pub fn svcprop(&self, fmri: &str, propval: &str) -> Result<String> {
        let out = std::process::Command::new("/usr/bin/svcprop")
            .env_clear()
            .arg("-p").arg(propval)
            .arg(fmri)
            .output()?;
        if !out.status.success() {
            bail!("svcprop failed: {}", out.info());
        }
        let val = String::from_utf8(out.stdout)?;
        let lines: Vec<_> = val.lines().collect();
        if lines.len() != 1 {
            bail!("unexpected output for {}: {:?}", fmri, lines);
        }
        Ok(lines[0].trim().to_string())
    }

    pub fn ensure_cron(&self, user: &str, name: &str, script: &str)
        -> Result<()>
    {
        info!(self.log, "cron script \"{}\" for user \"{}\"", script, user);

        /*
         * Read the existing crontab for this user:
         */
        let out = std::process::Command::new("/usr/bin/crontab")
            .env_clear()
            .arg("-l").arg(user)
            .output()?;
        if !out.status.success() {
            bail!("crontab -l {} failed: {}", name, out.info());
        }
        let val = String::from_utf8(out.stdout)?;
        let lines: Vec<String> = val.lines().map(|s| s.to_string()).collect();
        let mut new_lines = lines.clone();

        info!(self.log, "orig lines: {:#?}", lines);

        /*
         * First, we want to look for and transform any legacy "Chef Name"
         * entries.
         */
        new_lines = new_lines.iter_mut().map(|l| {
            if l.starts_with("# Chef Name: ") {
                l.replace("# Chef Name: ", "# confomat: ")
            } else {
                l.to_string()
            }
        }).collect();

        /*
         * Next, look to see if there is a job with the specified name:
         */
        let mut name_at: Option<usize> = None;
        let mut script_at: Option<usize> = None;
        for (i, l) in new_lines.iter().enumerate() {
            if l.starts_with("# confomat: ") {
                if &l["# confomat: ".len()..] == name {
                    if name_at.is_none() {
                        name_at = Some(i);
                    } else {
                        bail!("line marker appears twice in crontab");
                    }
                }
            } else if l.trim() == script.trim() {
                if script_at.is_none() {
                    script_at = Some(i);
                } else {
                    bail!("script appears twice in crontab already");
                }
            }
        }

        match (name_at, script_at) {
            (Some(ni), Some(si)) => {
                if si != ni + 1 {
                    bail!("the script does not directly follow the marker?!");
                }
            }
            (None, Some(si)) => {
                /*
                 * The script exists already, but the name marker was missing.
                 * Add the marker in.
                 */
                new_lines.insert(si, format!("# confomat: {}", name));
            }
            (Some(ni), None) => {
                if ni + 1 < new_lines.len() {
                    /*
                     * The marker exists, but the script does not.  Comment out
                     * whatever is on the line directly after the marker.
                     */
                    let nl = format!("# confomat preserved: {}",
                        new_lines[ni + 1]);
                    new_lines[ni + 1] = nl;
                }

                /*
                 * Insert the script right after the marker line.
                 */
                new_lines.insert(ni + 1, script.trim().to_string());
            }
            (None, None) => {
                /*
                 * Neither the marker nor the script appear in the file.
                 * Just append.
                 */
                new_lines.push(format!("# confomat: {}", name));
                new_lines.push(script.trim().to_string());
            }
        }

        if lines == new_lines {
            info!(self.log, "no change to crontab");
            return Ok(());
        }

        info!(self.log, "installing new lines: {:#?}", new_lines);
        let mut ct = String::new();
        for l in new_lines.iter() {
            ct.push_str(l);
            ct.push('\n');
        }

        /*
         * Run crontab as the target user to install the crontab.  Note that
         * this may fail, e.g., if the syntax is not valid or the disk is full.
         *
         * We use su to run the program as the target user because there is no
         * available crontab(1) "install a whole crontab" mode that targets an
         * arbitrary user.
         */
        let mut cmd = std::process::Command::new("/usr/bin/su")
            .env_clear()
            .arg("-").arg(user)
            .arg("-c").arg("/usr/bin/crontab")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()?;

        let stdin = cmd.stdin.as_mut().expect("crontab stdin");
        let ok = if let Err(e) = stdin.write_all(ct.as_bytes()) {
            error!(self.log, "failed to write to crontab stdin: {}", e);
            false
        } else {
            true
        };

        if !ok {
            /*
             * It does not appear that dropping the child process tracking
             * object will necessarily terminate the child.  Make sure we handle
             * that ourselves:
             */
            error!(self.log, "killing crontab child");
            cmd.kill()?;
        }

        let out = cmd.wait_with_output()?;
        if !out.status.success() {
            bail!("crontab -l {} failed: {}", name, out.info());
        }

        info!(self.log, "crontab ok");
        Ok(())
    }
}

fn read_file<P: AsRef<Path>>(p: P) -> Result<Option<String>> {
    let p = p.as_ref();

    let f = match std::fs::File::open(p) {
        Ok(f) => f,
        Err(e) => {
            match e.kind() {
                std::io::ErrorKind::NotFound => return Ok(None),
                _ => bail!("open \"{}\": {}", p.display(), e),
            };
        }
    };
    let mut r = std::io::BufReader::new(f);
    let mut out = String::new();
    r.read_to_string(&mut out)?;
    Ok(Some(out))
}

fn read_lines<P: AsRef<Path>>(path: P) -> Result<Option<Vec<String>>> {
    Ok(read_file(path.as_ref())?.map(|data| {
        data.lines().map(|a| a.trim().to_string()).collect()
    }))
}

fn which_os(log: &Logger) -> Result<OS> {
    if let Some(data) = read_lines("/etc/os-release")? {
        let kv: Vec<Vec<&str>> = data.iter()
            .map(|s| s.split('=').collect())
            .collect();

        if let Some(id) = kv.iter().find(|kve| kve[0] == "ID") {
            if id[1] == "omnios" {
                return Ok(OS::OmniOS);
            }
        }

        error!(log, "unknown OS from /etc/os-release: {:?}", data);

    } else if let Some(data) = read_lines("/etc/release")? {
        if !data.is_empty() {
            if data[0].contains("SmartOS") {
                return Ok(OS::SmartOS);
            } else if data[0].contains("OpenIndiana Hipster") {
                return Ok(OS::OpenIndiana);
            }
        }
        error!(log, "unknown OS from /etc/release: {:?}", data);
    } else {
        error!(log, "could not find OS ID file");
    }

    bail!("OS detection failure");
}

fn run_pkgsrc(log: &Logger, cmd: &[&str]) -> Result<()> {
    let mut args = vec!["/opt/local/bin/pkgin", "-y"];
    for c in cmd {
        args.push(c);
    }

    ensure::run(log, &args)?;

    Ok(())
}

#[derive(Debug, PartialEq)]
pub struct BootEnvironment {
    pub name: String,
    pub uuid: String,
    pub active: String,
    pub mountpoint: Option<String>,
    pub space: u64,
    pub policy: String,
    pub created: u64,
}


#[derive(Debug, PartialEq)]
pub struct PkgPublisher {
    pub name: String,
    pub sticky: bool,
    pub syspub: bool,
    pub enabled: bool,
    pub type_: String,
    pub status: String,
    pub uri: String,
    pub proxy: String,
}

#[derive(Debug, PartialEq)]
enum SMFState {
    Disabled,
    Degraded,
    Maintenance,
    Offline,
    Online,
    Other(String),
}

impl SMFState {
    fn from_str(val: &str) -> Option<SMFState> {
        match val {
            "-" => None,
            "ON" => Some(SMFState::Online),
            "OFF" => Some(SMFState::Offline),
            "DGD" => Some(SMFState::Degraded),
            "DIS" => Some(SMFState::Disabled),
            "MNT" => Some(SMFState::Maintenance),
            s => Some(SMFState::Other(s.to_string())),
        }
    }
}

fn instance_state(fmri: &str) -> Result<(SMFState, Option<SMFState>)> {
    let out = std::process::Command::new("/usr/bin/svcs")
        .env_clear()
        .arg("-Ho").arg("sta,nsta")
        .arg(fmri)
        .output()?;
    if !out.status.success() {
        bail!("svcs failed: {}", out.info());
    }
    let val = String::from_utf8(out.stdout)?;
    let lines: Vec<_> = val.lines().collect();
    if lines.len() != 1 {
        bail!("unexpected output for {}: {:?}", fmri, lines);
    }
    let terms: Vec<&str> = lines[0].split_whitespace().collect();
    Ok((SMFState::from_str(&terms[0]).unwrap(),
        SMFState::from_str(&terms[1])))
}

/**
 * A confomat wrapper should call this entrypoint to get things rolling.  This
 * will process arguments, locate the confomat directory and read any base
 * configuration.
 *
 * The `Confomat` instance returned should be configured with any additional
 * roles that the wrapper wishes to include, and then apply() should be called.
 */
pub fn start() -> Result<Confomat> {
    let args: Vec<String> = std::env::args().collect();

    let mut opts = getopts::Options::new();

    opts.optopt("d", "", "confomat data directory", "DIRECTORY");

    let p = match opts.parse(&args[1..]) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("ERROR: usage: {}", e);
            eprintln!("       {}", opts.usage("usage"));
            exit(1);
        }
    };

    let log = init_log();

    let dir = match p.opt_str("d") {
        Some(d) => std::path::PathBuf::from(d),
        None => rootdir()?,
    };
    info!(log, "confomat starting, dir: {}", dir.display());
    let os = which_os(&log)?;

    let c = Confomat {
        log,
        dir,
        os,
        nodename: unix::nodename(),
        #[cfg(target_os = "illumos")]
        zoneid: os::zoneid(),
        #[cfg(target_os = "illumos")]
        zonename: os::zonename(),
        freeargs: p.free,
        roles: HashMap::new(),
    };

    info!(c.log, "operating system: {:?}", c.os);
    info!(c.log, "nodename: {}", c.nodename);
    #[cfg(target_os = "illumos")]
    info!(c.log, "zone ID: {}", c.zoneid);
    #[cfg(target_os = "illumos")]
    info!(c.log, "zone name: {}", c.zonename);

    Ok(c)
}
