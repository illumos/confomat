/*
 * Copyright 2020 Oxide Computer Company
 */

use super::os;
use anyhow::{bail, Result};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::process::exit;

#[derive(Debug, Clone, PartialEq)]
pub struct Passwd {
    pub name: Option<String>,
    pub passwd: Option<String>,
    pub uid: u32,
    pub gid: u32,
    #[cfg(target_os = "illumos")]
    pub age: Option<String>,
    #[cfg(target_os = "illumos")]
    pub comment: Option<String>,
    pub gecos: Option<String>,
    pub dir: Option<String>,
    pub shell: Option<String>,
}

impl Passwd {
    fn from(p: *const libc::passwd) -> Result<Passwd> {
        fn cs(lpsz: *const c_char) -> Result<Option<String>> {
            if lpsz.is_null() {
                Ok(None)
            } else {
                let cstr = unsafe { CStr::from_ptr(lpsz) };
                Ok(Some(cstr.to_str()?.to_string()))
            }
        }

        Ok(Passwd {
            name: cs(unsafe { (*p).pw_name })?,
            passwd: cs(unsafe { (*p).pw_passwd })?,
            uid: unsafe { (*p).pw_uid },
            gid: unsafe { (*p).pw_gid },
            #[cfg(target_os = "illumos")]
            age: cs(unsafe { (*p).pw_age })?,
            #[cfg(target_os = "illumos")]
            comment: cs(unsafe { (*p).pw_comment })?,
            gecos: cs(unsafe { (*p).pw_gecos })?,
            dir: cs(unsafe { (*p).pw_dir })?,
            shell: cs(unsafe { (*p).pw_shell })?,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Group {
    pub name: Option<String>,
    pub passwd: Option<String>,
    pub gid: u32,
    pub members: Option<Vec<String>>,
}

impl Group {
    fn from(g: *mut libc::group) -> Result<Group> {
        fn cs(lpsz: *const c_char) -> Result<Option<String>> {
            if lpsz.is_null() {
                Ok(None)
            } else {
                let cstr = unsafe { CStr::from_ptr(lpsz) };
                Ok(Some(cstr.to_str()?.to_string()))
            }
        }

        let mut mems = unsafe { (*g).gr_mem };
        let members: Option<Vec<String>> = if !mems.is_null() {
            let mut members = Vec::new();
            loop {
                if unsafe { *mems }.is_null() {
                    break;
                }

                members.push(cs(unsafe { *mems })?.unwrap());

                mems = unsafe { mems.offset(1) };
            }
            Some(members)
        } else {
            None
        };

        Ok(Group {
            name: cs(unsafe { (*g).gr_name })?,
            passwd: cs(unsafe { (*g).gr_passwd })?,
            gid: unsafe { (*g).gr_gid },
            members,
        })
    }
}

pub fn get_passwd_by_id(uid: u32) -> Result<Option<Passwd>> {
    os::clear_errno();
    let p = unsafe { libc::getpwuid(uid) };
    let e = os::errno();
    if p.is_null() {
        if e == 0 {
            Ok(None)
        } else {
            bail!("getpwuid: errno {}", e);
        }
    } else {
        Ok(Some(Passwd::from(p)?))
    }
}

pub fn get_passwd_by_name(name: &str) -> Result<Option<Passwd>> {
    os::clear_errno();
    let name = CString::new(name.to_owned())?;
    let p = unsafe { libc::getpwnam(name.as_ptr()) };
    let e = os::errno();
    if p.is_null() {
        if e == 0 {
            Ok(None)
        } else {
            bail!("getpwnam: errno {}", e);
        }
    } else {
        Ok(Some(Passwd::from(p)?))
    }
}

pub fn get_group_by_name(name: &str) -> Result<Option<Group>> {
    os::clear_errno();
    let name = CString::new(name.to_owned())?;
    let g = unsafe { libc::getgrnam(name.as_ptr()) };
    let e = os::errno();
    if g.is_null() {
        if e == 0 {
            Ok(None)
        } else {
            bail!("getgrnam: errno {}", e);
        }
    } else {
        Ok(Some(Group::from(g)?))
    }
}

pub fn get_group_by_id(gid: u32) -> Result<Option<Group>> {
    os::clear_errno();
    let g = unsafe { libc::getgrgid(gid) };
    let e = os::errno();
    if g.is_null() {
        if e == 0 {
            Ok(None)
        } else {
            bail!("getgrgid: errno {}", e);
        }
    } else {
        Ok(Some(Group::from(g)?))
    }
}

pub fn nodename() -> String {
    unsafe {
        let mut un: libc::utsname = std::mem::zeroed();
        if libc::uname(&mut un) < 0 {
            eprintln!("uname failure");
            exit(100);
        }
        std::ffi::CStr::from_ptr(un.nodename.as_mut_ptr())
    }
    .to_str()
    .unwrap()
    .to_string()
}
