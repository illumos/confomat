/*
 * Copyright 2020 Oxide Computer Company
 */

use std::os::raw::{c_char, c_int};
use std::process::exit;
use std::ffi::{CString, CStr};
use std::collections::HashMap;
use anyhow::Result;

pub fn errno() -> i32 {
    unsafe {
        let enp = libc::___errno();
        *enp
    }
}

pub fn clear_errno() {
    unsafe {
        let enp = libc::___errno();
        *enp = 0;
    }
}

#[derive(Debug, PartialEq)]
pub struct UserAttr {
    pub name: String,
    pub attr: HashMap<String, String>,
}

impl UserAttr {
    pub fn profiles(&self) -> Vec<String> {
        if let Some(p) = self.attr.get("profiles") {
            p.split(',')
                .map(|s| s.trim().to_string())
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        }
    }
}

#[repr(C)]
struct Kv {
    key: *const c_char,
    value: *const c_char,
}

impl Kv {
    fn name(&self) -> &CStr {
        unsafe { CStr::from_ptr(self.key) }
    }

    fn value(&self) -> &CStr {
        unsafe { CStr::from_ptr(self.value) }
    }
}

#[repr(C)]
struct Kva {
    length: c_int,
    data: *const Kv,
}

impl Kva {
    fn values(&self) -> &[Kv] {
        unsafe { std::slice::from_raw_parts(self.data, self.length as usize) }
    }
}

#[repr(C)]
struct UserAttrRaw {
    name: *mut c_char,
    qualifier: *mut c_char,
    res1: *mut c_char,
    res2: *mut c_char,
    attr: *mut Kva,
}

#[link(name = "secdb")]
extern {
    fn getusernam(buf: *const c_char) -> *mut UserAttrRaw;
    fn free_userattr(userattr: *mut UserAttrRaw);
}

pub fn get_user_attr_by_name(name: &str) -> Result<Option<UserAttr>> {
    let mut out = UserAttr {
        name: name.to_string(),
        attr: HashMap::new(),
    };

    let name = CString::new(name.to_owned())?;
    let ua = unsafe { getusernam(name.as_ptr()) };
    if ua.is_null() {
        return Ok(None);
    }

    for kv in unsafe { (*(*ua).attr).values() } {
        if let (Ok(k), Ok(v)) = (kv.name().to_str(), kv.value().to_str()) {
            out.attr.insert(k.to_string(), v.to_string());
        } else {
            continue;
        }
    }

    unsafe { free_userattr(ua) };

    Ok(Some(out))
}

#[link(name = "c")]
extern {
    fn getzoneid() -> i32;
    fn getzonenamebyid(id: i32, buf: *mut u8, buflen: usize) -> isize;
}

pub fn zoneid() -> i32 {
    unsafe { getzoneid() }
}

pub fn zonename() -> String {
    let buf = unsafe {
        let mut buf: [u8; 64] = std::mem::zeroed(); /* ZONENAME_MAX */

        let sz = getzonenamebyid(getzoneid(), buf.as_mut_ptr(), 64);
        if sz > 64 || sz < 0 {
            eprintln!("getzonenamebyid failure");
            exit(100);
        }

        Vec::from(&buf[0..sz as usize])
    };
    std::ffi::CStr::from_bytes_with_nul(&buf)
        .unwrap().to_str().unwrap().to_string()
}
