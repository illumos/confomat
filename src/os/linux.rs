pub fn errno() -> i32 {
    unsafe {
        let enp = libc::__errno_location();
        *enp
    }
}

pub fn clear_errno() {
    unsafe {
        let enp = libc::__errno_location();
        *enp = 0;
    }
}
