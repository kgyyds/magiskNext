use crate::selinux::restore_tmpcon;
use std::ffi::c_char;

#[allow(unused_imports)]
pub fn magisk_main(_argc: i32, _argv: *mut *mut c_char) -> i32 {
    // 设置 /debug_ramdisk SELinux 上下文
    match restore_tmpcon() {
        Ok(_) => 0,
        Err(_) => 1
    }
}
