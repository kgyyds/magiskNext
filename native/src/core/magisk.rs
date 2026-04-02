use crate::selinux::restore_tmpcon;
use std::ffi::c_char;

pub fn magisk_main(argc: i32, argv: *mut *mut c_char) -> i32 {
    // 设置 /debug_ramdisk SELinux 上下文
    match restore_tmpcon() {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("Failed to restore /debug_ramdisk context: {e}");
            1
        }
    }
}
