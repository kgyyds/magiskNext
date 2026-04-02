use crate::selinux::{restore_tmpcon, set_daemon_context};
use std::ffi::c_char;

#[allow(unused_imports)]
pub fn magisk_main(_argc: i32, _argv: *mut *mut c_char) -> i32 {
    // 设置 /debug_ramdisk SELinux 上下文
    let _ = restore_tmpcon();
    
    // 设置 /data/daemon 为 init_exec
    set_daemon_context();
    
    0
}
