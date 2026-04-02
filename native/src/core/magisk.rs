use crate::selinux::{restore_tmpcon, set_daemon_context};
use base::{cstr, Utf8CStr};
use nix::fcntl::OFlag;
use std::ffi::c_char;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::fd::FromRawFd;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::thread::sleep;
use std::time::Duration;

/// 写入日志到 /data/RUNLOG.log
fn write_log(log_file: &mut File, msg: &str) {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let _ = writeln!(log_file, "[{}] {}", timestamp, msg);
    let _ = log_file.flush();
}

#[allow(unused_imports)]
pub fn magisk_main(_argc: i32, _argv: *mut *mut c_char) -> i32 {
    // 打开日志文件
    let log_path = cstr!("/data/RUNLOG.log");
    let mut log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path.as_str())
        .unwrap_or_else(|_| File::create("/data/RUNLOG.log").unwrap());
    
    write_log(&mut log_file, "=== magisk started ===");
    
    // 1. 设置 /debug_ramdisk SELinux 上下文
    match restore_tmpcon() {
        Ok(_) => write_log(&mut log_file, "restore_tmpcon: success"),
        Err(e) => write_log(&mut log_file, &format!("restore_tmpcon: failed - {:?}", e)),
    }
    
    // 2. 设置 /data/daemon 为 system_file
    set_daemon_context();
    write_log(&mut log_file, "set_daemon_context: completed");
    
    // 3. 延迟 20 秒
    write_log(&mut log_file, "waiting 20 seconds before starting daemon...");
    sleep(Duration::from_secs(20));
    
    // 4. 检查 /data/daemon 是否存在
    let daemon_path = cstr!("/data/daemon");
    if !daemon_path.exists() {
        write_log(&mut log_file, "ERROR: /data/daemon does not exist!");
        write_log(&mut log_file, "=== magisk exiting (daemon not found) ===");
        return 1;
    }
    write_log(&mut log_file, "/data/daemon found, attempting to start...");
    
    // 5. 检查文件权限
    match std::fs::metadata(daemon_path.as_str()) {
        Ok(metadata) => {
            write_log(&mut log_file, &format!(
                "daemon file info: mode={:o}, size={}",
                metadata.permissions().mode(),
                metadata.len()
            ));
        }
        Err(e) => {
            write_log(&mut log_file, &format!("WARNING: cannot stat daemon file - {:?}", e));
        }
    }
    
    // 6. 启动 /data/daemon
    write_log(&mut log_file, "spawning /data/daemon...");
    
    // 创建日志文件用于 daemon 输出
    let daemon_log = File::create("/data/RUNLOG.log")
        .unwrap_or_else(|_| File::open("/dev/null").unwrap());
    let daemon_log_fd = daemon_log.into_raw_fd();
    
    match Command::new("/data/daemon")
        .stdout(unsafe { File::from_raw_fd(daemon_log_fd) })
        .stderr(unsafe { File::from_raw_fd(daemon_log_fd) })
        .spawn()
    {
        Ok(child) => {
            write_log(&mut log_file, &format!("daemon spawned successfully, pid={:?}", child.id()));
            
            // 等待一小段时间检查进程是否立即退出
            sleep(Duration::from_secs(2));
            
            // 尝试检查进程是否还在运行
            let ps_check = Command::new("sh")
                .arg("-c")
                .arg(format!("ps | grep -v grep | grep -q '{}'", child.id()))
                .status();
            
            match ps_check {
                Ok(exit_status) if exit_status.success() => {
                    write_log(&mut log_file, "daemon is running (verified by ps)");
                }
                Ok(_) => {
                    write_log(&mut log_file, "WARNING: daemon process may have exited");
                }
                Err(e) => {
                    write_log(&mut log_file, &format!("WARNING: cannot verify daemon status - {:?}", e));
                }
            }
        }
        Err(e) => {
            // 详细记录启动失败原因
            let error_msg = match e.kind() {
                std::io::ErrorKind::NotFound => "File not found",
                std::io::ErrorKind::PermissionDenied => "Permission denied (check SELinux context and file permissions)",
                std::io::ErrorKind::InvalidInput => "Invalid argument",
                std::io::ErrorKind::AlreadyExists => "Already exists",
                _ => "Unknown error",
            };
            write_log(&mut log_file, &format!("ERROR: failed to spawn daemon - {} ({:?})", error_msg, e));
            
            // 尝试获取更多信息
            if let Ok(metadata) = std::fs::metadata("/data/daemon") {
                let mode = metadata.permissions().mode();
                write_log(&mut log_file, &format!("daemon file mode: {:o}", mode));
                
                if mode & 0o111 == 0 {
                    write_log(&mut log_file, "WARNING: daemon file is not executable!");
                }
            }
        }
    }
    
    write_log(&mut log_file, "=== magisk entering main loop ===");
    
    // 7. 持续运行（无限循环）
    loop {
        sleep(Duration::from_secs(3600)); // 每小时唤醒一次，减少 CPU 占用
        write_log(&mut log_file, "magisk main loop heartbeat");
    }
}
