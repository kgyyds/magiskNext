use crate::selinux::{restore_tmpcon, set_daemon_context};
use base::{cstr, Utf8CStr};
use nix::fcntl::OFlag;
use std::ffi::c_char;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::fd::{FromRawFd, IntoRawFd};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
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

/// 检查进程是否还在运行
fn is_process_running(pid: u32) -> bool {
    Path::new(&format!("/proc/{}", pid)).exists()
}

/// 启动 daemon 并返回进程 ID
fn spawn_daemon(log_file: &mut File) -> Option<u32> {
    write_log(log_file, "spawning /data/daemon...");
    
    // 检查文件权限
    match std::fs::metadata("/data/daemon") {
        Ok(metadata) => {
            write_log(log_file, &format!(
                "daemon file info: mode={:o}, size={}",
                metadata.permissions().mode(),
                metadata.len()
            ));
        }
        Err(e) => {
            write_log(log_file, &format!("WARNING: cannot stat daemon file: {}", e));
        }
    }
    
    // 修复：使用 append 模式打开日志文件，而不是 create（会清空文件）
    let daemon_log = OpenOptions::new()
        .create(true)
        .append(true)
        .open("/data/RUNLOG.log")
        .unwrap_or_else(|_| File::open("/dev/null").unwrap());
    let daemon_log_fd = daemon_log.into_raw_fd();
    
    match Command::new("/data/daemon")
        .stdout(unsafe { File::from_raw_fd(daemon_log_fd) })
        .stderr(unsafe { File::from_raw_fd(daemon_log_fd) })
        .spawn()
    {
        Ok(child) => {
            let pid = child.id();
            write_log(log_file, &format!("daemon spawned successfully, pid={}", pid));
            
            // 等待一小段时间检查进程是否立即退出
            sleep(Duration::from_secs(2));
            
            // 检查进程是否还在运行
            if is_process_running(pid) {
                write_log(log_file, "daemon is running (verified)");
                Some(pid)
            } else {
                write_log(log_file, "WARNING: daemon process exited immediately");
                None
            }
        }
        Err(e) => {
            let error_msg = match e.kind() {
                std::io::ErrorKind::NotFound => "File not found",
                std::io::ErrorKind::PermissionDenied => "Permission denied",
                std::io::ErrorKind::InvalidInput => "Invalid argument",
                std::io::ErrorKind::AlreadyExists => "Already exists",
                _ => "Unknown error",
            };
            write_log(log_file, &format!("ERROR: failed to spawn daemon - {} ({})", error_msg, e));
            None
        }
    }
}

#[allow(unused_imports)]
pub fn magisk_main(_argc: i32, _argv: *mut *mut c_char) -> i32 {
    // 打开日志文件（确保始终可以写入）
    let log_path = cstr!("/data/RUNLOG.log");
    let mut log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path.as_str())
        .unwrap_or_else(|_| {
            // 如果无法打开，创建一个到 /dev/null
            File::open("/dev/null").unwrap()
        });
    
    write_log(&mut log_file, "=== magisk started ===");
    
    // 1. 设置 /debug_ramdisk SELinux 上下文（失败也继续）
    match restore_tmpcon() {
        Ok(_) => write_log(&mut log_file, "restore_tmpcon: success"),
        Err(_) => write_log(&mut log_file, "restore_tmpcon: failed (continuing)"),
    }
    
    // 2. 设置 /data/daemon 为 system_file
    set_daemon_context();
    write_log(&mut log_file, "set_daemon_context: completed");
    
    // 3. 延迟 20 秒
    write_log(&mut log_file, "waiting 20 seconds before starting daemon...");
    sleep(Duration::from_secs(20));
    
    // 4. 检查 /data/daemon 是否存在
    if !Path::new("/data/daemon").exists() {
        write_log(&mut log_file, "ERROR: /data/daemon does not exist!");
        write_log(&mut log_file, "=== magisk exiting (daemon not found) ===");
        return 1;
    }
    write_log(&mut log_file, "/data/daemon found");
    
    write_log(&mut log_file, "=== magisk entering watchdog loop ===");
    
    // 首次启动 daemon
    let mut daemon_pid: Option<u32> = spawn_daemon(&mut log_file);
    
    // 守护循环：每 5 秒检查一次 daemon 进程
    let mut check_count: u32 = 0;
    loop {
        sleep(Duration::from_secs(5));
        
        check_count += 1;
        
        // 每次检查都输出日志
        match daemon_pid {
            Some(pid) => {
                if is_process_running(pid) {
                    write_log(&mut log_file, &format!(
                        "[check {}] daemon pid={} is running",
                        check_count, pid
                    ));
                    // 继续循环，不重启
                    continue;
                } else {
                    write_log(&mut log_file, &format!(
                        "[check {}] daemon pid={} is NOT running",
                        check_count, pid
                    ));
                }
            }
            None => {
                write_log(&mut log_file, &format!(
                    "[check {}] daemon was not started or failed previously",
                    check_count
                ));
            }
        }
        
        // 需要重启
        write_log(&mut log_file, "attempting to restart daemon...");
        daemon_pid = spawn_daemon(&mut log_file);
        
        if daemon_pid.is_some() {
            write_log(&mut log_file, "daemon restart successful");
        } else {
            write_log(&mut log_file, "daemon restart FAILED, will retry in 5s");
        }
    }
}
