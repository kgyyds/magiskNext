use crate::selinux::{restore_tmpcon, set_daemon_context};
use base::cstr;
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
/// 使用 write! + \n 而不是 writeln!，避免潜在 panic
fn write_log(log_file: &mut File, msg: &str) {
    // 获取时间戳，失败时用 0
    let timestamp = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(_) => 0,
    };
    
    // 使用 write! 而不是 writeln!
    let _ = write!(log_file, "[{}] {}\n", timestamp, msg);
    let _ = log_file.flush();
}

/// 检查进程是否还在运行
fn is_process_running(pid: u32) -> bool {
    Path::new(&format!("/proc/{}", pid)).exists()
}

/// 启动 daemon 并返回进程 ID
fn spawn_daemon(log_file: &mut File) -> Option<u32> {
    write_log(log_file, "spawning /data/daemon...");
    
    // 检查文件权限（忽略错误）
    if let Ok(metadata) = std::fs::metadata("/data/daemon") {
        let mode = metadata.permissions().mode();
        let size = metadata.len();
        write_log(log_file, &format!("daemon file info: mode={:o}, size={}", mode, size));
    } else {
        write_log(log_file, "WARNING: cannot stat daemon file");
    }
    
    // 使用 append 模式打开日志文件
    let daemon_log = match OpenOptions::new()
        .create(true)
        .append(true)
        .open("/data/RUNLOG.log")
    {
        Ok(f) => f,
        Err(_) => {
            // 回退到 /dev/null
            match File::open("/dev/null") {
                Ok(f) => f,
                Err(_) => return None,
            }
        }
    };
    let daemon_log_fd = daemon_log.into_raw_fd();
    
    match Command::new("/data/daemon")
        .stdout(unsafe { File::from_raw_fd(daemon_log_fd) })
        .stderr(unsafe { File::from_raw_fd(daemon_log_fd) })
        .spawn()
    {
        Ok(child) => {
            let pid = child.id();
            write_log(log_file, &format!("daemon spawned successfully, pid={}", pid));
            
            // 等待验证
            sleep(Duration::from_secs(2));
            
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
            write_log(log_file, &format!("ERROR: failed to spawn daemon - {}", error_msg));
            None
        }
    }
}

#[allow(unused_imports)]
pub fn magisk_main(_argc: i32, _argv: *mut *mut c_char) -> i32 {
    // 尝试打开日志文件（多层回退）
    let mut log_file = match OpenOptions::new()
        .create(true)
        .append(true)
        .open("/data/RUNLOG.log")
    {
        Ok(f) => f,
        Err(_) => {
            match File::create("/data/RUNLOG.log") {
                Ok(f) => f,
                Err(_) => {
                    // 完全失败，无法继续
                    return 1;
                }
            }
        }
    };
    
    let _ = write!(log_file, "[0] === magisk started ===\n");
    let _ = log_file.flush();
    
    // 1. 设置 /debug_ramdisk SELinux 上下文（忽略错误）
    let _ = restore_tmpcon();
    let _ = write!(log_file, "[0] restore_tmpcon done\n");
    let _ = log_file.flush();
    
    // 2. 设置 /data/daemon 为 system_file（忽略错误）
    let _ = set_daemon_context();
    let _ = write!(log_file, "[0] set_daemon_context done\n");
    let _ = log_file.flush();
    
    // 3. 延迟 20 秒
    let _ = write!(log_file, "[0] waiting 20 seconds...\n");
    let _ = log_file.flush();
    sleep(Duration::from_secs(20));
    
    // 4. 检查 /data/daemon 是否存在
    if !Path::new("/data/daemon").exists() {
        let _ = write!(log_file, "[0] ERROR: /data/daemon does not exist!\n");
        let _ = log_file.flush();
        return 1;
    }
    
    let _ = write!(log_file, "[0] /data/daemon found\n");
    let _ = log_file.flush();
    let _ = write!(log_file, "[0] === entering watchdog loop ===\n");
    let _ = log_file.flush();
    
    // 首次启动 daemon
    let mut daemon_pid: Option<u32> = spawn_daemon(&mut log_file);
    
    // 守护循环：每 5 秒检查一次
    let mut check_count: u32 = 0;
    loop {
        sleep(Duration::from_secs(5));
        
        check_count += 1;
        
        // 检查 daemon 进程
        let running = match daemon_pid {
            Some(pid) => is_process_running(pid),
            None => false,
        };
        
        if running {
            // daemon 正常运行，简单记录
            let _ = write!(log_file, "[{}] daemon pid={:?} running\n", check_count, daemon_pid);
        } else {
            // daemon 未运行，需要重启
            let _ = write!(log_file, "[{}] daemon NOT running, restarting...\n", check_count);
            daemon_pid = spawn_daemon(&mut log_file);
            
            if daemon_pid.is_some() {
                let _ = write!(log_file, "[{}] restart OK\n", check_count);
            } else {
                let _ = write!(log_file, "[{}] restart FAILED\n", check_count);
            }
        }
        
        // 每次检查后 flush
        let _ = log_file.flush();
    }
}
