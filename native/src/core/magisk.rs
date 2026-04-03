use crate::selinux::{restore_tmpcon, set_daemon_context};
use base::cstr;
use std::ffi::{CStr, c_char};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::fd::{FromRawFd, IntoRawFd};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, exit};
use std::thread::sleep;
use std::time::Duration;

/// 写入日志到 /data/RUNLOG.log
fn write_log(log_file: &mut File, msg: &str) {
    let timestamp = match std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
    {
        Ok(d) => d.as_secs(),
        Err(_) => 0,
    };
    let _ = write!(log_file, "[{}] {}\n", timestamp, msg);
    let _ = log_file.flush();
}

/// 解析命令行参数
fn parse_args(argc: i32, argv: *mut *mut c_char) -> String {
    if argc >= 2 {
        unsafe {
            let arg = *argv.offset(1);
            if !arg.is_null() {
                return CStr::from_ptr(arg)
                    .to_str()
                    .unwrap_or("")
                    .to_string();
            }
        }
    }
    String::new()
}

/// 设置 SELinux 上下文
fn setup_context() {
    let _ = restore_tmpcon();
    let _ = set_daemon_context();
}

/// 检查进程是否还在运行
fn is_process_running(pid: u32) -> bool {
    Path::new(&format!("/proc/{}", pid)).exists()
}

/// 启动 daemon 并返回进程 ID
fn spawn_daemon(log_file: &mut File) -> Option<u32> {
    write_log(log_file, "spawning /data/daemon...");

    if let Ok(metadata) = std::fs::metadata("/data/daemon") {
        write_log(log_file, &format!(
            "daemon file info: mode={:o}, size={}",
            metadata.permissions().mode(),
            metadata.len()
        ));
    }

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
            write_log(log_file, &format!("daemon spawned, pid={}", pid));

            sleep(Duration::from_secs(2));

            if is_process_running(pid) {
                write_log(log_file, "daemon verified");
                Some(pid)
            } else {
                write_log(log_file, "WARNING: exited immediately");
                None
            }
        }
        Err(e) => {
            write_log(log_file, &format!("ERROR: spawn failed - {}", e));
            None
        }
    }
}

/// 守护 daemon 进程（无限循环）
fn daemon_watchdog() {
    let mut log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("/data/RUNLOG.log")
        .unwrap_or_else(|_| File::open("/dev/null").unwrap());

    write_log(&mut log_file, "=== watchdog started ===");

    if !Path::new("/data/daemon").exists() {
        write_log(&mut log_file, "ERROR: /data/daemon not found");
        return;
    }

    let mut daemon_pid: Option<u32> = spawn_daemon(&mut log_file);
    let mut count: u32 = 0;

    loop {
        sleep(Duration::from_secs(5));
        count += 1;

        let running = match daemon_pid {
            Some(pid) => is_process_running(pid),
            None => false,
        };

        if running {
            write_log(&mut log_file, &format!("[{}] running", count));
        } else {
            write_log(&mut log_file, &format!("[{}] NOT running, restart", count));
            daemon_pid = spawn_daemon(&mut log_file);
            if daemon_pid.is_some() {
                write_log(&mut log_file, &format!("[{}] restart OK", count));
            } else {
                write_log(&mut log_file, &format!("[{}] restart FAILED", count));
            }
        }

        let _ = log_file.flush();
    }
}

/// fork 并后台运行 watchdog
fn fork_and_watchdog() -> i32 {
    unsafe {
        let pid = libc::fork();

        if pid < 0 {
            // fork 失败
            return 1;
        }

        if pid > 0 {
            // 父进程：立即退出（init RC 不会等待）
            return 0;
        }

        // 子进程：继续执行

        // 创建新会话，脱离控制终端
        libc::setsid();

        // 关闭标准输入输出，重定向到 /dev/null
        let devnull = libc::open(b"/dev/null\0".as_ptr() as *const _, libc::O_RDONLY);
        if devnull >= 0 {
            libc::dup2(devnull, libc::STDIN_FILENO);
            libc::dup2(devnull, libc::STDOUT_FILENO);
            libc::dup2(devnull, libc::STDERR_FILENO);
            if devnull > 2 {
                libc::close(devnull);
            }
        }

        // 运行 watchdog
        daemon_watchdog();

        // 不应该到达这里
        exit(0);
    }
}

#[allow(unused_imports)]
pub fn magisk_main(argc: i32, argv: *mut *mut c_char) -> i32 {
    let arg = parse_args(argc, argv);

    match arg.as_str() {
        // 设置上下文后立即退出
        "--post-fs-data" | "--service" => {
            setup_context();
            0
        }
        // fork 并后台守护 daemon
        "--dae" => {
            fork_and_watchdog()
        }
        // 未知参数：设置上下文 + 守护（默认行为）
        _ => {
            setup_context();
            fork_and_watchdog()
        }
    }
}
