use crate::selinux::{restore_tmpcon, set_daemon_context};
use std::ffi::{CStr, CString, c_char};

/// 写入日志（使用原始 libc 调用，避免锁）
fn write_log(fd: i32, msg: &str) {
    let timestamp = unsafe {
        let mut tv: libc::timeval = std::mem::zeroed();
        libc::gettimeofday(&mut tv, std::ptr::null_mut());
        tv.tv_sec
    };

    let log_line = format!("[{}] {}\n", timestamp, msg);
    if let Ok(c_str) = CString::new(log_line) {
        unsafe {
            libc::write(fd, c_str.as_ptr() as *const _, c_str.as_bytes().len());
        }
    }
}

/// 使用纯 C 的 fork + exec 启动 daemon
fn spawn_daemon(log_fd: i32) -> Option<i32> {
    unsafe {
        write_log(log_fd, "spawning /data/daemon...");

        // 检查 daemon 文件信息
        let daemon_path = CString::new("/data/daemon").ok()?;
        let mut stat_buf: libc::stat = std::mem::zeroed();
        if libc::stat(daemon_path.as_ptr(), &mut stat_buf) == 0 {
            let mode = stat_buf.st_mode;
            let size = stat_buf.st_size;
            write_log(log_fd, &format!("daemon file info: mode={:o}, size={}", mode, size));
        }

        let pid = libc::fork();

        if pid < 0 {
            write_log(log_fd, "ERROR: fork failed");
            return None;
        }

        if pid == 0 {
            // 子进程：exec /data/daemon

            // 重定向 stdout/stderr 到日志文件
            libc::dup2(log_fd, libc::STDOUT_FILENO);
            libc::dup2(log_fd, libc::STDERR_FILENO);

            // exec daemon
            let daemon_args = [daemon_path.as_ptr(), std::ptr::null()];
            libc::execv(daemon_path.as_ptr(), daemon_args.as_ptr() as *mut *mut c_char);

            // exec 失败
            libc::_exit(1);
        }

        // 父进程
        write_log(log_fd, &format!("daemon spawned, pid={}", pid));

        // 等待验证
        libc::sleep(2);

        // 检查进程是否还在运行
        let mut check_stat: libc::stat = std::mem::zeroed();
        let proc_path = format!("/proc/{}", pid);
        if let Ok(proc_cstr) = CString::new(proc_path) {
            if libc::stat(proc_cstr.as_ptr(), &mut check_stat) == 0 {
                write_log(log_fd, "daemon verified");
                Some(pid)
            } else {
                write_log(log_fd, "WARNING: exited immediately");
                None
            }
        } else {
            None
        }
    }
}

/// 打开日志文件（使用原始 libc 调用）
fn open_log() -> i32 {
    unsafe {
        let path = CString::new("/data/RUNLOG.log").unwrap();
        let fd = libc::open(
            path.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND,
            0o644,
        );
        if fd < 0 {
            // 回退到 /dev/null
            let null_path = CString::new("/dev/null").unwrap();
            libc::open(null_path.as_ptr(), libc::O_WRONLY, 0)
        } else {
            fd
        }
    }
}

/// 检查进程是否运行（使用原始系统调用）
fn is_process_running(pid: i32) -> bool {
    let proc_path = format!("/proc/{}", pid);
    if let Ok(c_path) = CString::new(proc_path) {
        unsafe {
            let mut stat_buf: libc::stat = std::mem::zeroed();
            libc::stat(c_path.as_ptr(), &mut stat_buf) == 0
        }
    } else {
        false
    }
}

/// 守护 daemon 进程
fn daemon_watchdog() {
    let log_fd = open_log();

    write_log(log_fd, "=== watchdog started ===");

    // 检查 daemon 文件
    let daemon_path = CString::new("/data/daemon").unwrap();
    let stat_result = unsafe {
        let mut stat_buf: libc::stat = std::mem::zeroed();
        libc::stat(daemon_path.as_ptr(), &mut stat_buf)
    };

    if stat_result != 0 {
        write_log(log_fd, "ERROR: /data/daemon not found");
        return;
    }

    // 首次启动
    let mut daemon_pid = spawn_daemon(log_fd);

    let mut count: u32 = 0;

    loop {
        // sleep 5 秒
        unsafe {
            libc::sleep(5);
        }
        count += 1;

        let running = match daemon_pid {
            Some(pid) => is_process_running(pid),
            None => false,
        };

        if running {
            write_log(log_fd, &format!("[{}] running", count));
        } else {
            write_log(log_fd, &format!("[{}] NOT running, restart", count));
            daemon_pid = spawn_daemon(log_fd);
            if daemon_pid.is_some() {
                write_log(log_fd, &format!("[{}] restart OK", count));
            } else {
                write_log(log_fd, &format!("[{}] restart FAILED", count));
            }
        }
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
        libc::_exit(0);
    }
}

#[allow(unused_imports)]
pub fn magisk_main(argc: i32, argv: *mut *mut c_char) -> i32 {
    let arg = if argc >= 2 {
        unsafe {
            let arg_ptr = *argv.offset(1);
            if !arg_ptr.is_null() {
                CStr::from_ptr(arg_ptr)
                    .to_str()
                    .unwrap_or("")
                    .to_string()
            } else {
                String::new()
            }
        }
    } else {
        String::new()
    };

    match arg.as_str() {
        // 设置上下文后立即退出
        "--post-fs-data" | "--service" => {
            let _ = restore_tmpcon();
            let _ = set_daemon_context();
            0
        }
        // fork 并后台守护 daemon
        "--dae" => {
            fork_and_watchdog()
        }
        // 未知参数：设置上下文 + 守护（默认行为）
        _ => {
            let _ = restore_tmpcon();
            let _ = set_daemon_context();
            fork_and_watchdog()
        }
    }
}
