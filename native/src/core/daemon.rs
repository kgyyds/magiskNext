use crate::consts::{
    MAGISK_FILE_CON, MAGISK_FULL_VER, MAGISK_PROC_CON, MAGISK_VER_CODE, MAGISK_VERSION,
    MAIN_CONFIG, MAIN_SOCKET, ROOTMNT, ROOTOVL,
};
use crate::logging::{android_logging, magisk_logging, setup_logfile, start_log_daemon};
use crate::resetprop::{get_prop, set_prop};
use crate::selinux::restore_tmpcon;
use crate::ffi::{RequestCode, RespondCode, get_magisk_tmp};

use base::const_format::concatcp;
use base::{
    BufReadExt, FsPathBuilder, LoggedResult, ResultExt, Utf8CStr,
    WriteExt, cstr, fork_dont_care, info, libc, log_err, set_nice_name,
};

use nix::fcntl::OFlag;
use nix::mount::MsFlags;
use nix::sys::signal::SigSet;
use nix::unistd::{dup2_stderr, dup2_stdin, dup2_stdout, getpid, getuid, setsid};

use num_traits::AsPrimitive;
use std::fmt::Write as _;
use std::fs::OpenOptions;
use std::io::{BufReader, Write};
use std::os::fd::{AsFd, AsRawFd, IntoRawFd, RawFd};
use std::os::unix::net::{UCred, UnixListener, UnixStream};
use std::process::{Command, Stdio, exit};
use std::sync::OnceLock;
use std::time::Duration;

// 只跑一次（你要一直 curl 就不用它；要只跑一次就用）
static RUN_ONCE: OnceLock<()> = OnceLock::new();

fn kmsg(tag: &str) {
    if let Ok(mut f) = OpenOptions::new().write(true).open("/dev/kmsg") {
        let _ = writeln!(f, "<6>[curlcute] {}", tag);
    }
}

fn append_testlog(line: &str) {
    if let Ok(mut f) = OpenOptions::new()
        .create(true)
        .append(true)
        .open("/data/test.txt")
    {
        let _ = writeln!(f, "{}", line);
    }
}

fn append_testlog_bytes(prefix: &str, bytes: &[u8], max: usize) {
    if let Ok(mut f) = OpenOptions::new()
        .create(true)
        .append(true)
        .open("/data/test.txt")
    {
        let n = bytes.len().min(max);
        let _ = writeln!(f, "{} (len={}, show={})", prefix, bytes.len(), n);
        let _ = f.write_all(&bytes[..n]);
        let _ = writeln!(f, "\n");
    }
}

// cgroup 逃逸（保命）
fn switch_cgroup(cgroup: &str, pid: i32) {
    let mut buf = cstr::buf::new::<64>()
        .join_path(cgroup)
        .join_path("cgroup.procs");
    if !buf.exists() {
        return;
    }
    if let Ok(mut file) = buf.open(OFlag::O_WRONLY | OFlag::O_APPEND | OFlag::O_CLOEXEC) {
        buf.clear();
        write!(buf, "{pid}").ok();
        file.write_all(buf.as_bytes()).log_ok();
    }
}

fn curl_once_and_log() {
    // 优先 curl，其次 toybox wget
    let mut cmd: Option<Command> = None;

    if cstr!("/system/bin/curl").exists() {
        let mut c = Command::new("/system/bin/curl");
        c.args([
            "-L",
            "--connect-timeout", "3",
            "--max-time", "6",
            "https://baidu.com",
        ]);
        cmd = Some(c);
    } else if cstr!("/system/bin/toybox").exists() {
        let mut c = Command::new("/system/bin/toybox");
        c.args(["wget", "-T", "6", "-qO-", "https://baidu.com"]);
        cmd = Some(c);
    }

    let Some(mut c) = cmd else {
        kmsg("no /system/bin/curl and no toybox wget");
        append_testlog("no /system/bin/curl and no toybox wget");
        return;
    };

    c.stdin(Stdio::null())
        .stderr(Stdio::null())
        .stdout(Stdio::piped());

    let out = match c.output() {
        Ok(o) => o,
        Err(e) => {
            let s = format!("curlcute: spawn failed: {e}");
            kmsg(&s);
            append_testlog(&s);
            return;
        }
    };

    let code = out.status.code().unwrap_or(-1);
    let head = format!("---- curl tick: code={code}");
    kmsg(&head);
    append_testlog(&head);

    // 只记 512 字节，防止 /data/test.txt 爆炸
    append_testlog_bytes("body", &out.stdout, 512);
}

fn spawn_curl_worker_keepalive() {
    std::thread::spawn(|| {
        kmsg("curl_worker start");
        append_testlog("curl_worker start");

        // 等 boot_completed=1 再开始，更稳
        loop {
            if get_prop(cstr!("sys.boot_completed")) == "1" {
                kmsg("boot_completed=1, start curl loop");
                append_testlog("boot_completed=1, start curl loop");
                break;
            }
            std::thread::sleep(Duration::from_millis(500));
        }

        // ✅ 常驻：每 30s 跑一次
        loop {
            curl_once_and_log();
            std::thread::sleep(Duration::from_secs(30));
        }

        // ✅ 只跑一次版本（想要就把上面的 loop 注释掉，打开这里）
        // if RUN_ONCE.set(()).is_ok() {
        //     curl_once_and_log();
        // }
    });
}

fn handle_request_sync(mut client: UnixStream, code: RequestCode) {
    match code {
        RequestCode::CHECK_VERSION => {
            #[cfg(debug_assertions)]
            let s = concatcp!(MAGISK_VERSION, ":MAGISK:D");
            #[cfg(not(debug_assertions))]
            let s = concatcp!(MAGISK_VERSION, ":MAGISK:R");
            client.write_encodable(s).log_ok();
        }
        RequestCode::CHECK_VERSION_CODE => {
            client.write_pod(&MAGISK_VER_CODE).log_ok();
        }
        RequestCode::START_DAEMON => {
            setup_logfile();
        }
        RequestCode::STOP_DAEMON => {
            client.write_pod(&0).log_ok();
            exit(0);
        }
        _ => {
            // 其他请求全部忽略（你说不需要对外处理能力）
        }
    }
}

fn handle_requests(mut client: UnixStream) {
    let Ok(cred) = client.peer_cred() else {
        return;
    };

    // 读取对端 SELinux context
    let mut context = cstr::buf::new::<256>();
    unsafe {
        let mut len: libc::socklen_t = context.capacity().as_();
        libc::getsockopt(
            client.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERSEC,
            context.as_mut_ptr().cast(),
            &mut len,
        );
    }
    context.rebuild().ok();

    let is_root = cred.uid == 0;
    let is_shell = cred.uid == 2000;
    let is_zygote = &context == "u:r:zygote:s0";

    // 最小放行：root/shell/zygote 都允许连
    if !is_root && !is_shell && !is_zygote {
        client.write_pod(&RespondCode::ACCESS_DENIED.repr).log_ok();
        return;
    }

    let mut code = -1;
    client.read_pod(&mut code).ok();

    if !(0..RequestCode::END.repr).contains(&code) {
        return;
    }

    // 拒绝 barrier 类（保持你原逻辑）
    if code == RequestCode::_SYNC_BARRIER_.repr || code == RequestCode::_STAGE_BARRIER_.repr {
        return;
    }

    let code = RequestCode { repr: code };

    // 你要“足够权限”，那就更硬一点：除 CHECK_* 外都要求 root
    match code {
        RequestCode::CHECK_VERSION | RequestCode::CHECK_VERSION_CODE => {}
        _ => {
            if !is_root {
                client.write_pod(&RespondCode::ROOT_REQUIRED.repr).log_ok();
                return;
            }
        }
    }

    if client.write_pod(&RespondCode::OK.repr).is_err() {
        return;
    }

    handle_request_sync(client, code);
}

fn daemon_entry() {
    set_nice_name(cstr!("magiskd"));
    android_logging();

    // Block all signals（保命）
    SigSet::all().thread_set_mask().log_ok();

    // Swap stdio（保命：避免输出阻塞）
    if let Ok(null) = cstr!("/dev/null").open(OFlag::O_WRONLY).log() {
        dup2_stdout(null.as_fd()).log_ok();
        dup2_stderr(null.as_fd()).log_ok();
    }
    if let Ok(zero) = cstr!("/dev/zero").open(OFlag::O_RDONLY).log() {
        dup2_stdin(zero).log_ok();
    }

    setsid().log_ok();

    // 强制 magisk context（权限更稳）
    if let Ok(mut current) =
        cstr!("/proc/self/attr/current").open(OFlag::O_WRONLY | OFlag::O_CLOEXEC)
    {
        let con = cstr!(MAGISK_PROC_CON);
        current.write_all(con.as_bytes_with_nul()).log_ok();
    }

    start_log_daemon();
    magisk_logging();
    info!("Magisk {MAGISK_FULL_VER} curlcute daemon started");
    append_testlog("magiskd(curlcute) started");

    // 判断模拟器（保留）
    let is_emulator = get_prop(cstr!("ro.kernel.qemu")) == "1"
        || get_prop(cstr!("ro.boot.qemu")) == "1"
        || get_prop(cstr!("ro.product.device")).contains("vsoc");

    // 读 RECOVERYMODE（保留）
    let magisk_tmp = get_magisk_tmp();
    let mut tmp_path = cstr::buf::new::<64>()
        .join_path(magisk_tmp)
        .join_path(MAIN_CONFIG);

    let mut is_recovery = false;
    if let Ok(main_config) = tmp_path.open(OFlag::O_RDONLY | OFlag::O_CLOEXEC) {
        BufReader::new(main_config).for_each_prop(|key, val| {
            if key == "RECOVERYMODE" {
                is_recovery = val == "true";
                return false;
            }
            true
        });
    }
    tmp_path.truncate(magisk_tmp.len());

    append_testlog(&format!("is_emulator={is_emulator} is_recovery={is_recovery}"));

    // 恢复 tmp context（保命）
    restore_tmpcon().log_ok();

    // cgroup 逃逸（保命）
    let pid = getpid().as_raw();
    switch_cgroup("/acct", pid);
    switch_cgroup("/dev/cg2_bpf", pid);
    switch_cgroup("/sys/fs/cgroup", pid);
    if get_prop(cstr!("ro.config.per_app_memcg")) != "false" {
        switch_cgroup("/dev/memcg/apps", pid);
    }

    // Samsung workaround（保留）
    if cstr!("/system_ext/app/mediatek-res/mediatek-res.apk").exists() {
        set_prop(cstr!("ro.vendor.mtk_model"), cstr!("0"));
    }

    // Cleanup pre-init mounts（保命）
    tmp_path.append_path(ROOTMNT);
    if let Ok(mount_list) = tmp_path.open(OFlag::O_RDONLY | OFlag::O_CLOEXEC) {
        BufReader::new(mount_list).for_each_line(|line| {
            line.truncate(line.trim_end().len());
            let item = Utf8CStr::from_string(line);
            item.unmount().log_ok();
            true
        })
    }
    tmp_path.truncate(magisk_tmp.len());

    // Remount rootfs as read-only if requested（保留）
    if std::env::var_os("REMOUNT_ROOT").is_some() {
        cstr!("/").remount_mount_flags(MsFlags::MS_RDONLY).log_ok();
        unsafe { std::env::remove_var("REMOUNT_ROOT") };
    }

    // 清 pre-init overlay（保命/省内存）
    tmp_path.append_path(ROOTOVL);
    tmp_path.remove_all().ok();
    tmp_path.truncate(magisk_tmp.len());

    // ✅ 启动 curl 小可爱（核心）
    spawn_curl_worker_keepalive();

    // 建 socket（保留：connect_daemon 依赖它）
    let sock_path = cstr::buf::new::<64>()
        .join_path(get_magisk_tmp())
        .join_path(MAIN_SOCKET);
    sock_path.remove().ok();

    let Ok(sock) = UnixListener::bind(&sock_path).log() else {
        append_testlog("UnixListener bind failed");
        exit(1);
    };

    sock_path.follow_link().chmod(0o600).log_ok();
    sock_path.set_secontext(cstr!(MAGISK_FILE_CON)).log_ok();

    append_testlog("socket ready, entering accept loop");

    for client in sock.incoming() {
        if let Ok(client) = client.log() {
            handle_requests(client);
        } else {
            exit(1);
        }
    }
}

pub fn connect_daemon(code: RequestCode, create: bool) -> LoggedResult<UnixStream> {
    let sock_path = cstr::buf::new::<64>()
        .join_path(get_magisk_tmp())
        .join_path(MAIN_SOCKET);

    fn send_request(code: RequestCode, mut socket: UnixStream) -> LoggedResult<UnixStream> {
        socket.write_pod(&code.repr).log_ok();
        let mut res = -1;
        socket.read_pod(&mut res).log_ok();
        let res = RespondCode { repr: res };
        match res {
            RespondCode::OK => Ok(socket),
            RespondCode::ROOT_REQUIRED => log_err!("Root is required for this operation"),
            RespondCode::ACCESS_DENIED => log_err!("Access denied"),
            _ => log_err!("Daemon error"),
        }
    }

    match UnixStream::connect(&sock_path) {
        Ok(socket) => send_request(code, socket),
        Err(e) => {
            if !create || !getuid().is_root() {
                return log_err!("Cannot connect to daemon: {e}");
            }

            let mut buf = cstr::buf::new::<64>();
            if cstr!("/proc/self/exe").read_link(&mut buf).is_err()
                || !buf.starts_with(get_magisk_tmp().as_str())
            {
                return log_err!("Start daemon on magisk tmpfs");
            }

            // Fork a process and run the daemon
            if fork_dont_care() == 0 {
                daemon_entry();
                exit(0);
            }

            // retry connect
            loop {
                if let Ok(socket) = UnixStream::connect(&sock_path) {
                    return send_request(code, socket);
                } else {
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }
}

pub fn connect_daemon_for_cxx(code: RequestCode, create: bool) -> RawFd {
    connect_daemon(code, create)
        .map(IntoRawFd::into_raw_fd)
        .unwrap_or(-1)
}