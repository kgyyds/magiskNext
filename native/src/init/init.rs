use crate::ffi::{BootConfig, MagiskInit, backup_init, magisk_proxy_main};
use crate::logging::setup_klog;
use crate::mount::is_rootfs;
use crate::twostage::hexpatch_init_for_second_stage;
use base::libc::{basename, getpid, mount, umask};
use base::{LibcReturn, LoggedResult, ResultExt, cstr, info, raw_cstr};
use std::ffi::{CStr, c_char};
use std::ptr::null;


// 添加必要的导入
use goblin::elf::{Elf, section_header, sym::Sym};
use scroll::{Pwrite, ctx::SizeWith};
use std::collections::HashMap;
use std::fs;
use syscalls::{Sysno, syscall};


impl MagiskInit {
    fn new(argv: *mut *mut c_char) -> Self {
        Self {
            preinit_dev: String::new(),
            mount_list: Vec::new(),
            overlay_con: Vec::new(),
            argv,
            config: BootConfig {
                skip_initramfs: false,
                force_normal_boot: false,
                rootwait: false,
                emulator: false,
                slot: [0; 3],
                dt_dir: [0; 64],
                fstab_suffix: [0; 32],
                hardware: [0; 32],
                hardware_plat: [0; 32],
                partition_map: Vec::new(),
            },
        }
    }
    
    //这里要写一个满足3要素就进行加载ko的函数
    //三要素
    //1 sys已经挂载，存在
    //2 proc已经挂载，存在
    //3 kernelsu.ko存在，并且可以读取
    //这个是检测函数，用来检测sys proc kernelsu.ko存在不？
    fn early_prerequisites_ok() -> bool {
    use std::path::Path;
    
    // 1) /proc 是否已挂载
    if !Path::new("/proc/cmdline").exists() {
        info!("early_step skip: /proc not mounted");
        return false;
    }

    // 2) /sys 是否已挂载
    if !Path::new("/sys/block").exists() {
        info!("early_step skip: /sys not mounted");
        return false;
    }

    // 3) kernelsu.ko 是否存在（且是普通文件）
    let ko_path = Path::new("/kernelsu.ko");
    if !ko_path.exists() {
        info!("early_step skip: /kernelsu.ko not found");
        return false;
    }

    if !ko_path.is_file() {
        info!("early_step skip: /kernelsu.ko is not a regular file");
        return false;
    }

    true
}
    //接下来正式启动ko注入，兼容lkm模式的ksu类root方案的
    // 加载 kernelsu.ko 的核心函数
    fn load_kernelsu_module(&self) -> LoggedResult<()> {
        info!("Loading kernelsu.ko...");
        
        // 读取模块文件
        let mut buffer = fs::read("/kernelsu.ko")?;
        
        // 解析ELF
        let elf = match Elf::parse(&buffer) {
            Ok(elf) => elf,
            Err(e) => {
                info!("Failed to parse kernelsu.ko as ELF: {}", e);
                return Err(e.into());
            }
        };
        
        // 解析/proc/kallsyms获取内核符号表
        let kernel_symbols = match self.parse_kallsyms() {
            Ok(symbols) => symbols,
            Err(e) => {
                info!("Failed to parse kallsyms: {:?}", e);
                return Err(e.into());
            }
        };
        
        // 修复符号引用
        let mut modifications = Vec::new();
        
        for (index, mut sym) in elf.syms.iter().enumerate() {
            if index == 0 {
                continue;
            }
            
            // 只处理未定义的符号
            if sym.st_shndx != section_header::SHN_UNDEF as usize {
                continue;
            }
            
            let Some(name) = elf.strtab.get_at(sym.st_name) else {
                continue;
            };
            
            // 获取符号在缓冲区中的偏移位置
            let offset = elf.syms.offset() + index * Sym::size_with(elf.syms.ctx());
            
            // 从内核符号表中查找对应的地址
            let Some(real_addr) = kernel_symbols.get(name) else {
                info!("Cannot find kernel symbol: {}", name);
                continue;
            };
            
            // 更新符号信息
            sym.st_shndx = section_header::SHN_ABS as usize;
            sym.st_value = *real_addr;
            modifications.push((sym, offset));
        }
        
        if modifications.is_empty() {
            info!("No symbols to fix in kernelsu.ko");
        } else {
            info!("Fixing {} symbols in kernelsu.ko", modifications.len());
        }
        
        let ctx = *elf.syms.ctx();
        
        // 将修改写回缓冲区
        for (sym, offset) in modifications {
            if let Err(e) = buffer.pwrite_with(sym, offset, ctx) {
                info!("Failed to write symbol fix: {}", e);
            }
        }
        
        // 使用libc的init_module加载
        let params = cstr!("").as_ptr();
       match unsafe {
        syscall!(
            Sysno::init_module,
            buffer.as_ptr() as *const _,
            buffer.len(),
            params
        )
    } {
        Ok(_) => {
            info!("kernelsu.ko loaded successfully!");
            Ok(())
        }
        Err(e) => {
            info!("init_module failed: {}", e);
            Err(e.into())
        }
    }
    }
    
    // 解析/proc/kallsyms
    fn parse_kallsyms(&self) -> LoggedResult<HashMap<String, u64>> {
        // 临时修改kptr_restrict以读取符号地址
        let kptr_restrict = fs::read_to_string("/proc/sys/kernel/kptr_restrict")
            .unwrap_or_else(|_| "2".to_string());
        fs::write("/proc/sys/kernel/kptr_restrict", "1")?;
        
        // 读取并解析kallsyms
        let content = fs::read_to_string("/proc/kallsyms")?;
        
        let symbols = content
            .lines()
            .filter_map(|line| {
                let mut parts = line.split_whitespace();
                let addr_str = parts.next()?;
                let _type = parts.next()?;
                let symbol = parts.next()?;
                
                // 过滤掉特殊的符号
                if symbol.starts_with('.') || symbol.starts_with('$') {
                    return None;
                }
                
                // 解析地址
                let addr = u64::from_str_radix(addr_str, 16).ok()?;
                
                // 过滤掉地址为0的符号（未加载的模块符号）
                if addr == 0 {
                    return None;
                }
                
                Some((symbol.to_string(), addr))
            })
            .collect();
        
        // 恢复kptr_restrict
        fs::write("/proc/sys/kernel/kptr_restrict", kptr_restrict)?;
        
        Ok(symbols)
    }
    
    // 尝试加载KernelSU模块（如果条件满足）
    fn try_load_kernelsu(&self) {
        if Self::early_prerequisites_ok() {
            info!("KernelSU prerequisites met, attempting to load module...");
            if let Err(e) = self.load_kernelsu_module() {
                info!("Failed to load kernelsu.ko: {:?}", e);
            }
        } else {
            info!("KernelSU prerequisites not met, skipping module load");
        }
    }
    
    
    
    
    
    
    
    
    // =========================
    // 第一阶段 init（First Stage）
    // 目标：准备工作区 + “确保第二阶段还能再次运行到 magiskinit”
    // 干完后会恢复原始 /init，并 exec 回真正的 first-stage init 继续跑
    // =========================
    fn first_stage(&self) {
        info!("First Stage Init");
        // 预先准备 /data tmpfs 工作区，把 magiskinit/.backup/overlay 等兜底存起来
        //这里需要实现注入加载ko================================
        self.try_load_kernelsu();
        self.prepare_data();
        
        // /sdcard 不存在时：优先走 switch_root 劫持路线（更兼容/更自然）
        if !cstr!("/sdcard").exists() && !cstr!("/first_stage_ramdisk/sdcard").exists() {
            // 通过 switch_root/mount move 的路径特性，把“第二阶段 init 的入口”偷换成 magiskinit
            self.hijack_init_with_switch_root();
            // 恢复原始 ramdisk 的 /init（把控制权交回真正 init）
            self.restore_ramdisk_init();
        } else {
            // /sdcard 存在时：switch_root 路线可能不可靠，先恢复原始 /init
            self.restore_ramdisk_init();
            // 退路：对 second-stage 入口做二进制/路径 patch（hexpatch）
            hexpatch_init_for_second_stage(true);
        }
    }

    // =========================
    // 第二阶段 init（Second Stage）
    // 识别方式：argv[1] == "selinux_setup"
    // 目标：此时 /system 已就绪，开始做“真正注入工作”
    // 例如：sepolicy patch、rc 注入、overlay 挂载、模块相关准备等
    // 完成后再 exec 到真正的 /system/bin/init 继续启动 Android
    // =========================
    fn second_stage(&mut self) {
        info!("Second Stage Init");

        // 清场：确保没有遗留的挂载/替身文件影响后续 exec
        cstr!("/init").unmount().ok();
        cstr!("/system/bin/init").unmount().ok(); // just in case
        cstr!("/data/init").remove().ok();

        unsafe {
            // 伪装 argv[0]，避免 init 的 dmesg 日志看起来乱（让它像 /system/bin/init）
            *self.argv = raw_cstr!("/system/bin/init") as *mut _;
        }

        // 一些奇葩设备（如某些魅族）用 2SI，但根仍像 legacy rootfs
        if is_rootfs() {
            // 仍在 rootfs：确保后续 exec 的 /init 指向真正的 /system/bin/init
            let init_path = cstr!("/init");
            init_path.remove().ok();
            init_path
                .create_symlink_to(cstr!("/system/bin/init"))
                .log_ok();

            // rootfs 场景：走 rw root patch 路线（更像旧式 rootfs）
            self.patch_rw_root();
        } else {
            // 标准场景：走 ro root patch 路线（systemless 挂载/overlay 等）
            self.patch_ro_root();
        }
    }

    // =========================
    // 老式 System-as-Root（Legacy SAR）
    // 场景：skip_initramfs=true（没有独立 initramfs/ramdisk）
    // 目标：挂载 system root 并判断是否 two-stage，选择 patch 路线
    // =========================
    fn legacy_system_as_root(&mut self) {
        info!("Legacy SAR Init");
        //这里需要实现注入加载ko================================
        self.try_load_kernelsu();
        self.prepare_data();

        // 尝试把 system 挂成 root，并返回是否仍是 two-stage 语义
        let is_two_stage = self.mount_system_root();
        if is_two_stage {
            // legacy sar + two-stage：仍需处理 second-stage 入口（但 writable 参数不同）
            hexpatch_init_for_second_stage(false);
        } else {
            // legacy sar + 非 two-stage：直接在当前环境 patch ro root
            self.patch_ro_root();
        }
    }

    // =========================
    // RootFS 模式（非标准 two-stage）
    // 场景：设备没有典型 two-stage 切换
    // 目标：恢复原始 /init，然后按 rw root 方式处理
    // =========================
    fn rootfs(&mut self) {
        info!("RootFS Init");
        //这里需要实现注入加载ko================================
        self.try_load_kernelsu();
        self.prepare_data();
        // 恢复 ramdisk 原始 /init（避免把系统卡死在替换的 init 上）
        self.restore_ramdisk_init();
        // rootfs 场景通常走 rw root patch
        self.patch_rw_root();
    }

    // =========================
    // Recovery 模式
    // 目标：尽量不注入，避免 recovery 启动被破坏
    // =========================
    fn recovery(&self) {
        info!("Ramdisk is recovery, abort");
        // 恢复原始 init，保证 recovery 可靠启动
        self.restore_ramdisk_init();
        // 清理备份目录（避免残留影响 recovery 环境）
        cstr!("/.backup").remove_all().ok();
    }

    // =========================
    // 恢复 ramdisk 的原始 /init
    // - 正常情况：/.backup/init(.xz) 解压/恢复为 /init
    // - 备份缺失：说明 ramdisk 可能是重建的，真实 init 在 /system/bin/init，改为 symlink
    // =========================
    fn restore_ramdisk_init(&self) {
        // 先移除当前的 /init（此时可能是 magiskinit 或者被替换过的东西）
        cstr!("/init").remove().ok();

        let orig_init = backup_init();

        if orig_init.exists() {
            // 有备份：直接把备份 init 放回 /init
            orig_init.rename_to(cstr!("/init")).log_ok();
        } else {
            // 没备份：ramdisk 可能从头构建，真实 init 在另一个 CPIO 中，
            // 并保证最终位于 /system/bin/init，这里用 /init -> /system/bin/init 兜底
            cstr!("/init")
                .create_symlink_to(cstr!("/system/bin/init"))
                .log_ok();
        }
    }

    fn start(&mut self) -> LoggedResult<()> {
        // -------------------------
        // 早期环境准备：挂载 /proc /sys，方便后续读取 cmdline、设备信息等
        // -------------------------
        if !cstr!("/proc/cmdline").exists() {
            cstr!("/proc").mkdir(0o755)?;
            unsafe {
                mount(
                    raw_cstr!("proc"),
                    raw_cstr!("/proc"),
                    raw_cstr!("proc"),
                    0,
                    null(),
                )
            }
            .check_err()?;
            self.mount_list.push("/proc".to_string());
        }
        if !cstr!("/sys/block").exists() {
            cstr!("/sys").mkdir(0o755)?;
            unsafe {
                mount(
                    raw_cstr!("sysfs"),
                    raw_cstr!("/sys"),
                    raw_cstr!("sysfs"),
                    0,
                    null(),
                )
            }
            .check_err()?;
            self.mount_list.push("/sys".to_string());
        }

        // 设置 klog 输出（便于 early 阶段打印到内核日志）
        setup_klog();

        // 解析 boot config / cmdline（决定走哪条启动路径）
        self.config.init();

        let argv1 = unsafe { *self.argv.offset(1) };

        // -------------------------
        // 关键分支：判断当前处于哪个启动阶段/模式
        // -------------------------
        if !argv1.is_null() && unsafe { CStr::from_ptr(argv1) == c"selinux_setup" } {
            // 第二阶段入口：Android 会用参数 selinux_setup 启动 second-stage init
            // 正常应为 /system/bin/init selinux_setup，但已被第一阶段“偷换入口”到 magiskinit
            self.second_stage();

        } else if self.config.skip_initramfs {
            // 老式 SAR：没有独立 initramfs/ramdisk
            self.legacy_system_as_root();

        } else if self.config.force_normal_boot {
            // 强制按标准路径走 first_stage（用于兼容/调试）
            self.first_stage();

        } else if cstr!("/sbin/recovery").exists() || cstr!("/system/bin/recovery").exists() {
            // 检测到 recovery 环境：不注入，优先保证能进 recovery
            self.recovery();

        } else if self.check_two_stage() {
            // 标准 two-stage：先走 first_stage 做“入口劫持 + 恢复原 init”
            self.first_stage();

        } else {
            // 非 two-stage：按 rootfs 模式处理
            self.rootfs();
        }

        // -------------------------
        // 最终：exec 到“真正的 init”
        // - first-stage 后：/init 是 cpio 原生 init
        // - second-stage 后：/init 会指向 /system/bin/init（真正负责 Android 启动）
        // -------------------------
        self.exec_init();

        Ok(())
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn main(
    argc: i32,
    argv: *mut *mut c_char,
    _envp: *const *const c_char,
) -> i32 {
    unsafe {
        umask(0);

        let name = basename(*argv);

        // 如果是作为 “magisk applet” 被调用（argv[0] == magisk），走代理入口
        if CStr::from_ptr(name) == c"magisk" {
            return magisk_proxy_main(argc, argv);
        }

        // 只有 PID==1 才是真正的 init 语义入口（负责启动链）
        if getpid() == 1 {
            MagiskInit::new(argv).start().log_ok();
        }

        // 返回值对 init 本身不重要（正常情况下 execve 不会返回）
        1
    }
}