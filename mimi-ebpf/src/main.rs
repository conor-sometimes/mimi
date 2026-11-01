#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_task, bpf_ktime_get_ns, bpf_probe_read_kernel, bpf_probe_read_user_buf,
    },
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use mimi_types::{Ancestor, Lineage, CMDLINE_LEN, MAX_DEPTH};

// task_struct / mm_struct field byte offsets for THIS kernel (6.18, from `pahole`). PoC stopgap: the
// first-class sensor relocates these via CO-RE (aya-tool vmlinux bindings) so one binary runs on any
// BTF kernel. Hardcoded offsets cannot cross kernels -- which is exactly why the distro matrix forces
// CO-RE (see the roadmap). The only `unsafe` below is the kernel/user reads: fault-safe helpers,
// bounded loop, verified by the kernel's BPF verifier at load.
const OFF_TGID: usize = 1924; // task_struct.tgid
const OFF_REAL_PARENT: usize = 1936; // task_struct.real_parent
const OFF_COMM: usize = 2464; // task_struct.comm[16]
const OFF_MM: usize = 1792; // task_struct.mm
const OFF_ARG_START: usize = 488; // mm_struct.arg_start (user address)
const OFF_ARG_END: usize = 496; // mm_struct.arg_end

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[inline(always)]
unsafe fn read_at<T>(base: *const u8, off: usize) -> Result<T, i64> {
    // bpf_probe_read_kernel returns Result<T, i32>; `?` widens the error to i64.
    Ok(bpf_probe_read_kernel(base.add(off) as *const T)?)
}

#[tracepoint]
pub fn mimi(_ctx: TracePointContext) -> u32 {
    let _ = run();
    0
}

fn run() -> Result<(), i64> {
    let mut lin = Lineage::zeroed();
    lin.time_ns = unsafe { bpf_ktime_get_ns() };

    let task0 = unsafe { bpf_get_current_task() } as *const u8;

    // argv of the just-execed process: its own user memory between mm->arg_start and mm->arg_end,
    // NUL-separated (the region /proc/PID/cmdline reads).
    if !task0.is_null() {
        let mm: *const u8 = unsafe { read_at(task0, OFF_MM)? };
        if !mm.is_null() {
            let arg_start: u64 = unsafe { read_at(mm, OFF_ARG_START)? };
            let arg_end: u64 = unsafe { read_at(mm, OFF_ARG_END)? };
            let total = arg_end.saturating_sub(arg_start);
            let n = if total > CMDLINE_LEN as u64 { CMDLINE_LEN as u32 } else { total as u32 };
            if arg_start != 0
                && n > 0
                && unsafe { bpf_probe_read_user_buf(arg_start as *const u8, &mut lin.cmdline) }.is_ok()
            {
                lin.cmdline_len = n;
            }
        }
    }

    // ancestry walk: real_parent up the tree until pid 1 or MAX_DEPTH.
    let mut task = task0;
    for i in 0..MAX_DEPTH {
        if task.is_null() {
            break;
        }
        let pid: u32 = unsafe { read_at(task, OFF_TGID)? };
        let comm: [u8; 16] = unsafe { read_at(task, OFF_COMM)? };
        lin.chain[i] = Ancestor { pid, comm };
        lin.count += 1;
        if pid <= 1 {
            break;
        }
        task = unsafe { read_at::<*const u8>(task, OFF_REAL_PARENT)? };
    }

    if let Some(mut entry) = EVENTS.reserve::<Lineage>(0) {
        entry.write(lin);
        entry.submit(0);
    }
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
