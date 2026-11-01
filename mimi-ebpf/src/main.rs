#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext,
    helpers::{
        bpf_get_current_task, bpf_get_current_uid_gid, bpf_ktime_get_ns, bpf_probe_read_kernel,
        bpf_probe_read_kernel_str_bytes, bpf_probe_read_user_buf,
    },
    macros::{map, tracepoint},
    maps::{Array, PerCpuArray, RingBuf},
    programs::TracePointContext,
};
use mimi_types::{Ancestor, CMDLINE_LEN, Lineage, MAX_DEPTH};

// task_struct / mm_struct field byte offsets. The probe holds NONE of its own: it reads each from
// the OFFSETS map, which the loader fills from the running kernel's own BTF before attaching (the
// CO-RE property -- one binary adapts to each kernel's layout; mimi/src/btf.rs resolves them, and
// mimi_types::OFFSET_TABLE is only the loader's fallback for a kernel without BTF). Reading them
// through a fault-safe helper at a value-sourced offset is exactly how libbpf CO-RE reads work, so
// the BPF verifier accepts it. The only `unsafe` below is the kernel/user reads and the scratch-map
// access: fault-safe helpers, bounded loop, verifier-checked at load.
#[map]
static OFFSETS: Array<u32> = Array::with_max_entries(mimi_types::OFFSET_COUNT, 0);

#[inline(always)]
fn off(idx: u32) -> usize {
    OFFSETS.get(idx).copied().unwrap_or(0) as usize
}

// sched_process_exec tracepoint record layout (tracefs
// events/sched/sched_process_exec/format; stable across 5.x/6.x):
//   common_type u16 @0, common_flags u8 @2, common_preempt_count u8 @3, common_pid i32 @4,
//   __data_loc char[] filename u32 @8, pid i32 @12, old_pid i32 @16.
// A __data_loc is (len << 16) | offset, the offset being from the start of the record (= the
// tracepoint ctx pointer), so the path lives at ctx + (loc & 0xffff). Confirmed live on 6.18.59:
// a load captured file.path=/run/current-system/sw/bin/timeout for the right exec.
const OFF_FILENAME_LOC: usize = 8;

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

// Lineage is 576 bytes, over the 512-byte BPF stack, so it is assembled in a per-CPU scratch slot
// and copied into the ring buffer, never held on the stack. One slot is enough: a tracepoint
// program is not re-entered on the same CPU.
#[map]
static SCRATCH: PerCpuArray<Lineage> = PerCpuArray::with_max_entries(1, 0);

// Events lost because the ring buffer was full (reserve returned None), per CPU, so loss is counted
// rather than silent. Userspace reads it (sum over CPUs) -- not yet wired up.
#[map]
static DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[inline(always)]
unsafe fn read_at<T>(base: *const u8, off: usize) -> Result<T, i64> {
    // Rust 2024 wants the unsafe ops spelled out even inside an unsafe fn. bpf_probe_read_kernel
    // returns Result<T, i32>; `?` widens the error to i64.
    let ptr = unsafe { base.add(off) } as *const T;
    Ok(unsafe { bpf_probe_read_kernel(ptr) }?)
}

#[tracepoint]
pub fn mimi(ctx: TracePointContext) -> u32 {
    let _ = run(&ctx);
    0
}

fn run(ctx: &TracePointContext) -> Result<(), i64> {
    let lin_ptr = SCRATCH.get_ptr_mut(0).ok_or(-1i64)?;
    // Zero in place (a memset into the map value) rather than `*lin_ptr = Lineage::zeroed()`, which
    // could materialise the 576-byte constant on the stack first.
    unsafe { core::ptr::write_bytes(lin_ptr, 0, 1) };
    let lin: &mut Lineage = unsafe { &mut *lin_ptr };

    lin.time_ns = unsafe { bpf_ktime_get_ns() };

    // bpf_get_current_uid_gid packs (gid << 32) | uid.
    let ug = bpf_get_current_uid_gid();
    lin.uid = ug as u32;
    lin.gid = (ug >> 32) as u32;

    // Executed program path from the tracepoint's own record (see OFF_FILENAME_LOC). The helper
    // stops at the NUL and is bounded by FILENAME_LEN; a failed read leaves filename all-NUL.
    if let Ok(loc) = unsafe { ctx.read_at::<u32>(OFF_FILENAME_LOC) } {
        let src = unsafe { (ctx.as_ptr() as *const u8).add((loc & 0xffff) as usize) };
        let _ = unsafe { bpf_probe_read_kernel_str_bytes(src, &mut lin.filename) };
    }

    let task0 = unsafe { bpf_get_current_task() } as *const u8;

    // The field offsets for this kernel, read once from the OFFSETS map the loader filled from BTF.
    let (off_tgid, off_rp, off_comm) = (
        off(mimi_types::OFF_IDX_TGID),
        off(mimi_types::OFF_IDX_REAL_PARENT),
        off(mimi_types::OFF_IDX_COMM),
    );
    let (off_mm, off_arg_start, off_arg_end) = (
        off(mimi_types::OFF_IDX_MM),
        off(mimi_types::OFF_IDX_ARG_START),
        off(mimi_types::OFF_IDX_ARG_END),
    );

    // argv of the just-execed process: its own user memory between mm->arg_start and mm->arg_end,
    // NUL-separated (the region /proc/PID/cmdline reads).
    if !task0.is_null() {
        let mm: *const u8 = unsafe { read_at(task0, off_mm)? };
        if !mm.is_null() {
            let arg_start: u64 = unsafe { read_at(mm, off_arg_start)? };
            let arg_end: u64 = unsafe { read_at(mm, off_arg_end)? };
            let total = arg_end.saturating_sub(arg_start);
            // True length before clamping, so the consumer can see a truncated capture.
            lin.argv_total_len = total.min(u32::MAX as u64) as u32;
            let n = if total > CMDLINE_LEN as u64 {
                CMDLINE_LEN as u32
            } else {
                total as u32
            };
            if arg_start != 0
                && n > 0
                && unsafe { bpf_probe_read_user_buf(arg_start as *const u8, &mut lin.cmdline) }
                    .is_ok()
            {
                lin.cmdline_len = n;
            }
        }
    }

    // ancestry walk: real_parent up the tree until pid 1 or MAX_DEPTH. A failed read ends the walk
    // (break, not return) so the partial chain plus the argv/filename already captured still ship.
    let mut task = task0;
    for i in 0..MAX_DEPTH {
        if task.is_null() {
            break;
        }
        let Ok(pid) = (unsafe { read_at::<u32>(task, off_tgid) }) else {
            break;
        };
        let Ok(comm) = (unsafe { read_at::<[u8; 16]>(task, off_comm) }) else {
            break;
        };
        lin.chain[i] = Ancestor { pid, comm };
        lin.count += 1;
        if pid <= 1 {
            break;
        }
        let Ok(parent) = (unsafe { read_at::<*const u8>(task, off_rp) }) else {
            break;
        };
        task = parent;
    }

    match EVENTS.reserve::<Lineage>(0) {
        Some(mut entry) => {
            // map value -> ring buffer, one bounded copy, no stack intermediate.
            unsafe {
                core::ptr::copy_nonoverlapping(lin_ptr as *const Lineage, entry.as_mut_ptr(), 1)
            };
            entry.submit(0);
        }
        None => {
            if let Some(drops) = DROPS.get_ptr_mut(0) {
                unsafe { *drops += 1 };
            }
        }
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
