#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{BPF_F_FAST_STACK_CMP, BPF_F_REUSE_STACKID, BPF_F_USER_STACK},
    cty::c_long,
    macros::{map, perf_event},
    maps::{PerCpuHashMap, StackTrace},
    programs::PerfEventContext,
    EbpfContext,
};

use c_oncpu_common::{BTS_MAX_ENTRIES, TRACE_MAX_ENTRIES};

#[map]
static BTS: PerCpuHashMap<i64, u64> = PerCpuHashMap::with_max_entries(BTS_MAX_ENTRIES, 0);

#[map]
static STACK_TRACES: StackTrace = StackTrace::with_max_entries(TRACE_MAX_ENTRIES, 0);

#[no_mangle]
static KERNEL_THREAD_ONLY: bool = false;

#[perf_event]
pub fn c_oncpu(ctx: PerfEventContext) -> u32 {
    match try_c_oncpu(ctx) {
        Ok(rc) => rc,
        Err(_) => 1,
    }
}

fn try_c_oncpu(ctx: PerfEventContext) -> Result<u32, c_long> {
    let stack_flags = if ctx.pid() == 0 {
        // running a kernel task
        BPF_F_FAST_STACK_CMP | BPF_F_REUSE_STACKID
    } else {
        // running a user task
        BPF_F_USER_STACK | BPF_F_FAST_STACK_CMP | BPF_F_REUSE_STACKID
    };

    let stack_id = unsafe { STACK_TRACES.get_stackid(&ctx, stack_flags as u64)? };

    match BTS.get_ptr_mut(&stack_id) {
        Some(n) => unsafe { *n += 1 },
        None => BTS.insert(&stack_id, &1, 0)?,
    }

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
