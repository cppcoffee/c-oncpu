use std::env;
use std::path::PathBuf;

use anyhow::Result;
use aya::{
    programs::{perf_event, PerfEvent},
    Ebpf,
};
use clap::Parser;
use log::{debug, info, warn};

use c_oncpu::symbol::dump_stack_frames;
use c_oncpu::util::{dump_to_file, wait_for_termination_signal};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, help = "pid of the process")]
    pid: u32,

    #[clap(short, long, default_value = "30", help = "timeout in seconds")]
    timeout: u64,

    #[clap(short, long, default_value = "/tmp/output.out", help = "output file")]
    output: PathBuf,

    #[clap(short, long, default_value = "false", help = "verbose mode")]
    verbose: bool,

    #[clap(
        short,
        long,
        default_value = "false",
        help = "Kernel threads only (no user threads)"
    )]
    kernel_threads_only: bool,

    #[clap(short, long, default_value = "1000", help = "sample frequency")]
    frequency: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::parse();

    // set log level, when RUST_LOG env not set
    if env::var("RUST_LOG").is_err() {
        let s = if opt.verbose { "debug" } else { "info" };

        env::var("RUST_LOG")
            .err()
            .map(|_| env::set_var("RUST_LOG", s));
    }

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/c-oncpu"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    attach_perf_event(&mut ebpf, opt.pid, opt.frequency)?;

    info!("wait for {}s or press ctrl+c to start dump", opt.timeout);
    wait_for_termination_signal(opt.timeout).await;

    let map = dump_stack_frames(&mut ebpf, opt.pid).await?;
    dump_to_file(&opt.output, &map).await?;

    info!("dump stack frame to {:?}", opt.output);

    Ok(())
}

fn attach_perf_event(ebpf: &mut Ebpf, pid: u32, frequency: u64) -> Result<()> {
    // This will raise scheduled events on each CPU at 1 HZ, triggered by the kernel based
    // on clock ticks.
    let program: &mut PerfEvent = ebpf.program_mut("c_oncpu").unwrap().try_into()?;
    program.load()?;
    program.attach(
        perf_event::PerfTypeId::Software,
        perf_event::perf_sw_ids::PERF_COUNT_SW_CPU_CLOCK as u64,
        perf_event::PerfEventScope::OneProcessAnyCpu { pid },
        perf_event::SamplePolicy::Frequency(frequency),
        false,
    )?;

    Ok(())
}
