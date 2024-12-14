use std::collections::{BTreeMap, HashMap};
use std::num::NonZeroU32;

use anyhow::{anyhow, Context, Result};
use aya::maps::stack_trace::StackTrace;
use aya::maps::{PerCpuHashMap, StackTraceMap};
use aya::util::kernel_symbols;
use aya::Ebpf;
use blazesym::symbolize::{CodeInfo, Input, Process, Source, Sym, Symbolizer};
use blazesym::Pid;
use log::info;

pub async fn dump_stack_frames(ebpf: &mut Ebpf, pid: u32) -> Result<HashMap<String, u64>> {
    let mut count = 0;
    let mut result = HashMap::new();

    let src = Source::Process(Process::new(Pid::Pid(NonZeroU32::new(pid as u32).unwrap())));
    let symbolizer = Symbolizer::new();
    let ksyms = kernel_symbols().context("failed to load kernel symbols")?;

    let stack_traces = StackTraceMap::try_from(ebpf.map("STACK_TRACES").unwrap())?;
    let bts: PerCpuHashMap<_, i64, u64> = PerCpuHashMap::try_from(ebpf.map("BTS").unwrap())?;

    for item in bts.iter() {
        let (stack_id, values) = item.context("failed to iter BTS map")?;

        let stack_trace = stack_traces.get(&(stack_id as u32), 0)?;
        let stack_frame = symbolize_stack_frames(&stack_trace, &symbolizer, &src, &ksyms)?;
        let sum = values.iter().sum::<u64>();

        result.insert(stack_frame, sum);

        count += 1;
    }

    info!("total {} stack frames, collapse to {}", count, result.len());

    Ok(result)
}

fn symbolize_stack_frames(
    stack_trace: &StackTrace,
    symbolizer: &Symbolizer,
    src: &Source,
    ksyms: &BTreeMap<u64, String>,
) -> Result<String> {
    let addrs: Vec<_> = stack_trace.frames().iter().rev().map(|x| x.ip).collect();

    let syms = symbolizer
        .symbolize(src, Input::AbsAddr(&addrs))
        .map_err(|e| anyhow!(format!("symbolize fail: {}", e)))?;

    let mut buffer = String::with_capacity(128);

    for (sym, addr) in syms.iter().zip(addrs.iter()) {
        if !buffer.is_empty() {
            buffer.push(';');
        }

        let name = match sym.as_sym() {
            Some(x) => format_symbolize(x),
            None => {
                ksymbols_search(ksyms, *addr).unwrap_or_else(|| format!("unknown_0x{:08x}", addr))
            }
        };

        buffer.push_str(&name);
    }

    Ok(buffer)
}

fn format_symbolize(sym: &Sym<'_>) -> String {
    let mut s = sym.name.to_string();

    if let Some(code_info) = &sym.code_info {
        s += format!(" ({})", format_code_info(&code_info)).as_ref();
    } else {
        if sym.inlined.len() > 0 {
            let inlined = &sym.inlined[0];

            s += format!(" <inlined:{}>", inlined.name).as_ref();

            if let Some(code_info) = &inlined.code_info {
                s += format!(" ({})", format_code_info(&code_info)).as_ref();
            }
        }
    }

    s += format!(" +0x{:x}", sym.offset).as_ref();

    s
}

fn format_code_info(code_info: &CodeInfo<'_>) -> String {
    match (code_info.dir.as_ref(), code_info.line) {
        (Some(dir), Some(line)) => {
            format!(
                "{}/{}:{}",
                dir.display(),
                code_info.file.to_string_lossy(),
                line
            )
        }
        (Some(dir), None) => format!("{}/{}", dir.display(), code_info.file.to_string_lossy()),
        (None, Some(line)) => format!("{}:{}", code_info.file.to_string_lossy(), line),
        (None, None) => format!("{}", code_info.file.to_string_lossy()),
    }
}

fn ksymbols_search(ksyms: &BTreeMap<u64, String>, ip: u64) -> Option<String> {
    let (sym_addr, name) = ksyms.range(..=ip).next_back()?;

    let kernel_addr_start = if cfg!(target_pointer_width = "64") {
        0xFFFF_8000_0000_0000
    } else {
        0xC000_0000
    };

    let result = if ip >= kernel_addr_start {
        let offset = ip - sym_addr;
        format!("{}+0x{:x}", name, offset)
    } else {
        name.to_string()
    };

    Some(result)
}
