use anyhow::Context;
use aya::maps::{PerCpuHashMap, PerCpuValues};
use aya::programs::{Xdp, XdpFlags};
use aya::util::nr_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use log::{info, warn, debug};
use tokio::signal;
use std::time::Duration;
use std::thread;
use num_format::ToFormattedString;
use num_format::format::Locale;


#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
    #[clap(long, default_value = "5")]
    cms_rows: u32,
    #[clap(long, default_value = "131072")]
    cms_size: u32,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    // let ret = unsafe { libc::setrlimit(libc::RLIMIT_AS, &rlim) };
    // let ret = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &rlim) };
    // let ret = unsafe { libc::setrlimit(libc::RLIMIT_CPU, &rlim) };
    // let ret = unsafe { libc::setrlimit(libc::RLIMIT_DATA, &rlim) };
    // let ret = unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &rlim) };
    // let ret = unsafe { libc::setrlimit(libc::RLIMIT_LOCKS, &rlim) };
    // let ret = unsafe { libc::setrlimit(libc::RLIMIT_MSGQUEUE, &rlim) };
    // let ret = unsafe { libc::setrlimit(libc::RLIMIT_NICE, &rlim) };
    // let ret = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &rlim) };
    // let ret = unsafe { libc::setrlimit(libc::RLIMIT_NPROC, &rlim) };
    // let ret = unsafe { libc::setrlimit(libc::RLIMIT_RSS, &rlim) };
    // let ret = unsafe { libc::setrlimit(libc::RLIMIT_RTPRIO, &rlim) };
    // let ret = unsafe { libc::setrlimit(libc::RLIMIT_RTTIME, &rlim) };
    // let ret = unsafe { libc::setrlimit(libc::RLIMIT_SIGPENDING, &rlim) };
    // let ret = unsafe { libc::setrlimit(libc::RLIMIT_STACK, &rlim) };
    // let ret = unsafe { libc::setrlimit(libc::RLIMIT_NLIMITS, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/print"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/print"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut Xdp = bpf.program_mut("print").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    // let mut stat_map: PerCpuHashMap<_,u32,u32> = PerCpuHashMap::try_from(bpf.map_mut("STAT").unwrap())?;
    // stat_map.insert(0, PerCpuValues::try_from(vec![0;nr_cpus()?])?, 0);

    // info!("Waiting for Ctrl-C...");
    // let mut oldpkts = 0;
    // let mut maxpps = 0;
    // loop {

    //     let mut totpkts = 0;
    //     let pkts = stat_map.get(&0, 0)?;
    //     for cpupkt in pkts.iter(){
    //         totpkts+=cpupkt;
    //     }

    //     let pps = totpkts-oldpkts;
    //     if pps>maxpps{
    //         maxpps=pps;

    //     }

    //     let formatted_counter = pps.to_formatted_string(&Locale::it);
    //     let formatted_max= maxpps.to_formatted_string(&Locale::it);

    //     info!("Pacchetti al secondo = {} Max = {}",formatted_counter,formatted_max);
    //     oldpkts = totpkts;
    //     thread::sleep(Duration::from_secs(1));

    // }
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
