use anyhow::Context;
use aya::{
    include_bytes_aligned,
    maps::HashMap,
    programs::{Xdp, XdpFlags},
    Bpf,
};
use aya_log::BpfLogger;
use clap::Parser;
use log::{info, warn, debug};
use std::net::Ipv4Addr;
use tokio::signal;
use std::fs;
use std::net::IpAddr;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
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
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/xdp-firewall-rs"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/xdp-firewall-rs"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut Xdp = bpf.program_mut("xdp_firewall_rs").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let block_conf = fs::read_to_string("block.list").expect("can not read file");

    let mut ips: Vec<[u8; 4]> = Vec::new();

    for line in block_conf.lines() {
        if line.is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.split('/').collect();
        if parts.len() != 2 {
            println!("无效的行: {}", line);
            continue;
        }

        let ip = parts[0].parse::<IpAddr>().expect("invalid ip");
        let octets = match ip {
            IpAddr::V4(ipv4) => ipv4.octets(),
            IpAddr::V6(ipv6) => ipv6.octets()[..4].try_into().unwrap(),
        };

        ips.push(octets);
    }

    let mut blocklist: HashMap<_, u32, u32> =
        HashMap::try_from(bpf.map_mut("BLOCKLIST").unwrap())?;

    let mut block_addr:u32;
    for ip in ips {
        block_addr = Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]).try_into()?;
        blocklist.insert(block_addr, 0, 0)?;
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
