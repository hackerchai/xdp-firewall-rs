use std::net::Ipv4Addr;

use aya::{
    include_bytes_aligned,
    maps::{perf::AsyncPerfEventArray, HashMap},
    programs::{CgroupSkb, CgroupSkbAttachType},
    util::online_cpus,
    Bpf,
};
use bytes::BytesMut;
use clap::Parser;
use log::info;
use tokio::{signal, task};

use xdp_firewall_rs_common::PacketLog;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "/sys/fs/cgroup/foo/cgroup.procs")]
    cgroup_path: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

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
    let program: &mut CgroupSkb =
        bpf.program_mut("cgroup_skb_egress").unwrap().try_into()?;
    let cgroup = std::fs::File::open(opt.cgroup_path)?;
    // (1)
    program.load()?;
    // (2)
    program.attach(cgroup, CgroupSkbAttachType::Egress)?;

    let mut blocklist: HashMap<_, u32, u32> =
        HashMap::try_from(bpf.map_mut("BLOCKLIST").unwrap())?;

    let block_addr: u32 = Ipv4Addr::new(1, 1, 1, 1).try_into()?;

    // (3)
    blocklist.insert(block_addr, 0, 0)?;

    let mut perf_array =
        AsyncPerfEventArray::try_from(bpf.take_map("EVENTS").unwrap())?;

    for cpu_id in online_cpus()? {
        let mut buf = perf_array.open(cpu_id, None)?;

        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for buf in buffers.iter_mut().take(events.read) {
                    let ptr = buf.as_ptr() as *const PacketLog;
                    let data = unsafe { ptr.read_unaligned() };
                    let src_addr = Ipv4Addr::from(data.ipv4_address);
                    info!("LOG: DST {}, ACTION {}", src_addr, data.action);
                }
            }
        });
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
