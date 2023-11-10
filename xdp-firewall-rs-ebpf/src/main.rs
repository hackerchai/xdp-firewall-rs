#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;

use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[map]
static BLOCKLIST: HashMap<u32, u32> =
    HashMap::<u32, u32>::with_max_entries(1024, 0);

#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    let ptr = (start + offset) as *const T;
    Ok(&*ptr)
}

fn block_ip(address: u32) -> bool {
    unsafe { BLOCKLIST.get(&address).is_some() }
}

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
    let source = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let dst = u32::from_be(unsafe { (*ipv4hdr).dst_addr });
    let size = u16::from_be(unsafe { (*ipv4hdr).tot_len });
    let source_port = match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)? };
            u16::from_be(unsafe { (*tcphdr).source })
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr = unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)? };
            u16::from_be(unsafe { (*udphdr).source })
        }
        _ => return Err(()),
    };

    let action_str = if block_ip(source) {
        "DROP"
    } else {
        "PASS"
    };
    info!(&ctx, "SRC: {:i},SRC PORT: {}, DEST: {:i}, ACTION: {}, SIZE: {}", source, source_port, dst, action_str, size);

    let action = if block_ip(source) {
        xdp_action::XDP_DROP
    } else {
        xdp_action::XDP_PASS
    };

    Ok(action)
}
