#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{HashMap, PerfEventArray},
    programs::XdpContext,
};
use aya_log_ebpf::info;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct NetworkEvent {
    pub family: u8,
    pub src_ip: [u8; 16],
    pub dst_port: u16,
    pub protocol: u8,
    pub _pad: u8,
    pub timestamp: u64,
}

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<NetworkEvent> = PerfEventArray::with_max_entries(4096, 0);

#[map(name = "SYN_COUNT")]
static mut SYN_COUNT: HashMap<u32, u32> = HashMap::with_max_entries(65536, 0);

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const ETH_HDR_LEN: usize = 14;

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

#[xdp(name = "xdp_syn_filter")]
pub fn xdp_syn_filter(ctx: XdpContext) -> u32 {
    match try_xdp_syn_filter(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_xdp_syn_filter(ctx: &XdpContext) -> Result<u32, ()> {
    let eth_proto: u16 = unsafe { *ptr_at(ctx, ETH_HDR_LEN - 2)? };

    let protocol: u8;
    let mut event = NetworkEvent {
        family: 0,
        src_ip: [0u8; 16],
        dst_port: 0,
        protocol: 0,
        _pad: 0,
        timestamp: 0,
    };
    let mut src_ip_u32: u32 = 0;
    let ip_hdr_len: usize;

    match eth_proto.to_be() {
        ETH_P_IP => {
            let version_ihl: u8 = unsafe { *ptr_at(ctx, ETH_HDR_LEN)? };
            let ihl = (version_ihl & 0x0f) as usize * 4;
            ip_hdr_len = ihl;
            protocol = unsafe { *ptr_at(ctx, ETH_HDR_LEN + 9)? };
            let saddr: u32 = unsafe { *ptr_at(ctx, ETH_HDR_LEN + 12)? };
            let daddr: u32 = unsafe { *ptr_at(ctx, ETH_HDR_LEN + 16)? };
            src_ip_u32 = saddr;
            event.family = AF_INET;
            event.src_ip[0..4].copy_from_slice(&saddr.to_be_bytes());
            let _ = daddr;
        }
        ETH_P_IPV6 => {
            ip_hdr_len = 40;
            protocol = unsafe { *ptr_at(ctx, ETH_HDR_LEN + 6)? };
            let saddr: [u8; 16] = unsafe { *ptr_at(ctx, ETH_HDR_LEN + 8)? };
            event.family = AF_INET6;
            event.src_ip = saddr;
        }
        _ => return Ok(xdp_action::XDP_PASS),
    }

    event.protocol = protocol;

    if protocol != IPPROTO_TCP {
        return Ok(xdp_action::XDP_PASS);
    }

    let tcp_base = ETH_HDR_LEN + ip_hdr_len;
    let src_port: u16 = unsafe { *ptr_at(ctx, tcp_base)? };
    let dst_port: u16 = unsafe { *ptr_at(ctx, tcp_base + 2)? };
    let tcp_flags: u8 = unsafe { *ptr_at(ctx, tcp_base + 13)? };
    let _ = src_port;

    event.dst_port = dst_port;

    let syn = (tcp_flags & 0x02) != 0;
    let ack = (tcp_flags & 0x10) != 0;

    if syn && !ack {
        unsafe {
            let count = SYN_COUNT.get(&src_ip_u32).copied().unwrap_or(0);
            let new_count = count.saturating_add(1);
            SYN_COUNT.insert(&src_ip_u32, &new_count, 0);

            if new_count > 1000 {
                info!(ctx, "Dropping SYN flood from {:i}", src_ip_u32);
                return Ok(xdp_action::XDP_DROP);
            }
        }

        unsafe {
            EVENTS.output(ctx, &event, 0);
        }
    }

    Ok(xdp_action::XDP_PASS)
}

unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = core::mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
