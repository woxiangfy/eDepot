use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::error::Result;
use crate::event::NetworkEvent;

pub mod error;
pub use error::Error;

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct NetworkEventRaw {
    pub family: u8,
    pub src_ip: [u8; 16],
    pub dst_port: u16,
    pub protocol: u8,
    pub _pad: u8,
    pub timestamp: u64,
}

impl NetworkEventRaw {
    pub fn new(family: u8, src_ip: [u8; 16], dst_port: u16, protocol: u8, timestamp: u64) -> Self {
        Self {
            family,
            src_ip,
            dst_port,
            protocol,
            _pad: 0,
            timestamp,
        }
    }

    pub fn to_network_event(&self) -> NetworkEvent {
        let src_ip = if self.family == 2 {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&self.src_ip[0..4]);
            IpAddr::V4(Ipv4Addr::from(bytes))
        } else {
            IpAddr::V6(Ipv6Addr::from(self.src_ip))
        };

        NetworkEvent::new(
            self.family,
            src_ip,
            u16::from_be(self.dst_port),
            self.protocol,
            self.timestamp,
        )
    }

    pub fn is_ipv4(&self) -> bool {
        self.family == 2
    }

    pub fn is_ipv6(&self) -> bool {
        self.family == 10
    }
}

pub struct Collector {
    tx: mpsc::Sender<NetworkEvent>,
    #[cfg(feature = "ebpf")]
    bpf: Option<aya::Bpf>,
}

impl Collector {
    pub async fn new(tx: mpsc::Sender<NetworkEvent>) -> Result<Self> {
        #[cfg(feature = "ebpf")]
        {
            debug!("Loading eBPF bytes from BPF_OBJECT");
            let bpf_bytes = include_bytes!(env!("BPF_OBJECT"));
            debug!("eBPF bytes size: {} bytes", bpf_bytes.len());

            let bpf = if bpf_bytes.is_empty() {
                debug!("eBPF bytes are empty, running without eBPF");
                None
            } else {
                debug!("Loading eBPF program from bytes");
                let loaded_bpf = aya::Bpf::load(bpf_bytes)?;
                debug!("eBPF program loaded successfully");
                Some(loaded_bpf)
            };

            info!("Collector created with eBPF support");
            Ok(Self { tx, bpf })
        }

        #[cfg(not(feature = "ebpf"))]
        {
            debug!("eBPF feature not enabled, creating collector without eBPF");
            info!("Collector created (eBPF disabled)");
            Ok(Self { tx })
        }
    }

    pub async fn load_tracepoint(&mut self) -> Result<()> {
        #[cfg(feature = "ebpf")]
        {
            if let Some(bpf) = &mut self.bpf {
                debug!("Loading tracepoint program: inet_sock_set_state");
                let tracepoint = bpf
                    .program_mut("inet_sock_set_state")
                    .ok_or(Error::ProgramNotFound("inet_sock_set_state"))?;
                debug!("Found tracepoint program, loading...");
                tracepoint.load()?;
                debug!("Tracepoint program loaded, attaching...");
                tracepoint.attach()?;
                info!("Loaded tracepoint: inet_sock_set_state");
                debug!("Tracepoint attached successfully");
            } else {
                info!("eBPF not available, tracepoint skipped");
                debug!("No eBPF object available for tracepoint");
            }
        }

        #[cfg(not(feature = "ebpf"))]
        {
            info!("eBPF feature disabled, tracepoint skipped");
            debug!("eBPF feature not enabled, skipping tracepoint");
        }

        Ok(())
    }

    pub async fn load_xdp(&mut self, interface: &str) -> Result<()> {
        #[cfg(feature = "ebpf")]
        {
            if let Some(bpf) = &mut self.bpf {
                debug!("Loading XDP program on interface: {}", interface);
                let xdp = bpf
                    .program_mut("xdp_syn_filter")
                    .ok_or(Error::ProgramNotFound("xdp_syn_filter"))?;
                debug!("Found XDP program, loading...");
                xdp.load()?;
                debug!("XDP program loaded, attaching to interface...");
                xdp.attach(interface, aya::programs::XdpFlags::default())?;
                info!("Attached XDP program to interface: {}", interface);
                debug!("XDP program attached successfully to {}", interface);
            } else {
                info!("eBPF not available, XDP skipped");
                debug!("No eBPF object available for XDP on {}", interface);
            }
        }

        #[cfg(not(feature = "ebpf"))]
        {
            info!("eBPF feature disabled, XDP skipped for {}", interface);
            debug!("eBPF feature not enabled, skipping XDP on {}", interface);
        }

        Ok(())
    }

    pub async fn start_event_loop(&self) -> Result<()> {
        #[cfg(feature = "ebpf")]
        {
            use aya::maps::perf::AsyncPerfEventArray;
            use std::mem;

            if let Some(bpf) = &self.bpf {
                debug!("Setting up event loop with eBPF");
                let events_map = bpf.map("EVENTS").ok_or(Error::MapNotFound("EVENTS"))?;
                debug!("Found EVENTS map, creating AsyncPerfEventArray");

                let mut events = AsyncPerfEventArray::try_from(events_map)?;
                debug!("AsyncPerfEventArray created");

                let tx = self.tx.clone();
                let cpu_count = aya::util::online_cpus().unwrap().len();
                debug!("Spawning event readers for {} CPUs", cpu_count);

                for cpu in 0..cpu_count {
                    let mut buf = events.open(cpu, None, None)?;
                    let tx = tx.clone();

                    tokio::task::spawn(async move {
                        debug!("Event reader for CPU {} started", cpu);
                        let mut buffers = vec![0u8; 4096];

                        loop {
                            let events = buf.read_events(&mut buffers).await;
                            match events {
                                Ok(read) => {
                                    debug!("CPU {}: read {} events", cpu, read.read);
                                    for i in 0..read.read {
                                        let offset = i * mem::size_of::<NetworkEventRaw>();
                                        if offset + mem::size_of::<NetworkEventRaw>() <= read.read {
                                            let raw: &NetworkEventRaw = unsafe {
                                                &*(buffers.as_ptr().add(offset)
                                                    as *const NetworkEventRaw)
                                            };
                                            let event = raw.to_network_event();
                                            debug!(
                                                "CPU {}: event from {} port {} protocol {}",
                                                cpu, event.src_ip, event.dst_port, event.protocol
                                            );
                                            if tx.send(event).await.is_err() {
                                                debug!("Event channel closed, exiting event loop for CPU {}", cpu);
                                                break;
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!("Perf event read error on CPU {}: {}", cpu, e);
                                    break;
                                }
                            }
                        }
                        debug!("Event reader for CPU {} exited", cpu);
                    });
                }

                info!("Event loop started");
                debug!("Event loop fully initialized");
            } else {
                info!("eBPF not available, event loop running in stub mode");
                debug!("No eBPF object, event loop in stub mode");
            }
        }

        #[cfg(not(feature = "ebpf"))]
        {
            info!("eBPF feature disabled, event loop running in stub mode");
            debug!("eBPF feature not enabled, event loop in stub mode");
        }

        Ok(())
    }

    pub async fn send_test_event(&self, event: NetworkEvent) -> Result<()> {
        debug!("Sending test event: {} -> port {} (proto {})", event.src_ip, event.dst_port, event.protocol);
        self.tx.send(event).await.map_err(|e| {
            warn!("Failed to send event: {}", e);
            crate::error::Error::ChannelSendFailed
        })?;
        debug!("Test event sent successfully");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    #[test]
    fn test_network_event_raw_new() {
        let src_ip: [u8; 16] = [192, 168, 1, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let raw = NetworkEventRaw::new(2, src_ip, 0x0016, 6, 1234567890);

        assert_eq!(raw.family, 2);
        assert_eq!(raw.src_ip, src_ip);
        assert_eq!(raw.dst_port, 0x0016);
        assert_eq!(raw.protocol, 6);
        assert_eq!(raw.timestamp, 1234567890);
    }

    #[test]
    fn test_to_network_event_ipv4() {
        let src_ip: [u8; 16] = [192, 168, 1, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let raw = NetworkEventRaw::new(2, src_ip, u16::to_be(22), 6, 1234567890);

        let event = raw.to_network_event();

        assert_eq!(event.family, 2);
        assert_eq!(event.src_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
        assert_eq!(event.dst_port, 22);
        assert_eq!(event.protocol, 6);
        assert_eq!(event.timestamp, 1234567890);
    }

    #[test]
    fn test_to_network_event_ipv6() {
        let src_ip: [u8; 16] = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        let raw = NetworkEventRaw::new(10, src_ip, u16::to_be(80), 6, 1234567890);

        let event = raw.to_network_event();

        assert_eq!(event.family, 10);
        assert_eq!(
            event.src_ip,
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
        );
        assert_eq!(event.dst_port, 80);
        assert_eq!(event.protocol, 6);
    }

    #[test]
    fn test_is_ipv4() {
        let ipv4_raw = NetworkEventRaw::new(2, [0u8; 16], 0, 0, 0);
        let ipv6_raw = NetworkEventRaw::new(10, [0u8; 16], 0, 0, 0);

        assert!(ipv4_raw.is_ipv4());
        assert!(!ipv6_raw.is_ipv4());
    }

    #[test]
    fn test_is_ipv6() {
        let ipv4_raw = NetworkEventRaw::new(2, [0u8; 16], 0, 0, 0);
        let ipv6_raw = NetworkEventRaw::new(10, [0u8; 16], 0, 0, 0);

        assert!(!ipv4_raw.is_ipv6());
        assert!(ipv6_raw.is_ipv6());
    }

    #[test]
    fn test_network_event_raw_partial_eq() {
        let src_ip1: [u8; 16] = [192, 168, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let src_ip2: [u8; 16] = [192, 168, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        let raw1 = NetworkEventRaw::new(2, src_ip1, 0x0016, 6, 0);
        let raw2 = NetworkEventRaw::new(2, src_ip1, 0x0016, 6, 0);
        let raw3 = NetworkEventRaw::new(2, src_ip2, 0x0016, 6, 0);

        assert_eq!(raw1, raw2);
        assert_ne!(raw1, raw3);
    }

    #[tokio::test]
    async fn test_collector_new() {
        let (tx, _rx) = mpsc::channel(100);
        let collector = Collector::new(tx).await;

        assert!(collector.is_ok());
    }

    #[tokio::test]
    async fn test_collector_load_tracepoint() {
        let (tx, _rx) = mpsc::channel(100);
        let mut collector = Collector::new(tx).await.unwrap();

        let result = collector.load_tracepoint().await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_collector_load_xdp() {
        let (tx, _rx) = mpsc::channel(100);
        let mut collector = Collector::new(tx).await.unwrap();

        let result = collector.load_xdp("eth0").await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_collector_send_test_event() {
        let (tx, mut rx) = mpsc::channel(100);
        let collector = Collector::new(tx).await.unwrap();

        let test_event = NetworkEvent::new(
            2,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            22,
            6,
            1234567890,
        );

        let send_result = collector.send_test_event(test_event.clone()).await;

        assert!(send_result.is_ok());

        let received_event = rx.recv().await;

        assert!(received_event.is_some());
        assert_eq!(received_event.unwrap(), test_event);
    }

    #[tokio::test]
    async fn test_collector_start_event_loop() {
        let (tx, _rx) = mpsc::channel(100);
        let collector = Collector::new(tx).await.unwrap();

        let result = collector.start_event_loop().await;

        assert!(result.is_ok());
    }
}
