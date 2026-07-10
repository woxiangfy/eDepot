use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::error::Result;
use crate::event::NetworkEvent;

pub mod error;
pub use error::Error;

pub mod event_source;
pub use event_source::{EventSource, EventSourceBuilder, EventSourceType};

pub mod proc_net_source;
#[cfg(feature = "ebpf")]
pub mod ebpf_source;
#[cfg(feature = "ebpf")]
pub mod hybrid_source;

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
    event_source: Option<Box<dyn EventSource>>,
}

impl Collector {
    pub async fn new(tx: mpsc::Sender<NetworkEvent>) -> Result<Self> {
        debug!("Creating collector without event source");
        info!("Collector created");
        Ok(Self { tx, event_source: None })
    }

    pub async fn with_event_source(
        tx: mpsc::Sender<NetworkEvent>,
        source_type: EventSourceType,
        interface: Option<&str>,
        poll_interval_ms: u64,
    ) -> Result<Self> {
        debug!("Creating collector with event source: {}", source_type);
        let event_source = EventSourceBuilder::new(source_type)
            .interface(interface.unwrap_or(""))
            .poll_interval_ms(poll_interval_ms)
            .build()
            .await?;

        info!("Collector created with event source: {}", event_source.name());
        Ok(Self {
            tx,
            event_source: Some(event_source),
        })
    }

    pub async fn start_event_loop(&self) -> Result<()> {
        if let Some(event_source) = &self.event_source {
            debug!("Starting event loop with source: {}", event_source.name());
            event_source.start(self.tx.clone()).await?;
            info!("Event loop started with source: {}", event_source.name());
        } else {
            info!("No event source configured, running in stub mode");
            debug!("Collector has no event source, event loop in stub mode");
        }

        Ok(())
    }

    pub async fn send_test_event(&self, event: NetworkEvent) -> Result<()> {
        debug!(
            "Sending test event: {} -> port {} (proto {})",
            event.src_ip, event.dst_port, event.protocol
        );
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
    use std::str::FromStr;
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
    async fn test_collector_with_event_source_procnet() {
        let (tx, _rx) = mpsc::channel(100);
        let collector = Collector::with_event_source(
            tx,
            EventSourceType::ProcNet,
            None,
            1000,
        )
        .await;

        assert!(collector.is_ok());
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
    async fn test_collector_start_event_loop_no_source() {
        let (tx, _rx) = mpsc::channel(100);
        let collector = Collector::new(tx).await.unwrap();

        let result = collector.start_event_loop().await;

        assert!(result.is_ok());
    }

    #[test]
    fn test_event_source_type_from_str() {
        assert_eq!(
            EventSourceType::from_str("ebpf"),
            Ok(EventSourceType::Ebpf)
        );
        assert_eq!(
            EventSourceType::from_str("procnet"),
            Ok(EventSourceType::ProcNet)
        );
        assert_eq!(
            EventSourceType::from_str("hybrid"),
            Ok(EventSourceType::Hybrid)
        );
        assert!(EventSourceType::from_str("invalid").is_err());
    }

    #[test]
    fn test_event_source_type_display() {
        assert_eq!(format!("{}", EventSourceType::Ebpf), "ebpf");
        assert_eq!(format!("{}", EventSourceType::ProcNet), "procnet");
        assert_eq!(format!("{}", EventSourceType::Hybrid), "hybrid");
    }
}