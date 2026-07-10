use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::SystemTime;

use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};
use tracing::{debug, error, info, warn};

use crate::error::Result;
use crate::event::NetworkEvent;

pub mod error;
pub use error::Error;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ConnectionKey {
    src_ip: IpAddr,
    dst_port: u16,
    protocol: u8,
}

pub struct Collector {
    tx: mpsc::Sender<NetworkEvent>,
    poll_interval_ms: u64,
    previous_connections: HashSet<ConnectionKey>,
}

impl Collector {
    pub async fn new(tx: mpsc::Sender<NetworkEvent>, poll_interval_ms: u64) -> Result<Self> {
        debug!(
            "Creating collector with {}ms polling interval",
            poll_interval_ms
        );
        info!("Collector created");
        Ok(Self {
            tx,
            poll_interval_ms,
            previous_connections: HashSet::new(),
        })
    }

    pub async fn start_event_loop(&mut self) -> Result<()> {
        info!(
            "Starting /proc/net event loop with {}ms polling interval",
            self.poll_interval_ms
        );
        debug!("Polling /proc/net/tcp, /proc/net/tcp6, /proc/net/udp, /proc/net/udp6");

        loop {
            if let Err(e) = self.poll_once().await {
                error!("Error polling /proc/net: {}", e);
            }

            sleep(Duration::from_millis(self.poll_interval_ms)).await;
        }
    }

    async fn poll_once(&mut self) -> Result<()> {
        let mut new_connections = HashSet::new();

        self.process_proc_file("/proc/net/tcp", 6, &mut new_connections)
            .await?;
        self.process_proc_file("/proc/net/tcp6", 6, &mut new_connections)
            .await?;
        self.process_proc_file("/proc/net/udp", 17, &mut new_connections)
            .await?;
        self.process_proc_file("/proc/net/udp6", 17, &mut new_connections)
            .await?;

        self.previous_connections = new_connections;
        Ok(())
    }

    async fn process_proc_file(
        &self,
        path: &str,
        protocol: u8,
        new_connections: &mut HashSet<ConnectionKey>,
    ) -> Result<()> {
        let file = match File::open(path) {
            Ok(f) => f,
            Err(e) => {
                debug!("Could not open {}: {}", path, e);
                return Ok(());
            }
        };

        let reader = BufReader::new(file);
        let mut line_num = 0;

        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(e) => {
                    warn!("Error reading line from {}: {}", path, e);
                    continue;
                }
            };

            line_num += 1;
            if line_num == 1 {
                continue;
            }

            if let Some(event) = self.parse_line(&line, protocol) {
                let key = ConnectionKey {
                    src_ip: event.src_ip,
                    dst_port: event.dst_port,
                    protocol: event.protocol,
                };

                new_connections.insert(key.clone());

                if !self.previous_connections.contains(&key) {
                    debug!(
                        "New connection from {}: {} -> port {} (proto {})",
                        path, event.src_ip, event.dst_port, event.protocol
                    );
                    if self.tx.send(event).await.is_err() {
                        warn!("Failed to send event to channel");
                    }
                }
            }
        }

        Ok(())
    }

    fn parse_line(&self, line: &str, protocol: u8) -> Option<NetworkEvent> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            return None;
        }

        let local_address = parts[1];
        let remote_address = parts[2];

        let (_local_ip, local_port) = match self.parse_address(local_address) {
            Some(ip_port) => ip_port,
            None => {
                debug!("Failed to parse local address: {}", local_address);
                return None;
            }
        };

        let (remote_ip, _) = match self.parse_address(remote_address) {
            Some(ip_port) => ip_port,
            None => {
                debug!("Failed to parse remote address: {}", remote_address);
                return None;
            }
        };

        let family = if remote_ip.is_ipv4() { 2u8 } else { 10u8 };
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        Some(NetworkEvent::new(
            family, remote_ip, local_port, protocol, timestamp,
        ))
    }

    fn parse_address(&self, address: &str) -> Option<(IpAddr, u16)> {
        let parts: Vec<&str> = address.split(':').collect();
        if parts.len() != 2 {
            return None;
        }

        let ip_hex = parts[0];
        let port_hex = parts[1];

        let port = match u16::from_str_radix(port_hex, 16) {
            Ok(p) => p,
            Err(e) => {
                debug!("Failed to parse port {}: {}", port_hex, e);
                return None;
            }
        };

        if ip_hex.len() == 8 {
            let ip = self.parse_ipv4(ip_hex);
            ip.map(|ip| (IpAddr::V4(ip), port))
        } else if ip_hex.len() == 32 {
            let ip = self.parse_ipv6(ip_hex);
            ip.map(|ip| (IpAddr::V6(ip), port))
        } else {
            debug!("Unknown address format: {}", ip_hex);
            None
        }
    }

    fn parse_ipv4(&self, hex: &str) -> Option<Ipv4Addr> {
        let bytes: Vec<u8> = (0..4)
            .map(|i| {
                let start = i * 2;
                let end = start + 2;
                u8::from_str_radix(&hex[start..end], 16).unwrap_or(0)
            })
            .collect();

        if bytes.len() == 4 {
            Some(Ipv4Addr::new(bytes[3], bytes[2], bytes[1], bytes[0]))
        } else {
            None
        }
    }

    fn parse_ipv6(&self, hex: &str) -> Option<Ipv6Addr> {
        let mut segments: Vec<u16> = Vec::with_capacity(8);

        for i in 0..8 {
            let start = i * 4;
            let end = start + 4;
            if end > hex.len() {
                return None;
            }

            let seg = match u16::from_str_radix(&hex[start..end], 16) {
                Ok(s) => s,
                Err(e) => {
                    debug!("Failed to parse IPv6 segment {}: {}", &hex[start..end], e);
                    return None;
                }
            };

            let reversed = ((seg & 0xFF) << 8) | ((seg >> 8) & 0xFF);
            segments.push(reversed);
        }

        let segments_array: [u16; 8] = segments.try_into().ok()?;
        Some(Ipv6Addr::from(segments_array))
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
    use tokio::sync::mpsc;

    #[test]
    fn test_parse_ipv4() {
        let collector = Collector {
            tx: mpsc::channel(100).0,
            poll_interval_ms: 1000,
            previous_connections: HashSet::new(),
        };
        let ip = collector.parse_ipv4("0101A8C0");

        assert_eq!(ip, Some(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn test_parse_ipv6() {
        let collector = Collector {
            tx: mpsc::channel(100).0,
            poll_interval_ms: 1000,
            previous_connections: HashSet::new(),
        };
        let ip = collector.parse_ipv6("00000000000000000000000000000100");

        assert_eq!(ip, Some(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)));
    }

    #[test]
    fn test_parse_address_ipv4() {
        let collector = Collector {
            tx: mpsc::channel(100).0,
            poll_interval_ms: 1000,
            previous_connections: HashSet::new(),
        };
        let result = collector.parse_address("0101A8C0:0016");

        assert_eq!(
            result,
            Some((IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 22))
        );
    }

    #[test]
    fn test_parse_address_ipv6() {
        let collector = Collector {
            tx: mpsc::channel(100).0,
            poll_interval_ms: 1000,
            previous_connections: HashSet::new(),
        };
        let result = collector.parse_address("00000000000000000000000000000100:0050");

        assert_eq!(
            result,
            Some((IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 80))
        );
    }

    #[test]
    fn test_parse_line() {
        let collector = Collector {
            tx: mpsc::channel(100).0,
            poll_interval_ms: 1000,
            previous_connections: HashSet::new(),
        };
        let line = "  1: C0A80101:0016 0101017F:0050 01 00000000:00000000 00:00000000 00000000";
        let event = collector.parse_line(line, 6);

        assert!(event.is_some());
        let event = event.unwrap();
        assert_eq!(event.src_ip, IpAddr::V4(Ipv4Addr::new(127, 1, 1, 1)));
        assert_eq!(event.dst_port, 22);
        assert_eq!(event.protocol, 6);
    }

    #[test]
    fn test_connection_key() {
        let key1 = ConnectionKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            dst_port: 22,
            protocol: 6,
        };
        let key2 = ConnectionKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            dst_port: 22,
            protocol: 6,
        };
        let key3 = ConnectionKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            dst_port: 22,
            protocol: 6,
        };

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }

    #[tokio::test]
    async fn test_collector_new() {
        let (tx, _rx) = mpsc::channel(100);
        let collector = Collector::new(tx, 1000).await;

        assert!(collector.is_ok());
    }

    #[tokio::test]
    async fn test_collector_send_test_event() {
        let (tx, mut rx) = mpsc::channel(100);
        let collector = Collector::new(tx, 1000).await.unwrap();

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
}
