use std::net::IpAddr;
use std::sync::Arc;

use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::config::Config;
use crate::error::Result;
use crate::event::NetworkEvent;

pub mod error;
pub use error::Error;

pub struct Dispatcher {
    config: Arc<Config>,
    worker_senders: Vec<mpsc::Sender<NetworkEvent>>,
}

impl Dispatcher {
    /// 创建新的事件分发器
    ///
    /// # 参数
    ///
    /// * `config` - 配置（包含白名单）
    /// * `worker_senders` - Worker 的发送通道列表
    pub fn new(config: Arc<Config>, worker_senders: Vec<mpsc::Sender<NetworkEvent>>) -> Self {
        Self {
            config,
            worker_senders,
        }
    }

    /// 运行分发器主循环
    ///
    /// 从接收通道获取事件，进行白名单过滤后分发给对应的 Worker
    ///
    /// # 参数
    ///
    /// * `rx` - 事件接收通道
    pub async fn run(&self, mut rx: mpsc::Receiver<NetworkEvent>) -> Result<()> {
        info!("Dispatcher started");

        while let Some(event) = rx.recv().await {
            if self.is_whitelisted(&event.src_ip) {
                debug!("Whitelisted IP skipped: {}", event.src_ip);
                continue;
            }

            let worker_idx = self.select_worker(&event);
            if let Err(e) = self.worker_senders[worker_idx].send(event).await {
                warn!("Failed to send event to worker {}: {}", worker_idx, e);
            }
        }

        info!("Dispatcher stopped");
        Ok(())
    }

    /// 检查 IP 是否在白名单中
    fn is_whitelisted(&self, ip: &IpAddr) -> bool {
        self.config.is_whitelisted(ip)
    }

    /// 根据事件选择目标 Worker
    ///
    /// 使用 FNV-1a 哈希算法对源 IP 进行哈希，确保同一 IP 的事件总是发送到同一个 Worker，
    /// 同时保证分布更均匀。
    ///
    /// # 参数
    ///
    /// * `event` - 网络事件
    ///
    /// # 返回值
    ///
    /// 返回 Worker 的索引
    fn select_worker(&self, event: &NetworkEvent) -> usize {
        let mut hash: u64 = 0xcbf29ce484222325;

        match event.src_ip {
            IpAddr::V4(ip) => {
                for &byte in ip.octets().iter() {
                    hash ^= byte as u64;
                    hash = hash.wrapping_mul(0x100000001b3);
                }
            }
            IpAddr::V6(ip) => {
                for &byte in ip.octets().iter() {
                    hash ^= byte as u64;
                    hash = hash.wrapping_mul(0x100000001b3);
                }
            }
        }

        (hash % self.worker_senders.len() as u64) as usize
    }

    /// 获取 Worker 数量
    pub fn worker_count(&self) -> usize {
        self.worker_senders.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;
    use tokio::sync::mpsc;

    #[test]
    fn test_new() {
        let config = Arc::new(Config {
            global: crate::config::GlobalConfig {
                worker_count: 4,
                nft_table: "edepot".to_string(),
                log_level: "info".to_string(),
                poll_interval_ms: 1000,
            },
            whitelist: crate::config::WhitelistConfig { cidr: Vec::new() },
            rules: Vec::new(),
            memory: crate::config::MemoryConfig {
                max_entries: 100000,
                cleanup_interval: 60,
            },
        });

        let (tx1, _rx1) = mpsc::channel(100);
        let (tx2, _rx2) = mpsc::channel(100);
        let worker_senders = vec![tx1, tx2];

        let dispatcher = Dispatcher::new(config, worker_senders);

        assert_eq!(dispatcher.worker_count(), 2);
    }

    #[test]
    fn test_select_worker_ipv4() {
        let config = Arc::new(Config {
            global: crate::config::GlobalConfig {
                worker_count: 4,
                nft_table: "edepot".to_string(),
                log_level: "info".to_string(),
                poll_interval_ms: 1000,
            },
            whitelist: crate::config::WhitelistConfig { cidr: Vec::new() },
            rules: Vec::new(),
            memory: crate::config::MemoryConfig {
                max_entries: 100000,
                cleanup_interval: 60,
            },
        });

        let (tx1, _rx1) = mpsc::channel(100);
        let (tx2, _rx2) = mpsc::channel(100);
        let (tx3, _rx3) = mpsc::channel(100);
        let worker_senders = vec![tx1, tx2, tx3];

        let dispatcher = Dispatcher::new(config, worker_senders);

        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101));

        let event1 = NetworkEvent::new(2, ip1, 22, 6, 0);
        let event2 = NetworkEvent::new(2, ip1, 22, 6, 0);
        let event3 = NetworkEvent::new(2, ip2, 22, 6, 0);

        let idx1 = dispatcher.select_worker(&event1);
        let idx2 = dispatcher.select_worker(&event2);
        let idx3 = dispatcher.select_worker(&event3);

        assert_eq!(idx1, idx2);
        assert!(idx1 < 3);
        assert!(idx3 < 3);
    }

    #[test]
    fn test_select_worker_ipv6() {
        let config = Arc::new(Config {
            global: crate::config::GlobalConfig {
                worker_count: 4,
                nft_table: "edepot".to_string(),
                log_level: "info".to_string(),
                poll_interval_ms: 1000,
            },
            whitelist: crate::config::WhitelistConfig { cidr: Vec::new() },
            rules: Vec::new(),
            memory: crate::config::MemoryConfig {
                max_entries: 100000,
                cleanup_interval: 60,
            },
        });

        let (tx1, _rx1) = mpsc::channel(100);
        let (tx2, _rx2) = mpsc::channel(100);
        let worker_senders = vec![tx1, tx2];

        let dispatcher = Dispatcher::new(config, worker_senders);

        let ip1 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let ip2 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2));

        let event1 = NetworkEvent::new(10, ip1, 80, 6, 0);
        let event2 = NetworkEvent::new(10, ip1, 80, 6, 0);
        let event3 = NetworkEvent::new(10, ip2, 80, 6, 0);

        let idx1 = dispatcher.select_worker(&event1);
        let idx2 = dispatcher.select_worker(&event2);
        let idx3 = dispatcher.select_worker(&event3);

        assert_eq!(idx1, idx2);
        assert!(idx1 < 2);
        assert!(idx3 < 2);
    }

    #[test]
    fn test_is_whitelisted() {
        let config = Arc::new(Config {
            global: crate::config::GlobalConfig {
                worker_count: 4,
                nft_table: "edepot".to_string(),
                log_level: "info".to_string(),
                poll_interval_ms: 1000,
            },
            whitelist: crate::config::WhitelistConfig {
                cidr: vec!["127.0.0.0/8".to_string(), "::1/128".to_string()],
            },
            rules: Vec::new(),
            memory: crate::config::MemoryConfig {
                max_entries: 100000,
                cleanup_interval: 60,
            },
        });

        let (tx, _rx) = mpsc::channel(100);
        let worker_senders = vec![tx];

        let dispatcher = Dispatcher::new(config, worker_senders);

        let whitelisted_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let non_whitelisted_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let whitelisted_ipv6 = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));

        assert!(dispatcher.is_whitelisted(&whitelisted_ip));
        assert!(!dispatcher.is_whitelisted(&non_whitelisted_ip));
        assert!(dispatcher.is_whitelisted(&whitelisted_ipv6));
    }

    #[tokio::test]
    async fn test_run_with_whitelist() {
        let config = Arc::new(Config {
            global: crate::config::GlobalConfig {
                worker_count: 1,
                nft_table: "edepot".to_string(),
                log_level: "info".to_string(),
                poll_interval_ms: 1000,
            },
            whitelist: crate::config::WhitelistConfig {
                cidr: vec!["127.0.0.0/8".to_string()],
            },
            rules: Vec::new(),
            memory: crate::config::MemoryConfig {
                max_entries: 100000,
                cleanup_interval: 60,
            },
        });

        let (worker_tx, mut worker_rx) = mpsc::channel(100);
        let worker_senders = vec![worker_tx];

        let (dispatcher_tx, dispatcher_rx) = mpsc::channel(100);
        let dispatcher = Dispatcher::new(config, worker_senders);

        tokio::spawn(async move {
            let _ = dispatcher.run(dispatcher_rx).await;
        });

        let whitelisted_event =
            NetworkEvent::new(2, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 22, 6, 0);
        let non_whitelisted_event =
            NetworkEvent::new(2, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 22, 6, 0);

        dispatcher_tx.send(whitelisted_event).await.unwrap();
        dispatcher_tx
            .send(non_whitelisted_event.clone())
            .await
            .unwrap();

        drop(dispatcher_tx);

        let received_event = worker_rx.recv().await;

        assert!(received_event.is_some());
        assert_eq!(received_event.unwrap(), non_whitelisted_event);
    }

    #[tokio::test]
    async fn test_run_distribution() {
        let config = Arc::new(Config {
            global: crate::config::GlobalConfig {
                worker_count: 2,
                nft_table: "edepot".to_string(),
                log_level: "info".to_string(),
                poll_interval_ms: 1000,
            },
            whitelist: crate::config::WhitelistConfig { cidr: Vec::new() },
            rules: Vec::new(),
            memory: crate::config::MemoryConfig {
                max_entries: 100000,
                cleanup_interval: 60,
            },
        });

        let (worker_tx1, mut worker_rx1) = mpsc::channel(100);
        let (worker_tx2, mut worker_rx2) = mpsc::channel(100);
        let worker_senders = vec![worker_tx1, worker_tx2];

        let (dispatcher_tx, dispatcher_rx) = mpsc::channel(100);
        let dispatcher = Dispatcher::new(config, worker_senders);

        tokio::spawn(async move {
            let _ = dispatcher.run(dispatcher_rx).await;
        });

        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        let event1 = NetworkEvent::new(2, ip1, 22, 6, 0);
        let event2 = NetworkEvent::new(2, ip1, 22, 6, 0);
        let event3 = NetworkEvent::new(2, ip2, 80, 6, 0);

        dispatcher_tx.send(event1.clone()).await.unwrap();
        dispatcher_tx.send(event2.clone()).await.unwrap();
        dispatcher_tx.send(event3.clone()).await.unwrap();

        drop(dispatcher_tx);

        let mut received_events_worker1 = Vec::new();
        let mut received_events_worker2 = Vec::new();

        while let Some(event) = worker_rx1.recv().await {
            received_events_worker1.push(event);
        }

        while let Some(event) = worker_rx2.recv().await {
            received_events_worker2.push(event);
        }

        assert_eq!(
            received_events_worker1.len() + received_events_worker2.len(),
            3
        );
        assert!(
            received_events_worker1.contains(&event1) == received_events_worker1.contains(&event2)
        );
        assert!(
            received_events_worker2.contains(&event1) == received_events_worker2.contains(&event2)
        );
    }

    #[test]
    fn test_worker_count() {
        let config = Arc::new(Config {
            global: crate::config::GlobalConfig {
                worker_count: 4,
                nft_table: "edepot".to_string(),
                log_level: "info".to_string(),
                poll_interval_ms: 1000,
            },
            whitelist: crate::config::WhitelistConfig { cidr: Vec::new() },
            rules: Vec::new(),
            memory: crate::config::MemoryConfig {
                max_entries: 100000,
                cleanup_interval: 60,
            },
        });

        let (tx1, _rx1) = mpsc::channel(100);
        let (tx2, _rx2) = mpsc::channel(100);
        let (tx3, _rx3) = mpsc::channel(100);
        let worker_senders = vec![tx1, tx2, tx3];

        let dispatcher = Dispatcher::new(config, worker_senders);

        assert_eq!(dispatcher.worker_count(), 3);
    }
}
