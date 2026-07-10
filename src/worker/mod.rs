use std::sync::Arc;
use std::time::Instant;

use tokio::sync::mpsc;
use tracing::{debug, info};

use crate::config::Config;
use crate::error::Result;
use crate::event::NetworkEvent;
use crate::rules::RuleEngine;

pub mod error;
pub use error::Error;

pub struct Worker {
    id: usize,
    config: Arc<Config>,
    rule_engine: RuleEngine,
    rx: mpsc::Receiver<NetworkEvent>,
}

impl Worker {
    /// 创建新的 Worker
    ///
    /// # 参数
    ///
    /// * `id` - Worker 标识符
    /// * `config` - 配置
    /// * `rule_engine` - 规则引擎
    /// * `rx` - 事件接收通道
    pub fn new(
        id: usize,
        config: Arc<Config>,
        rule_engine: RuleEngine,
        rx: mpsc::Receiver<NetworkEvent>,
    ) -> Self {
        Self {
            id,
            config,
            rule_engine,
            rx,
        }
    }

    /// 运行 Worker 主循环
    ///
    /// 从通道接收事件并评估规则，同时定期清理过期状态。
    /// 当通道关闭时会优雅退出。
    pub async fn run(mut self) -> Result<()> {
        info!("Worker {} started", self.id);

        let mut cleanup_interval = tokio::time::interval(std::time::Duration::from_secs(
            self.config.memory.cleanup_interval as u64,
        ));

        loop {
            tokio::select! {
                maybe_event = self.rx.recv() => {
                    match maybe_event {
                        Some(event) => {
                            if let Err(e) = self.rule_engine.evaluate(&event) {
                                debug!("Worker {} evaluate error: {}", self.id, e);
                            }
                        }
                        None => {
                            info!("Worker {} channel closed, exiting", self.id);
                            break;
                        }
                    }
                }
                _ = cleanup_interval.tick() => {
                    self.rule_engine.cleanup(Instant::now(), self.config.memory.max_entries);
                }
            }
        }

        info!("Worker {} stopped", self.id);
        Ok(())
    }

    /// 获取 Worker ID
    pub fn id(&self) -> usize {
        self.id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{Rule, RuleType};
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use tokio::sync::mpsc;

    #[test]
    fn test_worker_new() {
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

        let (_tx, rx) = mpsc::channel(100);
        let (nft_tx, _nft_rx) = mpsc::channel(100);
        let (storage_tx, _storage_rx) = mpsc::channel(100);

        let rules = vec![Rule {
            name: "test_rule".to_string(),
            protocol: 6,
            ports: Some(vec![22]),
            rule_type: RuleType::Ip,
            window_secs: 20,
            threshold: 10,
            block_duration: 3600,
            ipv4_prefix: 24,
            ipv6_prefix: 64,
        }];

        let rule_engine = RuleEngine::new(rules, nft_tx, storage_tx);
        let worker = Worker::new(1, config, rule_engine, rx);

        assert_eq!(worker.id(), 1);
    }

    #[tokio::test]
    async fn test_worker_run_receive_event() {
        let config = Arc::new(Config {
            global: crate::config::GlobalConfig {
                worker_count: 1,
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

        let (tx, rx) = mpsc::channel(100);
        let (nft_tx, _nft_rx) = mpsc::channel(100);
        let (storage_tx, _storage_rx) = mpsc::channel(100);

        let rules = vec![Rule {
            name: "test_rule".to_string(),
            protocol: 6,
            ports: Some(vec![22]),
            rule_type: RuleType::Ip,
            window_secs: 60,
            threshold: 10,
            block_duration: 3600,
            ipv4_prefix: 24,
            ipv6_prefix: 64,
        }];

        let rule_engine = RuleEngine::new(rules, nft_tx, storage_tx);
        let worker = Worker::new(1, config, rule_engine, rx);

        let handle = tokio::spawn(async move { worker.run().await });

        let test_event =
            NetworkEvent::new(2, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 22, 6, 0);

        tx.send(test_event).await.unwrap();

        drop(tx);

        let result = tokio::time::timeout(std::time::Duration::from_secs(1), handle).await;

        assert!(result.is_ok());
        assert!(result.unwrap().is_ok());
    }

    #[tokio::test]
    async fn test_worker_id() {
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

        let (_tx, rx) = mpsc::channel(100);
        let (nft_tx, _nft_rx) = mpsc::channel(100);
        let (storage_tx, _storage_rx) = mpsc::channel(100);

        let rules = Vec::new();
        let rule_engine = RuleEngine::new(rules, nft_tx, storage_tx);

        let worker1 = Worker::new(1, Arc::clone(&config), rule_engine, rx);
        let (_tx2, rx2) = mpsc::channel(100);
        let (nft_tx2, _) = mpsc::channel(100);
        let (storage_tx2, _) = mpsc::channel(100);
        let rule_engine2 = RuleEngine::new(Vec::new(), nft_tx2, storage_tx2);
        let worker2 = Worker::new(2, config, rule_engine2, rx2);

        assert_eq!(worker1.id(), 1);
        assert_eq!(worker2.id(), 2);
    }
}
