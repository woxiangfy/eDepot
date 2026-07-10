use std::net::IpAddr;
use std::sync::Arc;

use tokio::sync::mpsc;
use tracing::{debug, info};

use crate::config::Config;
use crate::error::Result;
use crate::event::BanAction;

pub mod error;
pub use error::Error;

pub mod raw;
use raw::NftRawController;

pub struct NftController {
    config: Arc<Config>,
    nft: NftRawController,
}

impl NftController {
    /// 创建新的 nftables 控制器
    ///
    /// 初始化 nftables 表、集合和链
    ///
    /// # 参数
    ///
    /// * `config` - 配置（包含 nft_table 名称）
    pub async fn new(config: Arc<Config>) -> Result<Self> {
        let nft = NftRawController::new(&config.global.nft_table).map_err(Error::from)?;

        info!("Initializing nftables table: {}", config.global.nft_table);
        nft.create_table().map_err(Error::from)?;
        nft.create_sets().map_err(Error::from)?;
        nft.create_chains().map_err(Error::from)?;

        info!("nftables controller initialized");
        Ok(Self { config, nft })
    }

    /// 运行 nftables 控制器主循环
    ///
    /// 从通道接收封禁动作并执行封禁
    ///
    /// # 参数
    ///
    /// * `rx` - 封禁动作接收通道
    pub async fn run(&self, mut rx: mpsc::Receiver<BanAction>) -> Result<()> {
        info!("nftables controller started");

        while let Some(ban) = rx.recv().await {
            if let Err(e) = self.handle_ban(&ban) {
                debug!("Failed to handle ban: {}", e);
            }
        }

        info!("nftables controller stopped");
        Ok(())
    }

    /// 处理封禁动作
    ///
    /// 将 IP 添加到 nftables 封禁集合
    ///
    /// # 参数
    ///
    /// * `ban` - 封禁动作
    fn handle_ban(&self, ban: &BanAction) -> Result<()> {
        info!("Banning IP: {} for {} seconds", ban.src_ip, ban.duration);
        self.nft
            .add_ip_to_set(ban.src_ip, ban.duration)
            .map_err(Error::from)?;
        Ok(())
    }

    /// 获取已封禁的 IP 列表
    ///
    /// # 返回值
    ///
    /// 返回包含 IP 地址和剩余封禁时长的元组列表
    pub fn get_banned_ips(&self) -> Result<Vec<(IpAddr, u32)>> {
        Ok(self.nft.get_banned_ips().map_err(Error::from)?)
    }

    /// 获取配置中的 nft_table 名称
    pub fn table_name(&self) -> &str {
        &self.config.global.nft_table
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_nft_controller_new() {
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

        let result = NftController::new(config).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_nft_controller_run() {
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

        let controller = NftController::new(config).await.unwrap();
        let (tx, rx) = mpsc::channel(100);

        let handle = tokio::spawn(async move {
            let _ = controller.run(rx).await;
        });

        let test_ban = BanAction::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            "test_rule".to_string(),
            3600,
            "test".to_string(),
        );

        tx.send(test_ban).await.unwrap();

        drop(tx);

        let result = tokio::time::timeout(std::time::Duration::from_secs(1), handle).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_nft_controller_get_banned_ips() {
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

        let controller = NftController::new(config).await.unwrap();

        let result = controller.get_banned_ips();

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_nft_controller_table_name() {
        let config = Arc::new(Config {
            global: crate::config::GlobalConfig {
                worker_count: 4,
                nft_table: "edepot_test".to_string(),
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

        let controller = NftController::new(config).await.unwrap();

        assert_eq!(controller.table_name(), "edepot_test");
    }

    #[tokio::test]
    async fn test_nft_controller_handle_ban_ipv4() {
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

        let controller = NftController::new(config).await.unwrap();

        let test_ban = BanAction::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            "test_rule".to_string(),
            3600,
            "test".to_string(),
        );

        let result = controller.handle_ban(&test_ban);

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_nft_controller_handle_ban_ipv6() {
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

        let controller = NftController::new(config).await.unwrap();

        let test_ban = BanAction::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            "test_rule".to_string(),
            3600,
            "test".to_string(),
        );

        let result = controller.handle_ban(&test_ban);

        assert!(result.is_ok());
    }
}
