use std::net::IpAddr;
use std::sync::Arc;

use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::config::Config;
use crate::event::BanAction;

pub mod error;
pub use error::Error;
pub mod raw;
use raw::NftRawController;

type Result<T> = std::result::Result<T, crate::error::Error>;

pub struct NftController {
    config: Arc<Config>,
    nft: NftRawController,
}

impl NftController {
    /// 创建新的 nftables 控制器
    ///
    /// 初始化 nftables 表、集合和链，并同步已有封禁状态
    ///
    /// # 参数
    ///
    /// * `config` - 配置（包含 nft_table 名称）
    pub async fn new(config: Arc<Config>) -> Result<Self> {
        let nft = NftRawController::new(&config.global.nft_table)
            .map_err(crate::nft::error::Error::from)?;

        info!("Initializing nftables table: {}", config.global.nft_table);
        nft.create_table().map_err(crate::nft::error::Error::from)?;
        nft.create_sets().map_err(crate::nft::error::Error::from)?;
        nft.create_chains()
            .map_err(crate::nft::error::Error::from)?;

        info!("Syncing existing banned IPs from nftables");
        nft.sync_from_nftables()
            .map_err(crate::nft::error::Error::from)?;

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
                error!("Failed to handle ban: {}", e);
            }
        }

        info!("nftables controller stopped");
        Ok(())
    }

    /// 处理封禁动作
    ///
    /// 根据封禁类型（IP 或 CIDR）执行相应的封禁操作
    ///
    /// # 参数
    ///
    /// * `ban` - 封禁动作
    fn handle_ban(&self, ban: &BanAction) -> Result<()> {
        if ban.is_cidr_ban() {
            self.handle_cidr_ban(ban)
        } else {
            self.handle_ip_ban(ban)
        }
    }

    /// 处理 IP 封禁
    ///
    /// 将单个 IP 添加到 nftables 封禁集合
    /// 如果 IP 与已存在的 CIDR 冲突，则跳过
    fn handle_ip_ban(&self, ban: &BanAction) -> Result<()> {
        info!(
            "Banning IP: {} for {} seconds (rule: {})",
            ban.src_ip, ban.duration, ban.rule_name
        );

        match self.nft.add_ip_to_set(ban.src_ip, ban.duration) {
            Ok(_) => {
                debug!("IP {} banned successfully", ban.src_ip);
                Ok(())
            }
            Err(raw::Error::IpAlreadyExists) => {
                warn!(
                    "IP {} already banned, updating duration to {} seconds",
                    ban.src_ip, ban.duration
                );
                self.nft
                    .remove_ip_from_set(ban.src_ip)
                    .map_err(crate::nft::error::Error::from)?;
                self.nft
                    .add_ip_to_set(ban.src_ip, ban.duration)
                    .map_err(crate::nft::error::Error::from)?;
                Ok(())
            }
            Err(raw::Error::IpCidrConflict) => {
                info!(
                    "IP {} is already covered by an existing CIDR ban, skipping",
                    ban.src_ip
                );
                Ok(())
            }
            Err(e) => Err(crate::error::Error::Nftables(
                crate::nft::error::Error::from(e),
            )),
        }
    }

    /// 处理 CIDR 封禁
    ///
    /// 将 CIDR 网段添加到 nftables 封禁集合
    /// 先检查并删除该网段内已存在的单个 IP，避免冲突
    fn handle_cidr_ban(&self, ban: &BanAction) -> Result<()> {
        if let Some(cidr) = &ban.cidr {
            info!(
                "Banning CIDR: {} for {} seconds (rule: {}, triggered by {})",
                cidr, ban.duration, ban.rule_name, ban.src_ip
            );

            match self.nft.add_cidr_to_set(*cidr, ban.duration) {
                Ok(_) => {
                    debug!("CIDR {} banned successfully", cidr);
                    Ok(())
                }
                Err(raw::Error::IpAlreadyExists) => {
                    warn!(
                        "CIDR {} already banned, updating duration to {} seconds",
                        cidr, ban.duration
                    );
                    self.nft
                        .remove_cidr_from_set(*cidr)
                        .map_err(crate::nft::error::Error::from)?;
                    self.nft
                        .add_cidr_to_set(*cidr, ban.duration)
                        .map_err(crate::nft::error::Error::from)?;
                    Ok(())
                }
                Err(e) => {
                    error!("Failed to ban CIDR {}: {}", cidr, e);
                    Err(crate::error::Error::Nftables(
                        crate::nft::error::Error::from(e),
                    ))
                }
            }
        } else {
            Err(crate::error::Error::Nftables(
                crate::nft::error::Error::from(raw::Error::InvalidIp),
            ))
        }
    }

    /// 解封 IP 地址
    ///
    /// 从 nftables 封禁集合中移除指定 IP
    ///
    /// # 参数
    ///
    /// * `ip` - 要解封的 IP 地址
    pub fn unban_ip(&self, ip: IpAddr) -> Result<()> {
        info!("Unbanning IP: {}", ip);
        self.nft
            .remove_ip_from_set(ip)
            .map_err(crate::nft::error::Error::from)?;
        Ok(())
    }

    /// 解封 CIDR 网段
    ///
    /// 从 nftables 封禁集合中移除指定 CIDR
    ///
    /// # 参数
    ///
    /// * `cidr` - 要解封的 CIDR 网段
    pub fn unban_cidr(&self, cidr: ipnet::IpNet) -> Result<()> {
        info!("Unbanning CIDR: {}", cidr);
        self.nft
            .remove_cidr_from_set(cidr)
            .map_err(crate::nft::error::Error::from)?;
        Ok(())
    }

    /// 获取已封禁的 IP 列表
    ///
    /// # 返回值
    ///
    /// 返回包含 IP 地址和剩余封禁时长的元组列表
    pub fn get_banned_ips(&self) -> Result<Vec<(IpAddr, u32)>> {
        Ok(self
            .nft
            .get_banned_ips()
            .map_err(crate::nft::error::Error::from)?)
    }

    /// 获取配置中的 nft_table 名称
    pub fn table_name(&self) -> &str {
        &self.config.global.nft_table
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use super::*;
    #[cfg(target_os = "linux")]
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    #[cfg(target_os = "linux")]
    use std::sync::Arc;
    #[cfg(target_os = "linux")]
    use tokio::sync::mpsc;

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_nft_controller_new() {
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

        let result = NftController::new(config).await;

        assert!(result.is_ok());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_nft_controller_run() {
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

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_nft_controller_get_banned_ips() {
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

        let result = controller.get_banned_ips();

        assert!(result.is_ok());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_nft_controller_table_name() {
        let config = Arc::new(Config {
            global: crate::config::GlobalConfig {
                worker_count: 4,
                nft_table: "edepot_test_table".to_string(),
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

        assert_eq!(controller.table_name(), "edepot_test_table");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_nft_controller_handle_ban_ipv4() {
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

        let test_ban = BanAction::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            "test_rule".to_string(),
            3600,
            "test".to_string(),
        );

        let result = controller.handle_ban(&test_ban);

        assert!(result.is_ok());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_nft_controller_handle_ban_ipv6() {
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

        let test_ban = BanAction::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            "test_rule".to_string(),
            3600,
            "test".to_string(),
        );

        let result = controller.handle_ban(&test_ban);

        assert!(result.is_ok());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_nft_controller_handle_cidr_ban() {
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

        let cidr: ipnet::IpNet = "192.168.100.0/24".parse().unwrap();
        let test_ban = BanAction::new_cidr(
            IpAddr::V4(Ipv4Addr::new(192, 168, 100, 50)),
            "test_cidr_rule".to_string(),
            7200,
            "CIDR threshold exceeded".to_string(),
            cidr,
        );

        let result = controller.handle_ban(&test_ban);

        assert!(result.is_ok());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_nft_controller_unban_ip() {
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

        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200));
        let ban = BanAction::new(ip, "test_rule".to_string(), 3600, "test".to_string());
        controller.handle_ban(&ban).unwrap();

        let result = controller.unban_ip(ip);

        assert!(result.is_ok());
    }
}
