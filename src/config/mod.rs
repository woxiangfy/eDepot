use ipnet::IpNet;
use serde::Deserialize;
use std::fs;
use std::net::IpAddr;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to read config file: {0}")]
    ReadFile(#[from] std::io::Error),

    #[error("failed to parse config file: {0}")]
    Parse(#[from] toml::de::Error),

    #[error("invalid cidr: {0}")]
    InvalidCidr(String),

    #[error("validation error: {0}")]
    Validation(String),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Deserialize)]
pub struct GlobalConfig {
    #[serde(default = "default_worker_count")]
    pub worker_count: usize,
    #[serde(default = "default_nft_table")]
    pub nft_table: String,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default = "default_poll_interval_ms")]
    pub poll_interval_ms: u64,
}

fn default_worker_count() -> usize {
    4
}

fn default_nft_table() -> String {
    "edepot".to_string()
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_poll_interval_ms() -> u64 {
    1000
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            worker_count: default_worker_count(),
            nft_table: default_nft_table(),
            log_level: default_log_level(),
            poll_interval_ms: default_poll_interval_ms(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct WhitelistConfig {
    pub cidr: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RuleConfig {
    pub name: String,
    pub protocol: String,
    pub ports: Option<Vec<u16>>,
    pub rule_type: String,
    pub window_secs: u32,
    pub threshold: u32,
    pub block_duration: u32,
    pub ipv4_prefix: Option<u8>,
    pub ipv6_prefix: Option<u8>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MemoryConfig {
    pub max_entries: usize,
    pub cleanup_interval: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub global: GlobalConfig,
    pub whitelist: WhitelistConfig,
    pub rules: Vec<RuleConfig>,
    pub memory: MemoryConfig,
}

impl Config {
    /// 从 TOML 文件加载配置
    ///
    /// # 参数
    ///
    /// * `path` - 配置文件路径
    ///
    /// # 返回值
    ///
    /// 返回解析后的 Config 结构体，或错误信息
    pub fn from_file(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }

    /// 检查 IP 地址是否在白名单中
    ///
    /// # 参数
    ///
    /// * `ip` - 待检查的 IP 地址
    ///
    /// # 返回值
    ///
    /// 如果 IP 在白名单中返回 true，否则返回 false
    pub fn is_whitelisted(&self, ip: &IpAddr) -> bool {
        self.whitelist.cidr.iter().any(|cidr| {
            if let Ok(net) = cidr.parse::<IpNet>() {
                net.contains(ip)
            } else {
                false
            }
        })
    }

    /// 获取规则数量
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// 获取白名单 CIDR 数量
    pub fn whitelist_count(&self) -> usize {
        self.whitelist.cidr.len()
    }

    /// 校验配置文件的完整性和有效性
    ///
    /// 检查项包括：
    /// - worker_count 必须 > 0
    /// - nft_table 不能为空
    /// - poll_interval_ms 必须 > 0
    /// - 白名单 CIDR 格式必须正确
    /// - 每条规则的字段必须有效（协议、rule_type、端口、前缀等）
    /// - memory 配置必须有效
    ///
    /// # 返回值
    ///
    /// 校验通过返回 Ok(())，否则返回对应的错误信息
    pub fn validate(&self) -> Result<()> {
        // 校验 global 配置
        if self.global.worker_count == 0 {
            return Err(Error::Validation("worker_count must be > 0".to_string()));
        }
        if self.global.nft_table.is_empty() {
            return Err(Error::Validation("nft_table must not be empty".to_string()));
        }
        if self.global.poll_interval_ms == 0 {
            return Err(Error::Validation(
                "poll_interval_ms must be > 0".to_string(),
            ));
        }

        // 校验白名单 CIDR
        for (i, cidr) in self.whitelist.cidr.iter().enumerate() {
            if cidr.parse::<IpNet>().is_err() {
                return Err(Error::InvalidCidr(format!(
                    "whitelist[{}]: '{}' is not a valid CIDR",
                    i, cidr
                )));
            }
        }

        // 校验规则配置
        for (i, rule) in self.rules.iter().enumerate() {
            if rule.name.is_empty() {
                return Err(Error::Validation(format!(
                    "rule[{}]: name must not be empty",
                    i
                )));
            }

            let protocol = rule.protocol.to_lowercase();
            if protocol != "tcp" && protocol != "udp" {
                return Err(Error::Validation(format!(
                    "rule[{}] '{}': protocol must be 'tcp' or 'udp', got '{}'",
                    i, rule.name, rule.protocol
                )));
            }

            let rule_type = rule.rule_type.to_lowercase();
            if rule_type != "ip" && rule_type != "cidr" {
                return Err(Error::Validation(format!(
                    "rule[{}] '{}': rule_type must be 'ip' or 'cidr', got '{}'",
                    i, rule.name, rule.rule_type
                )));
            }

            if rule.rule_type == "cidr" {
                if rule.ipv4_prefix.is_none() || rule.ipv6_prefix.is_none() {
                    return Err(Error::Validation(format!(
                        "rule[{}] '{}': cidr rule requires both ipv4_prefix and ipv6_prefix",
                        i, rule.name
                    )));
                }
            }

            if rule.window_secs == 0 {
                return Err(Error::Validation(format!(
                    "rule[{}] '{}': window_secs must be > 0",
                    i, rule.name
                )));
            }

            if rule.threshold == 0 {
                return Err(Error::Validation(format!(
                    "rule[{}] '{}': threshold must be > 0",
                    i, rule.name
                )));
            }

            if rule.block_duration == 0 {
                return Err(Error::Validation(format!(
                    "rule[{}] '{}': block_duration must be > 0",
                    i, rule.name
                )));
            }
        }

        // 校验 memory 配置
        if self.memory.max_entries == 0 {
            return Err(Error::Validation("max_entries must be > 0".to_string()));
        }
        if self.memory.cleanup_interval == 0 {
            return Err(Error::Validation(
                "cleanup_interval must be > 0".to_string(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use tempfile::NamedTempFile;

    #[test]
    fn test_from_file_valid() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            r#"
[global]
worker_count = 4
nft_table = "edepot"

[whitelist]
cidr = ["127.0.0.0/8", "::1/128"]

[memory]
max_entries = 100000
cleanup_interval = 60

[[rules]]
name = "ssh_bruteforce"
protocol = "tcp"
ports = [22]
rule_type = "ip"
window_secs = 20
threshold = 8
block_duration = 3600
"#
        )
        .unwrap();

        let config = Config::from_file(temp_file.path().to_str().unwrap()).unwrap();

        assert_eq!(config.global.worker_count, 4);
        assert_eq!(config.global.nft_table, "edepot");
        assert_eq!(config.whitelist.cidr.len(), 2);
        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.memory.max_entries, 100000);
        assert_eq!(config.memory.cleanup_interval, 60);
    }

    #[test]
    fn test_from_file_invalid() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(
            temp_file,
            r#"
[global]
worker_count = "not_a_number"
"#
        )
        .unwrap();

        let result = Config::from_file(temp_file.path().to_str().unwrap());
        assert!(result.is_err());
    }

    #[test]
    fn test_from_file_not_found() {
        let result = Config::from_file("/nonexistent/path/config.toml");
        assert!(result.is_err());
    }

    #[test]
    fn test_is_whitelisted_ipv4() {
        let config = Config {
            global: GlobalConfig {
                worker_count: 4,
                nft_table: "edepot".to_string(),
                log_level: "info".to_string(),
                poll_interval_ms: 1000,
            },
            whitelist: WhitelistConfig {
                cidr: vec!["192.168.1.0/24".to_string(), "127.0.0.0/8".to_string()],
            },
            rules: Vec::new(),
            memory: MemoryConfig {
                max_entries: 100000,
                cleanup_interval: 60,
            },
        };

        assert!(config.is_whitelisted(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(config.is_whitelisted(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        assert!(!config.is_whitelisted(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    #[test]
    fn test_is_whitelisted_ipv6() {
        let config = Config {
            global: GlobalConfig {
                worker_count: 4,
                nft_table: "edepot".to_string(),
                log_level: "info".to_string(),
                poll_interval_ms: 1000,
            },
            whitelist: WhitelistConfig {
                cidr: vec!["::1/128".to_string(), "fe80::/10".to_string()],
            },
            rules: Vec::new(),
            memory: MemoryConfig {
                max_entries: 100000,
                cleanup_interval: 60,
            },
        };

        assert!(config.is_whitelisted(&IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))));
        assert!(config.is_whitelisted(&IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))));
        assert!(!config.is_whitelisted(&IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))));
    }

    #[test]
    fn test_is_whitelisted_invalid_cidr() {
        let config = Config {
            global: GlobalConfig {
                worker_count: 4,
                nft_table: "edepot".to_string(),
                log_level: "info".to_string(),
                poll_interval_ms: 1000,
            },
            whitelist: WhitelistConfig {
                cidr: vec!["invalid-cidr".to_string()],
            },
            rules: Vec::new(),
            memory: MemoryConfig {
                max_entries: 100000,
                cleanup_interval: 60,
            },
        };

        assert!(!config.is_whitelisted(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
    }

    #[test]
    fn test_rule_count() {
        let config = Config {
            global: GlobalConfig {
                worker_count: 4,
                nft_table: "edepot".to_string(),
                log_level: "info".to_string(),
                poll_interval_ms: 1000,
            },
            whitelist: WhitelistConfig { cidr: Vec::new() },
            rules: vec![
                RuleConfig {
                    name: "rule1".to_string(),
                    protocol: "tcp".to_string(),
                    ports: Some(vec![22]),
                    rule_type: "ip".to_string(),
                    window_secs: 20,
                    threshold: 10,
                    block_duration: 3600,
                    ipv4_prefix: None,
                    ipv6_prefix: None,
                },
                RuleConfig {
                    name: "rule2".to_string(),
                    protocol: "udp".to_string(),
                    ports: None,
                    rule_type: "cidr".to_string(),
                    window_secs: 60,
                    threshold: 100,
                    block_duration: 7200,
                    ipv4_prefix: Some(24),
                    ipv6_prefix: Some(64),
                },
            ],
            memory: MemoryConfig {
                max_entries: 100000,
                cleanup_interval: 60,
            },
        };

        assert_eq!(config.rule_count(), 2);
        assert_eq!(config.whitelist_count(), 0);
    }

    #[test]
    fn test_empty_config() {
        let config = Config {
            global: GlobalConfig {
                worker_count: 0,
                nft_table: "".to_string(),
                log_level: "info".to_string(),
                poll_interval_ms: 1000,
            },
            whitelist: WhitelistConfig { cidr: Vec::new() },
            rules: Vec::new(),
            memory: MemoryConfig {
                max_entries: 0,
                cleanup_interval: 0,
            },
        };

        assert_eq!(config.rule_count(), 0);
        assert_eq!(config.whitelist_count(), 0);
        assert!(!config.is_whitelisted(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
    }
}
