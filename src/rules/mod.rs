use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use ipnet::IpNet;
use tokio::sync::mpsc;
use tracing::{debug, info};

use crate::config::RuleConfig;
use crate::error::Result;
use crate::event::{BanAction, NetworkEvent};

pub mod error;
pub use error::Error;

pub mod sliding_window;
use sliding_window::SlidingWindow;

#[derive(Debug, Clone, PartialEq, Eq)]
enum RuleKey {
    Ip(IpAddr),
    Cidr(IpNet),
}

impl Hash for RuleKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            RuleKey::Ip(ip) => {
                match ip {
                    IpAddr::V4(ip) => ip.octets().hash(state),
                    IpAddr::V6(ip) => ip.octets().hash(state),
                }
            }
            RuleKey::Cidr(cidr) => {
                match cidr {
                    IpNet::V4(cidr) => {
                        cidr.network().octets().hash(state);
                        state.write_u8(cidr.prefix_len());
                    }
                    IpNet::V6(cidr) => {
                        cidr.network().octets().hash(state);
                        state.write_u8(cidr.prefix_len());
                    }
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub name: String,
    pub protocol: u8,
    pub ports: Option<Vec<u16>>,
    pub rule_type: RuleType,
    pub window_secs: u32,
    pub threshold: u32,
    pub block_duration: u32,
    pub ipv4_prefix: u8,
    pub ipv6_prefix: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleType {
    Ip,
    Cidr,
}

impl Rule {
    /// 从配置创建规则
    ///
    /// # 参数
    ///
    /// * `config` - 规则配置
    ///
    /// # 返回值
    ///
    /// 返回 Rule 结构体，或错误信息
    pub fn from_config(config: &RuleConfig) -> std::result::Result<Self, error::Error> {
        let protocol = match config.protocol.as_str() {
            "tcp" => 6,
            "udp" => 17,
            "icmp" => 1,
            _ => return Err(Error::InvalidProtocol(config.protocol.clone())),
        };

        let rule_type = match config.rule_type.as_str() {
            "ip" => RuleType::Ip,
            "cidr" => RuleType::Cidr,
            _ => return Err(Error::InvalidRuleType(config.rule_type.clone())),
        };

        Ok(Self {
            name: config.name.clone(),
            protocol,
            ports: config.ports.clone(),
            rule_type,
            window_secs: config.window_secs,
            threshold: config.threshold,
            block_duration: config.block_duration,
            ipv4_prefix: config.ipv4_prefix.unwrap_or(24),
            ipv6_prefix: config.ipv6_prefix.unwrap_or(64),
        })
    }

    /// 判断事件是否匹配规则
    ///
    /// # 参数
    ///
    /// * `event` - 网络事件
    ///
    /// # 返回值
    ///
    /// 如果事件匹配规则返回 true，否则返回 false
    pub fn matches(&self, event: &NetworkEvent) -> bool {
        if event.protocol != self.protocol {
            debug!(
                "Rule {}: protocol mismatch - event={}, rule={}",
                self.name, event.protocol, self.protocol
            );
            return false;
        }

        if let Some(ports) = &self.ports {
            if !ports.contains(&event.dst_port) {
                debug!(
                    "Rule {}: port mismatch - event={}, rule={:?}",
                    self.name, event.dst_port, ports
                );
                return false;
            }
        }

        debug!(
            "Rule {}: matched event from {} port {}",
            self.name, event.src_ip, event.dst_port
        );
        true
    }

    pub fn get_key(&self, ip: &IpAddr) -> RuleKey {
        match self.rule_type {
            RuleType::Ip => RuleKey::Ip(*ip),
            RuleType::Cidr => RuleKey::Cidr(self.get_cidr(ip)),
        }
    }

    pub fn get_cidr(&self, ip: &IpAddr) -> IpNet {
        match ip {
            IpAddr::V4(ip) => {
                let prefix = self.ipv4_prefix;
                let mask = u32::MAX << (32 - prefix);
                let masked = u32::from(*ip) & mask;
                IpNet::V4(ipnet::Ipv4Net::new(Ipv4Addr::from(masked), prefix).unwrap())
            }
            IpAddr::V6(ip) => {
                let prefix = self.ipv6_prefix;
                let cidr = ipnet::Ipv6Net::new(*ip, prefix).unwrap();
                IpNet::V6(ipnet::Ipv6Net::new(cidr.network(), prefix).unwrap())
            }
        }
    }
}

#[derive(Debug, Clone)]
struct RuleState {
    window: SlidingWindow,
    last_banned: Option<Instant>,
    banned: bool,
}

impl RuleState {
    /// 创建新的规则状态
    ///
    /// # 参数
    ///
    /// * `window_secs` - 滑动窗口大小（秒）
    fn new(window_secs: u32) -> Self {
        Self {
            window: SlidingWindow::new(window_secs),
            last_banned: None,
            banned: false,
        }
    }

    /// 判断是否应该封禁
    ///
    /// 记录事件并检查是否超过阈值，如果已封禁则检查封禁时长是否过期
    ///
    /// # 参数
    ///
    /// * `threshold` - 阈值
    /// * `block_duration` - 封禁时长（秒）
    ///
    /// # 返回值
    ///
    /// 如果应该封禁返回 true，否则返回 false
    fn should_ban(&mut self, threshold: u32, block_duration: u32) -> bool {
        if self.banned {
            if let Some(last) = self.last_banned {
                if last.elapsed() < Duration::from_secs(block_duration as u64) {
                    return false;
                }
            }
            self.banned = false;
        }

        let count = self.window.record();
        if count >= threshold {
            self.banned = true;
            self.last_banned = Some(Instant::now());
            true
        } else {
            false
        }
    }
}

pub struct RuleEngine {
    rules: Vec<Rule>,
    states: HashMap<String, HashMap<RuleKey, RuleState>>,
    tx: mpsc::Sender<BanAction>,
    storage_tx: mpsc::Sender<BanAction>,
}

impl RuleEngine {
    /// 创建新的规则引擎
    ///
    /// # 参数
    ///
    /// * `rules` - 规则列表
    /// * `tx` - 封禁动作发送通道（发送到 nftables）
    /// * `storage_tx` - 封禁动作发送通道（发送到存储）
    pub fn new(
        rules: Vec<Rule>,
        tx: mpsc::Sender<BanAction>,
        storage_tx: mpsc::Sender<BanAction>,
    ) -> Self {
        debug!("RuleEngine created with {} rules", rules.len());
        Self {
            rules,
            states: HashMap::new(),
            tx,
            storage_tx,
        }
    }

    pub fn evaluate(&mut self, event: &NetworkEvent) -> Result<()> {
        debug!(
            "Evaluating event: {} -> port {} (proto {})",
            event.src_ip, event.dst_port, event.protocol
        );

        for rule in &self.rules {
            if !rule.matches(event) {
                debug!("Rule {}: not matched", rule.name);
                continue;
            }

            let key = rule.get_key(&event.src_ip);

            let rule_states = self.states.entry(rule.name.clone()).or_default();
            let state = rule_states
                .entry(key)
                .or_insert_with(|| RuleState::new(rule.window_secs));

            debug!(
                "Rule {}: current count={}, threshold={}",
                rule.name,
                state.window.count(),
                rule.threshold
            );

            if state.should_ban(rule.threshold, rule.block_duration) {
                debug!(
                    "Rule {}: threshold exceeded, triggering ban for {}",
                    rule.name, event.src_ip
                );

                let ban_action = match rule.rule_type {
                    RuleType::Ip => BanAction::new(
                        event.src_ip,
                        rule.name.clone(),
                        rule.block_duration,
                        format!("Rule {} triggered for {}", rule.name, event.src_ip),
                    ),
                    RuleType::Cidr => {
                        let cidr = rule.get_cidr(&event.src_ip);
                        BanAction::new_cidr(
                            event.src_ip,
                            rule.name.clone(),
                            rule.block_duration,
                            format!("Rule {} triggered for CIDR {}", rule.name, cidr),
                            cidr,
                        )
                    }
                };

                let target = ban_action.get_target();

                if let Err(e) = self.tx.try_send(ban_action.clone()) {
                    debug!("Failed to send ban action to nft: {}", e);
                } else {
                    debug!("Ban action sent to nft controller");
                }

                if let Err(e) = self.storage_tx.try_send(ban_action) {
                    debug!("Failed to send ban action to storage: {}", e);
                } else {
                    debug!("Ban action sent to storage");
                }

                info!(
                    "Ban triggered: {} (rule: {}, target: {})",
                    event.src_ip,
                    rule.name,
                    target
                );
            } else {
                debug!(
                    "Rule {}: count={} < threshold={}, no ban",
                    rule.name,
                    state.window.count(),
                    rule.threshold
                );
            }
        }

        debug!("Event evaluation completed");
        Ok(())
    }

    pub fn cleanup(&mut self, now: Instant, max_entries: usize) {
        debug!("Starting cleanup, current states={}", self.state_count());

        for (rule_name, rule_states) in self.states.iter_mut() {
            let before_count = rule_states.len();
            rule_states.retain(|_, state| {
                let elapsed = now.duration_since(state.window.last_update());
                elapsed < Duration::from_secs(60) || state.banned
            });
            let removed = before_count - rule_states.len();
            if removed > 0 {
                debug!("Cleaned up {} entries from rule {}", removed, rule_name);
            }
        }

        let total_entries: usize = self.states.values().map(|m| m.len()).sum();
        debug!("After cleanup: {} entries", total_entries);

        if total_entries > max_entries {
            debug!(
                "Total entries {} exceeds max {}: performing memory limit cleanup",
                total_entries, max_entries
            );

            for rule_states in self.states.values_mut() {
                let keys_to_remove: Vec<_> = rule_states
                    .iter()
                    .filter(|(_, state)| !state.banned)
                    .map(|(k, _)| k.clone())
                    .collect();

                let to_remove = keys_to_remove
                    .len()
                    .saturating_sub(max_entries / self.rules.len());
                debug!("Removing {} non-banned entries", to_remove);

                for key in keys_to_remove.into_iter().take(to_remove) {
                    rule_states.remove(&key);
                }
            }

            let after_limit_cleanup: usize = self.states.values().map(|m| m.len()).sum();
            debug!(
                "After memory limit cleanup: {} entries",
                after_limit_cleanup
            );
        }

        debug!("Cleanup completed");
    }

    /// 获取规则数量
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// 获取状态数量
    pub fn state_count(&self) -> usize {
        self.states.values().map(|m| m.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    #[test]
    fn test_rule_from_config_tcp() {
        let config = RuleConfig {
            name: "ssh_bruteforce".to_string(),
            protocol: "tcp".to_string(),
            ports: Some(vec![22]),
            rule_type: "ip".to_string(),
            window_secs: 20,
            threshold: 8,
            block_duration: 3600,
            ipv4_prefix: None,
            ipv6_prefix: None,
        };

        let rule = Rule::from_config(&config).unwrap();

        assert_eq!(rule.name, "ssh_bruteforce");
        assert_eq!(rule.protocol, 6);
        assert_eq!(rule.ports, Some(vec![22]));
        assert_eq!(rule.rule_type, RuleType::Ip);
        assert_eq!(rule.window_secs, 20);
        assert_eq!(rule.threshold, 8);
        assert_eq!(rule.block_duration, 3600);
        assert_eq!(rule.ipv4_prefix, 24);
        assert_eq!(rule.ipv6_prefix, 64);
    }

    #[test]
    fn test_rule_from_config_udp() {
        let config = RuleConfig {
            name: "udp_scan".to_string(),
            protocol: "udp".to_string(),
            ports: None,
            rule_type: "cidr".to_string(),
            window_secs: 60,
            threshold: 100,
            block_duration: 7200,
            ipv4_prefix: Some(24),
            ipv6_prefix: Some(64),
        };

        let rule = Rule::from_config(&config).unwrap();

        assert_eq!(rule.name, "udp_scan");
        assert_eq!(rule.protocol, 17);
        assert_eq!(rule.rule_type, RuleType::Cidr);
        assert_eq!(rule.ipv4_prefix, 24);
    }

    #[test]
    fn test_rule_from_config_invalid_protocol() {
        let config = RuleConfig {
            name: "test".to_string(),
            protocol: "invalid".to_string(),
            ports: None,
            rule_type: "ip".to_string(),
            window_secs: 20,
            threshold: 10,
            block_duration: 3600,
            ipv4_prefix: None,
            ipv6_prefix: None,
        };

        let result = Rule::from_config(&config);

        assert!(result.is_err());
    }

    #[test]
    fn test_rule_from_config_invalid_rule_type() {
        let config = RuleConfig {
            name: "test".to_string(),
            protocol: "tcp".to_string(),
            ports: None,
            rule_type: "invalid".to_string(),
            window_secs: 20,
            threshold: 10,
            block_duration: 3600,
            ipv4_prefix: None,
            ipv6_prefix: None,
        };

        let result = Rule::from_config(&config);

        assert!(result.is_err());
    }

    #[test]
    fn test_rule_matches() {
        let rule = Rule {
            name: "ssh".to_string(),
            protocol: 6,
            ports: Some(vec![22]),
            rule_type: RuleType::Ip,
            window_secs: 20,
            threshold: 10,
            block_duration: 3600,
            ipv4_prefix: 24,
            ipv6_prefix: 64,
        };

        let event1 = NetworkEvent::new(2, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 22, 6, 0);
        let event2 = NetworkEvent::new(2, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 80, 6, 0);
        let event3 = NetworkEvent::new(2, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 22, 17, 0);

        assert!(rule.matches(&event1));
        assert!(!rule.matches(&event2));
        assert!(!rule.matches(&event3));
    }

    #[test]
    fn test_rule_matches_no_ports() {
        let rule = Rule {
            name: "udp_scan".to_string(),
            protocol: 17,
            ports: None,
            rule_type: RuleType::Cidr,
            window_secs: 60,
            threshold: 100,
            block_duration: 7200,
            ipv4_prefix: 24,
            ipv6_prefix: 64,
        };

        let event1 = NetworkEvent::new(2, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 53, 17, 0);
        let event2 = NetworkEvent::new(2, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 67, 17, 0);
        let event3 = NetworkEvent::new(2, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 22, 6, 0);

        assert!(rule.matches(&event1));
        assert!(rule.matches(&event2));
        assert!(!rule.matches(&event3));
    }

    #[test]
    fn test_get_key_ip() {
        let rule = Rule {
            name: "test".to_string(),
            protocol: 6,
            ports: None,
            rule_type: RuleType::Ip,
            window_secs: 20,
            threshold: 10,
            block_duration: 3600,
            ipv4_prefix: 24,
            ipv6_prefix: 64,
        };

        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let key = rule.get_key(&ip);

        assert_eq!(key, RuleKey::Ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
    }

    #[test]
    fn test_get_key_cidr_ipv4() {
        let rule = Rule {
            name: "test".to_string(),
            protocol: 6,
            ports: None,
            rule_type: RuleType::Cidr,
            window_secs: 20,
            threshold: 10,
            block_duration: 3600,
            ipv4_prefix: 24,
            ipv6_prefix: 64,
        };

        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200));
        let ip3 = IpAddr::V4(Ipv4Addr::new(192, 168, 2, 100));

        let cidr1 = IpNet::V4(ipnet::Ipv4Net::new(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap());
        let cidr2 = IpNet::V4(ipnet::Ipv4Net::new(Ipv4Addr::new(192, 168, 2, 0), 24).unwrap());

        assert_eq!(rule.get_key(&ip1), RuleKey::Cidr(cidr1));
        assert_eq!(rule.get_key(&ip2), RuleKey::Cidr(cidr1));
        assert_eq!(rule.get_key(&ip3), RuleKey::Cidr(cidr2));
    }

    #[test]
    fn test_get_key_cidr_ipv6() {
        let rule = Rule {
            name: "test".to_string(),
            protocol: 6,
            ports: None,
            rule_type: RuleType::Cidr,
            window_secs: 20,
            threshold: 10,
            block_duration: 3600,
            ipv4_prefix: 24,
            ipv6_prefix: 64,
        };

        let ip1 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let ip2 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2));

        let cidr = IpNet::V6(
            ipnet::Ipv6Net::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 64).unwrap(),
        );

        assert_eq!(rule.get_key(&ip1), RuleKey::Cidr(cidr));
        assert_eq!(rule.get_key(&ip2), RuleKey::Cidr(cidr));
    }

    #[test]
    fn test_rule_engine_new() {
        let rules = vec![Rule {
            name: "rule1".to_string(),
            protocol: 6,
            ports: Some(vec![22]),
            rule_type: RuleType::Ip,
            window_secs: 20,
            threshold: 10,
            block_duration: 3600,
            ipv4_prefix: 24,
            ipv6_prefix: 64,
        }];

        let (tx, _rx) = mpsc::channel(100);
        let (storage_tx, _storage_rx) = mpsc::channel(100);

        let engine = RuleEngine::new(rules, tx, storage_tx);

        assert_eq!(engine.rule_count(), 1);
        assert_eq!(engine.state_count(), 0);
    }

    #[test]
    fn test_rule_engine_evaluate_trigger_ban() {
        let rules = vec![Rule {
            name: "test_rule".to_string(),
            protocol: 6,
            ports: Some(vec![22]),
            rule_type: RuleType::Ip,
            window_secs: 60,
            threshold: 3,
            block_duration: 3600,
            ipv4_prefix: 24,
            ipv6_prefix: 64,
        }];

        let (tx, mut rx) = mpsc::channel(100);
        let (storage_tx, mut storage_rx) = mpsc::channel(100);

        let mut engine = RuleEngine::new(rules, tx, storage_tx);

        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let event = NetworkEvent::new(2, ip, 22, 6, 0);

        engine.evaluate(&event).unwrap();
        engine.evaluate(&event).unwrap();
        engine.evaluate(&event).unwrap();

        let ban_action = rx.try_recv();
        let storage_action = storage_rx.try_recv();

        assert!(ban_action.is_ok());
        assert!(storage_action.is_ok());
        assert_eq!(ban_action.unwrap().rule_name, "test_rule");
        assert_eq!(storage_action.unwrap().rule_name, "test_rule");
    }

    #[test]
    fn test_rule_engine_evaluate_no_ban() {
        let rules = vec![Rule {
            name: "test_rule".to_string(),
            protocol: 6,
            ports: Some(vec![22]),
            rule_type: RuleType::Ip,
            window_secs: 60,
            threshold: 5,
            block_duration: 3600,
            ipv4_prefix: 24,
            ipv6_prefix: 64,
        }];

        let (tx, mut rx) = mpsc::channel(100);
        let (storage_tx, mut storage_rx) = mpsc::channel(100);

        let mut engine = RuleEngine::new(rules, tx, storage_tx);

        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let event = NetworkEvent::new(2, ip, 22, 6, 0);

        engine.evaluate(&event).unwrap();
        engine.evaluate(&event).unwrap();

        let ban_action = rx.try_recv();
        let storage_action = storage_rx.try_recv();

        assert!(ban_action.is_err());
        assert!(storage_action.is_err());
    }

    #[test]
    fn test_rule_engine_evaluate_no_match() {
        let rules = vec![Rule {
            name: "test_rule".to_string(),
            protocol: 6,
            ports: Some(vec![22]),
            rule_type: RuleType::Ip,
            window_secs: 60,
            threshold: 1,
            block_duration: 3600,
            ipv4_prefix: 24,
            ipv6_prefix: 64,
        }];

        let (tx, mut rx) = mpsc::channel(100);
        let (storage_tx, mut storage_rx) = mpsc::channel(100);

        let mut engine = RuleEngine::new(rules, tx, storage_tx);

        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let event = NetworkEvent::new(2, ip, 80, 6, 0);

        engine.evaluate(&event).unwrap();

        let ban_action = rx.try_recv();
        let storage_action = storage_rx.try_recv();

        assert!(ban_action.is_err());
        assert!(storage_action.is_err());
    }

    #[test]
    fn test_rule_engine_cleanup() {
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

        let (tx, _rx) = mpsc::channel(100);
        let (storage_tx, _storage_rx) = mpsc::channel(100);

        let mut engine = RuleEngine::new(rules, tx, storage_tx);

        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101));
        let event1 = NetworkEvent::new(2, ip1, 22, 6, 0);
        let event2 = NetworkEvent::new(2, ip2, 22, 6, 0);

        engine.evaluate(&event1).unwrap();
        engine.evaluate(&event2).unwrap();

        assert_eq!(engine.state_count(), 2);

        engine.cleanup(Instant::now() + Duration::from_secs(120), 1000);

        assert_eq!(engine.state_count(), 0);
    }

    #[test]
    fn test_rule_type_partial_eq() {
        assert_eq!(RuleType::Ip, RuleType::Ip);
        assert_eq!(RuleType::Cidr, RuleType::Cidr);
        assert_ne!(RuleType::Ip, RuleType::Cidr);
    }

    #[test]
    fn test_rule_engine_state_count() {
        let rules = vec![
            Rule {
                name: "rule1".to_string(),
                protocol: 6,
                ports: Some(vec![22]),
                rule_type: RuleType::Ip,
                window_secs: 60,
                threshold: 10,
                block_duration: 3600,
                ipv4_prefix: 24,
                ipv6_prefix: 64,
            },
            Rule {
                name: "rule2".to_string(),
                protocol: 17,
                ports: None,
                rule_type: RuleType::Cidr,
                window_secs: 60,
                threshold: 100,
                block_duration: 7200,
                ipv4_prefix: 24,
                ipv6_prefix: 64,
            },
        ];

        let (tx, _rx) = mpsc::channel(100);
        let (storage_tx, _storage_rx) = mpsc::channel(100);

        let mut engine = RuleEngine::new(rules, tx, storage_tx);

        assert_eq!(engine.rule_count(), 2);
        assert_eq!(engine.state_count(), 0);

        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let event1 = NetworkEvent::new(2, ip, 22, 6, 0);
        let event2 = NetworkEvent::new(2, ip, 53, 17, 0);

        engine.evaluate(&event1).unwrap();
        engine.evaluate(&event2).unwrap();

        assert_eq!(engine.state_count(), 2);
    }
}
