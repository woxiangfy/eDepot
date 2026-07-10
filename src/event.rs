use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use ipnet::IpNet;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NetworkEvent {
    pub family: u8,
    pub src_ip: IpAddr,
    pub dst_port: u16,
    pub protocol: u8,
    pub timestamp: u64,
}

impl NetworkEvent {
    /// 创建新的网络事件
    ///
    /// # 参数
    ///
    /// * `family` - 地址族 (2=IPv4, 10=IPv6)
    /// * `src_ip` - 源 IP 地址
    /// * `dst_port` - 目标端口
    /// * `protocol` - 协议类型 (6=TCP, 17=UDP)
    /// * `timestamp` - 时间戳 (纳秒)
    pub fn new(family: u8, src_ip: IpAddr, dst_port: u16, protocol: u8, timestamp: u64) -> Self {
        Self {
            family,
            src_ip,
            dst_port,
            protocol,
            timestamp,
        }
    }

    /// 判断是否为 IPv4 事件
    pub fn is_ipv4(&self) -> bool {
        self.family == 2
    }

    /// 判断是否为 IPv6 事件
    pub fn is_ipv6(&self) -> bool {
        self.family == 10
    }

    /// 获取 IPv4 地址（如果是 IPv4 事件）
    pub fn ipv4(&self) -> Option<Ipv4Addr> {
        match self.src_ip {
            IpAddr::V4(ip) => Some(ip),
            _ => None,
        }
    }

    /// 获取 IPv6 地址（如果是 IPv6 事件）
    pub fn ipv6(&self) -> Option<Ipv6Addr> {
        match self.src_ip {
            IpAddr::V6(ip) => Some(ip),
            _ => None,
        }
    }

    /// 判断是否为 TCP 协议
    pub fn is_tcp(&self) -> bool {
        self.protocol == 6
    }

    /// 判断是否为 UDP 协议
    pub fn is_udp(&self) -> bool {
        self.protocol == 17
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BanAction {
    pub src_ip: IpAddr,
    pub rule_name: String,
    pub duration: u32,
    pub reason: String,
    pub cidr: Option<IpNet>,
}

impl BanAction {
    /// 创建新的 IP 封禁动作
    ///
    /// # 参数
    ///
    /// * `src_ip` - 要封禁的 IP 地址
    /// * `rule_name` - 触发的规则名称
    /// * `duration` - 封禁时长（秒）
    /// * `reason` - 封禁原因
    pub fn new(src_ip: IpAddr, rule_name: String, duration: u32, reason: String) -> Self {
        Self {
            src_ip,
            rule_name,
            duration,
            reason,
            cidr: None,
        }
    }

    /// 创建新的 CIDR 封禁动作
    ///
    /// # 参数
    ///
    /// * `src_ip` - 触发封禁的源 IP 地址
    /// * `rule_name` - 触发的规则名称
    /// * `duration` - 封禁时长（秒）
    /// * `reason` - 封禁原因
    /// * `cidr` - 要封禁的 CIDR 网络
    pub fn new_cidr(
        src_ip: IpAddr,
        rule_name: String,
        duration: u32,
        reason: String,
        cidr: IpNet,
    ) -> Self {
        Self {
            src_ip,
            rule_name,
            duration,
            reason,
            cidr: Some(cidr),
        }
    }

    /// 判断是否为 CIDR 封禁
    pub fn is_cidr_ban(&self) -> bool {
        self.cidr.is_some()
    }

    /// 获取封禁目标（IP 或 CIDR）
    pub fn get_target(&self) -> String {
        if let Some(cidr) = &self.cidr {
            cidr.to_string()
        } else {
            self.src_ip.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_event_new_ipv4() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let event = NetworkEvent::new(2, ip, 22, 6, 1234567890);

        assert_eq!(event.family, 2);
        assert_eq!(event.src_ip, ip);
        assert_eq!(event.dst_port, 22);
        assert_eq!(event.protocol, 6);
        assert_eq!(event.timestamp, 1234567890);
    }

    #[test]
    fn test_network_event_new_ipv6() {
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let event = NetworkEvent::new(10, ip, 80, 6, 1234567890);

        assert_eq!(event.family, 10);
        assert_eq!(event.src_ip, ip);
        assert_eq!(event.dst_port, 80);
        assert_eq!(event.protocol, 6);
    }

    #[test]
    fn test_is_ipv4() {
        let ipv4_event = NetworkEvent::new(2, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 22, 6, 0);
        let ipv6_event = NetworkEvent::new(
            10,
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            22,
            6,
            0,
        );

        assert!(ipv4_event.is_ipv4());
        assert!(!ipv6_event.is_ipv4());
    }

    #[test]
    fn test_is_ipv6() {
        let ipv4_event = NetworkEvent::new(2, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 22, 6, 0);
        let ipv6_event = NetworkEvent::new(
            10,
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            22,
            6,
            0,
        );

        assert!(!ipv4_event.is_ipv6());
        assert!(ipv6_event.is_ipv6());
    }

    #[test]
    fn test_ipv4_method() {
        let ipv4_addr = Ipv4Addr::new(192, 168, 1, 1);
        let ipv4_event = NetworkEvent::new(2, IpAddr::V4(ipv4_addr), 22, 6, 0);
        let ipv6_event = NetworkEvent::new(
            10,
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            22,
            6,
            0,
        );

        assert_eq!(ipv4_event.ipv4(), Some(ipv4_addr));
        assert_eq!(ipv6_event.ipv4(), None);
    }

    #[test]
    fn test_ipv6_method() {
        let ipv6_addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let ipv6_event = NetworkEvent::new(10, IpAddr::V6(ipv6_addr), 22, 6, 0);
        let ipv4_event = NetworkEvent::new(2, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 22, 6, 0);

        assert_eq!(ipv6_event.ipv6(), Some(ipv6_addr));
        assert_eq!(ipv4_event.ipv6(), None);
    }

    #[test]
    fn test_is_tcp() {
        let tcp_event = NetworkEvent::new(2, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 22, 6, 0);
        let udp_event = NetworkEvent::new(2, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 53, 17, 0);
        let other_event =
            NetworkEvent::new(2, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 123, 1, 0);

        assert!(tcp_event.is_tcp());
        assert!(!udp_event.is_tcp());
        assert!(!other_event.is_tcp());
    }

    #[test]
    fn test_is_udp() {
        let tcp_event = NetworkEvent::new(2, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 22, 6, 0);
        let udp_event = NetworkEvent::new(2, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 53, 17, 0);
        let other_event =
            NetworkEvent::new(2, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 123, 1, 0);

        assert!(!tcp_event.is_udp());
        assert!(udp_event.is_udp());
        assert!(!other_event.is_udp());
    }

    #[test]
    fn test_ban_action_new() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let ban = BanAction::new(
            ip,
            "ssh_bruteforce".to_string(),
            3600,
            "exceeded threshold".to_string(),
        );

        assert_eq!(ban.src_ip, ip);
        assert_eq!(ban.rule_name, "ssh_bruteforce");
        assert_eq!(ban.duration, 3600);
        assert_eq!(ban.reason, "exceeded threshold");
        assert_eq!(ban.cidr, None);
        assert!(!ban.is_cidr_ban());
        assert_eq!(ban.get_target(), "192.168.1.100");
    }

    #[test]
    fn test_ban_action_new_cidr() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let cidr: IpNet = "192.168.1.0/24".parse().unwrap();
        let ban = BanAction::new_cidr(
            ip,
            "tcp_scan".to_string(),
            7200,
            "CIDR threshold exceeded".to_string(),
            cidr,
        );

        assert_eq!(ban.src_ip, ip);
        assert_eq!(ban.rule_name, "tcp_scan");
        assert_eq!(ban.duration, 7200);
        assert_eq!(ban.reason, "CIDR threshold exceeded");
        assert!(ban.is_cidr_ban());
        assert_eq!(ban.get_target(), "192.168.1.0/24");
    }

    #[test]
    fn test_network_event_partial_eq() {
        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

        let event1 = NetworkEvent::new(2, ip1, 22, 6, 12345);
        let event2 = NetworkEvent::new(2, ip1, 22, 6, 12345);
        let event3 = NetworkEvent::new(2, ip2, 22, 6, 12345);

        assert_eq!(event1, event2);
        assert_ne!(event1, event3);
    }

    #[test]
    fn test_ban_action_partial_eq() {
        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

        let ban1 = BanAction::new(ip1, "rule1".to_string(), 3600, "reason".to_string());
        let ban2 = BanAction::new(ip1, "rule1".to_string(), 3600, "reason".to_string());
        let ban3 = BanAction::new(ip2, "rule1".to_string(), 3600, "reason".to_string());

        assert_eq!(ban1, ban2);
        assert_ne!(ban1, ban3);
    }
}
