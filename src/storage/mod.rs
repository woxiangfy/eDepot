use std::path::Path;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use tracing::{debug, info};

use crate::event::BanAction;

pub mod error;
pub use error::{Error, Result};

#[derive(Debug, Clone)]
pub struct AttackEvent {
    pub id: i64,
    pub source_ip: String,
    pub protocol: String,
    pub port: u16,
    pub rule: String,
    pub count: u32,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct BanRecord {
    pub id: i64,
    pub ip: String,
    pub duration: u32,
    pub reason: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

pub struct Storage {
    conn: Arc<Mutex<Connection>>,
}

impl Storage {
    /// 创建新的存储实例
    ///
    /// 打开 SQLite 数据库连接并初始化表结构
    ///
    /// # 参数
    ///
    /// * `path` - 数据库文件路径
    ///
    /// # 返回值
    ///
    /// 返回 Storage 实例，或错误信息
    pub fn new(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        Self::init_tables(&conn)?;

        info!("Storage initialized at: {}", path.display());
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// 初始化数据库表结构
    ///
    /// 创建 attack_events 和 ban_records 表以及相应的索引
    fn init_tables(conn: &Connection) -> Result<()> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS attack_events (
                id INTEGER PRIMARY KEY,
                source_ip TEXT NOT NULL,
                protocol TEXT NOT NULL,
                port INTEGER NOT NULL,
                rule TEXT NOT NULL,
                count INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS ban_records (
                id INTEGER PRIMARY KEY,
                ip TEXT NOT NULL,
                duration INTEGER NOT NULL,
                reason TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_attack_events_source_ip ON attack_events(source_ip)",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_ban_records_ip ON ban_records(ip)",
            [],
        )?;

        Ok(())
    }

    /// 插入攻击事件
    ///
    /// # 参数
    ///
    /// * `source_ip` - 源 IP 地址
    /// * `protocol` - 协议类型
    /// * `port` - 目标端口
    /// * `rule` - 触发的规则名称
    /// * `count` - 事件计数
    ///
    /// # 返回值
    ///
    /// 返回插入记录的 ID
    pub fn insert_attack_event(
        &self,
        source_ip: &str,
        protocol: &str,
        port: u16,
        rule: &str,
        count: u32,
    ) -> Result<i64> {
        let now = Utc::now().timestamp() as i64;
        let conn = self.conn.lock().unwrap();

        conn.execute(
            "INSERT INTO attack_events (source_ip, protocol, port, rule, count, created_at)
             VALUES (?, ?, ?, ?, ?, ?)",
            params![source_ip, protocol, port, rule, count, now],
        )?;

        Ok(conn.last_insert_rowid())
    }

    /// 插入封禁记录
    ///
    /// # 参数
    ///
    /// * `ban` - 封禁动作
    ///
    /// # 返回值
    ///
    /// 返回插入记录的 ID
    pub fn insert_ban_record(&self, ban: &BanAction) -> Result<i64> {
        let now = Utc::now().timestamp() as i64;
        let conn = self.conn.lock().unwrap();

        conn.execute(
            "INSERT INTO ban_records (ip, duration, reason, status, created_at)
             VALUES (?, ?, ?, ?, ?)",
            params![
                ban.src_ip.to_string(),
                ban.duration,
                ban.reason,
                "active",
                now
            ],
        )?;

        info!(
            "Ban record inserted: ip={}, rule={}, duration={}",
            ban.src_ip, ban.rule_name, ban.duration
        );
        Ok(conn.last_insert_rowid())
    }

    /// 更新封禁状态
    ///
    /// 将指定 IP 的活跃封禁记录更新为新状态
    ///
    /// # 参数
    ///
    /// * `ip` - IP 地址
    /// * `status` - 新状态（如 "expired", "removed"）
    pub fn update_ban_status(&self, ip: &str, status: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE ban_records SET status = ? WHERE ip = ? AND status = 'active'",
            params![status, ip],
        )?;

        Ok(())
    }

    /// 获取攻击事件列表
    ///
    /// # 参数
    ///
    /// * `limit` - 返回的最大记录数
    ///
    /// # 返回值
    ///
    /// 返回攻击事件列表，按时间降序排列
    pub fn get_attack_events(&self, limit: usize) -> Result<Vec<AttackEvent>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, source_ip, protocol, port, rule, count, created_at
             FROM attack_events ORDER BY created_at DESC LIMIT ?",
        )?;

        let mut events = Vec::new();
        let mut rows = stmt.query(params![limit])?;
        while let Some(row) = rows.next()? {
            events.push(AttackEvent {
                id: row.get(0)?,
                source_ip: row.get(1)?,
                protocol: row.get(2)?,
                port: row.get(3)?,
                rule: row.get(4)?,
                count: row.get(5)?,
                created_at: DateTime::from_timestamp(row.get(6)?, 0).unwrap_or_else(|| Utc::now()),
            });
        }

        Ok(events)
    }

    /// 获取封禁记录列表
    ///
    /// # 参数
    ///
    /// * `status` - 可选的状态过滤（如 "active"）
    ///
    /// # 返回值
    ///
    /// 返回封禁记录列表，按时间降序排列
    pub fn get_ban_records(&self, status: Option<&str>) -> Result<Vec<BanRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut records = Vec::new();

        if let Some(s) = status {
            let mut stmt = conn.prepare(
                "SELECT id, ip, duration, reason, status, created_at
                 FROM ban_records WHERE status = ? ORDER BY created_at DESC",
            )?;
            let mut rows = stmt.query(params![s])?;
            while let Some(row) = rows.next()? {
                records.push(BanRecord {
                    id: row.get(0)?,
                    ip: row.get(1)?,
                    duration: row.get(2)?,
                    reason: row.get(3)?,
                    status: row.get(4)?,
                    created_at: DateTime::from_timestamp(row.get(5)?, 0)
                        .unwrap_or_else(|| Utc::now()),
                });
            }
        } else {
            let mut stmt = conn.prepare(
                "SELECT id, ip, duration, reason, status, created_at
                 FROM ban_records ORDER BY created_at DESC",
            )?;
            let mut rows = stmt.query(params![])?;
            while let Some(row) = rows.next()? {
                records.push(BanRecord {
                    id: row.get(0)?,
                    ip: row.get(1)?,
                    duration: row.get(2)?,
                    reason: row.get(3)?,
                    status: row.get(4)?,
                    created_at: DateTime::from_timestamp(row.get(5)?, 0)
                        .unwrap_or_else(|| Utc::now()),
                });
            }
        }

        Ok(records)
    }

    /// 清理过期的攻击事件
    ///
    /// 删除指定天数之前的攻击事件记录
    ///
    /// # 参数
    ///
    /// * `days` - 保留天数
    ///
    /// # 返回值
    ///
    /// 返回删除的记录数
    pub fn cleanup_old_events(&self, days: u32) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        let cutoff = Utc::now().timestamp() - (days as i64 * 24 * 60 * 60);

        let count = conn.execute(
            "DELETE FROM attack_events WHERE created_at < ?",
            params![cutoff],
        )?;

        debug!("Cleaned up {} old attack events", count);
        Ok(count as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use tempfile::NamedTempFile;

    #[test]
    fn test_storage_new() {
        let temp_file = NamedTempFile::new().unwrap();
        let result = Storage::new(temp_file.path());

        assert!(result.is_ok());
    }

    #[test]
    fn test_insert_attack_event() {
        let temp_file = NamedTempFile::new().unwrap();
        let storage = Storage::new(temp_file.path()).unwrap();

        let id = storage
            .insert_attack_event("192.168.1.100", "tcp", 22, "ssh_bruteforce", 10)
            .unwrap();

        assert!(id > 0);
    }

    #[test]
    fn test_insert_ban_record_ipv4() {
        let temp_file = NamedTempFile::new().unwrap();
        let storage = Storage::new(temp_file.path()).unwrap();

        let ban = BanAction::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            "ssh_bruteforce".to_string(),
            3600,
            "exceeded threshold".to_string(),
        );

        let id = storage.insert_ban_record(&ban).unwrap();

        assert!(id > 0);
    }

    #[test]
    fn test_insert_ban_record_ipv6() {
        let temp_file = NamedTempFile::new().unwrap();
        let storage = Storage::new(temp_file.path()).unwrap();

        let ban = BanAction::new(
            IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            "web_attack".to_string(),
            7200,
            "high frequency".to_string(),
        );

        let id = storage.insert_ban_record(&ban).unwrap();

        assert!(id > 0);
    }

    #[test]
    fn test_get_attack_events() {
        let temp_file = NamedTempFile::new().unwrap();
        let storage = Storage::new(temp_file.path()).unwrap();

        storage
            .insert_attack_event("192.168.1.100", "tcp", 22, "ssh_bruteforce", 10)
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1));
        storage
            .insert_attack_event("10.0.0.1", "udp", 53, "udp_scan", 50)
            .unwrap();

        let events = storage.get_attack_events(10).unwrap();

        assert_eq!(events.len(), 2);
        let ips: Vec<String> = events.iter().map(|e| e.source_ip.clone()).collect();
        assert!(ips.contains(&"10.0.0.1".to_string()));
        assert!(ips.contains(&"192.168.1.100".to_string()));
    }

    #[test]
    fn test_get_ban_records_all() {
        let temp_file = NamedTempFile::new().unwrap();
        let storage = Storage::new(temp_file.path()).unwrap();

        let ban1 = BanAction::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            "ssh_bruteforce".to_string(),
            3600,
            "test1".to_string(),
        );
        let ban2 = BanAction::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            "tcp_scan".to_string(),
            7200,
            "test2".to_string(),
        );

        storage.insert_ban_record(&ban1).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1));
        storage.insert_ban_record(&ban2).unwrap();

        let records = storage.get_ban_records(None).unwrap();

        assert_eq!(records.len(), 2);
        let ips: Vec<String> = records.iter().map(|r| r.ip.clone()).collect();
        assert!(ips.contains(&"10.0.0.1".to_string()));
        assert!(ips.contains(&"192.168.1.100".to_string()));
    }

    #[test]
    fn test_get_ban_records_filtered() {
        let temp_file = NamedTempFile::new().unwrap();
        let storage = Storage::new(temp_file.path()).unwrap();

        let ban = BanAction::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            "ssh_bruteforce".to_string(),
            3600,
            "test".to_string(),
        );

        storage.insert_ban_record(&ban).unwrap();

        let active_records = storage.get_ban_records(Some("active")).unwrap();
        let expired_records = storage.get_ban_records(Some("expired")).unwrap();

        assert_eq!(active_records.len(), 1);
        assert_eq!(expired_records.len(), 0);
    }

    #[test]
    fn test_update_ban_status() {
        let temp_file = NamedTempFile::new().unwrap();
        let storage = Storage::new(temp_file.path()).unwrap();

        let ban = BanAction::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            "ssh_bruteforce".to_string(),
            3600,
            "test".to_string(),
        );

        storage.insert_ban_record(&ban).unwrap();

        let result = storage.update_ban_status("192.168.1.100", "expired");

        assert!(result.is_ok());

        let active_records = storage.get_ban_records(Some("active")).unwrap();
        let expired_records = storage.get_ban_records(Some("expired")).unwrap();

        assert_eq!(active_records.len(), 0);
        assert_eq!(expired_records.len(), 1);
    }

    #[test]
    fn test_cleanup_old_events() {
        let temp_file = NamedTempFile::new().unwrap();
        let storage = Storage::new(temp_file.path()).unwrap();

        storage
            .insert_attack_event("192.168.1.100", "tcp", 22, "ssh_bruteforce", 10)
            .unwrap();
        storage
            .insert_attack_event("10.0.0.1", "udp", 53, "udp_scan", 50)
            .unwrap();

        let count = storage.cleanup_old_events(365).unwrap();

        assert_eq!(count, 0);

        storage.cleanup_old_events(0).unwrap();

        let events = storage.get_attack_events(10).unwrap();

        assert!(events.len() <= 2);
    }

    #[test]
    fn test_attack_event_partial_eq() {
        let event1 = AttackEvent {
            id: 1,
            source_ip: "192.168.1.100".to_string(),
            protocol: "tcp".to_string(),
            port: 22,
            rule: "ssh_bruteforce".to_string(),
            count: 10,
            created_at: Utc::now(),
        };
        let event2 = AttackEvent {
            id: 1,
            source_ip: "192.168.1.100".to_string(),
            protocol: "tcp".to_string(),
            port: 22,
            rule: "ssh_bruteforce".to_string(),
            count: 10,
            created_at: Utc::now(),
        };

        assert_eq!(event1.id, event2.id);
        assert_eq!(event1.source_ip, event2.source_ip);
    }

    #[test]
    fn test_ban_record_partial_eq() {
        let record1 = BanRecord {
            id: 1,
            ip: "192.168.1.100".to_string(),
            duration: 3600,
            reason: "test".to_string(),
            status: "active".to_string(),
            created_at: Utc::now(),
        };
        let record2 = BanRecord {
            id: 1,
            ip: "192.168.1.100".to_string(),
            duration: 3600,
            reason: "test".to_string(),
            status: "active".to_string(),
            created_at: Utc::now(),
        };

        assert_eq!(record1.id, record2.id);
        assert_eq!(record1.ip, record2.ip);
        assert_eq!(record1.status, record2.status);
    }
}
