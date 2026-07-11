# eDepot - 主机自动化防御系统

eDepot 是一个基于 `/proc/net` 和 nftables 的主机自动化防御系统，能够实时监控网络流量，检测攻击行为，并自动封禁恶意 IP。

## 功能特性

- **`/proc/net` 轮询采集**：通过读取 `/proc/net/tcp`、`/proc/net/tcp6`、`/proc/net/udp`、`/proc/net/udp6` 文件获取网络连接信息，兼容性强，无需特殊内核配置
- **多维度规则检测**：支持基于 IP/CIDR 的滑动窗口检测，覆盖 SSH 暴力破解、CC 攻击、端口扫描等场景
- **nftables 内核级封禁**：通过 nftables 动态集合实现高效封禁
- **多 Worker 并行处理**：事件按源 IP 哈希分发到多个 Worker，充分利用多核 CPU
- **SQLite 审计存储**：所有攻击事件和封禁记录持久化存储，支持查询和回溯
- **环境自动检测**：启动时自动检测系统环境，确保满足运行要求

## 系统要求

- Linux 操作系统
- nftables 已安装
- root 权限运行

## 快速开始

### 编译

```bash
cargo build --release
```

### 配置

复制默认配置文件并根据需要修改：

```bash
cp config.toml my-config.toml
```

### 运行

eDepot 支持以下命令：

```bash
# 校验配置文件（不启动服务）
sudo ./target/release/edepot check

# 指定配置文件校验
sudo ./target/release/edepot check -c /path/to/config.toml

# 启动防御服务
sudo ./target/release/edepot start

# 指定配置文件启动
sudo ./target/release/edepot start -c /path/to/config.toml

# 查看帮助
./target/release/edepot --help
```

| 命令 | 说明 |
|------|------|
| `check` | 校验配置文件，检查配置项完整性和有效性，不启动服务 |
| `start` | 启动防御服务，包括环境检测、nftables 初始化、流量监控 |
| `-c, --config <FILE>` | 指定配置文件路径，默认 `config.toml` |
| `-h, --help` | 显示帮助信息 |

## 配置说明

### 全局配置

```toml
[global]
worker_count = 4            # Worker 线程数
nft_table = "edepot"        # nftables 表名
log_level = "info"          # 日志级别: debug/info/warn/error
poll_interval_ms = 1000     # /proc/net 轮询间隔（毫秒）
```

### 白名单

```toml
[whitelist]
cidr = [
    "127.0.0.0/8",          # IPv4 白名单
    "::1/128"               # IPv6 白名单
]
```

### 内存管理

```toml
[memory]
max_entries = 100000        # 最大状态条目数
cleanup_interval = 60       # 清理间隔（秒）
```

### 检测规则

```toml
[[rules]]
name = "ssh_bruteforce"     # 规则名称
protocol = "tcp"            # 协议: tcp/udp/icmp
ports = [22]                # 目标端口（可选，不填则匹配所有端口）
rule_type = "ip"            # 规则类型: ip/cidr
window_secs = 20            # 检测窗口（秒）
threshold = 8               # 阈值（窗口内连接数超过则封禁）
block_duration = 3600       # 封禁时长（秒）
```

## 项目架构

```
edepot/
├── src/
│   ├── main.rs               # 程序入口
│   ├── lib.rs                # 库文件
│   ├── error.rs              # 全局错误类型
│   ├── event.rs              # 事件定义
│   ├── config/               # 配置管理
│   ├── env_check/            # 环境检测
│   ├── collector/            # /proc/net 数据采集
│   ├── dispatcher/           # 事件分发器
│   ├── worker/               # Worker 处理
│   ├── rules/                # 规则引擎
│   ├── nft/                  # nftables 控制
│   └── storage/              # SQLite 存储
├── config.toml               # 默认配置文件
├── Cargo.toml                # 项目配置
└── build.rs                  # 构建脚本
```

## 数据流

```
/proc/net Collector → Dispatcher → Worker (Rule Engine) → nftables (封禁)
                                                              ↓
                                                        Storage (审计)
```

## 测试

运行所有测试：

```bash
cargo test
```

## License

MIT