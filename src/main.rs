use std::path::Path;
use std::sync::Arc;

use tokio::sync::mpsc;
use tracing::{debug, error, info, warn, Level};

use edepot::collector::Collector;
use edepot::config::Config;
use edepot::dispatcher::Dispatcher;
use edepot::env_check::{is_environment_supported, print_environment_report};
use edepot::error::Result;
use edepot::event::{BanAction, NetworkEvent};
use edepot::nft::NftController;
use edepot::rules::{Rule, RuleEngine};
use edepot::storage::Storage;
use edepot::worker::Worker;

/// CLI 用法说明
const USAGE: &str = "\
eDepot Host Defense System

USAGE:
    edepot <COMMAND> [OPTIONS]

COMMANDS:
    start          启动防御服务（加载配置、初始化 nftables、开始监控）
    check          校验配置文件（不启动服务，仅检查配置是否正确）

OPTIONS:
    -c, --config <FILE>    指定配置文件路径（默认: config.toml）
    -h, --help             显示帮助信息
";

/// CLI 参数解析
struct CliArgs {
    command: String,
    config_path: String,
}

/// 解析命令行参数
///
/// 支持的格式：
///   edepot start [-c config.toml]
///   edepot check [-c config.toml]
///   edepot --help / -h
fn parse_args() -> Result<CliArgs> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("{}", USAGE);
        std::process::exit(1);
    }

    let first = &args[1];
    if first == "-h" || first == "--help" {
        println!("{}", USAGE);
        std::process::exit(0);
    }

    let command = first.clone();
    if command != "start" && command != "check" {
        eprintln!("Error: unknown command '{}'\n", command);
        eprintln!("{}", USAGE);
        std::process::exit(1);
    }

    let mut config_path = "config.toml".to_string();
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "-c" | "--config" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: missing value for '{}'", args[i]);
                    std::process::exit(1);
                }
                config_path = args[i + 1].clone();
                i += 2;
            }
            other => {
                eprintln!("Error: unknown option '{}'", other);
                std::process::exit(1);
            }
        }
    }

    Ok(CliArgs {
        command,
        config_path,
    })
}

/// 初始化日志系统
///
/// 根据配置文件中的 log_level 设置全局日志级别
fn init_logging(log_level: &str) {
    let level = match log_level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => {
            eprintln!(
                "Warning: Invalid log level '{}', defaulting to 'info'",
                log_level
            );
            Level::INFO
        }
    };

    tracing_subscriber::fmt().with_max_level(level).init();

    info!("Logging initialized with level: {}", level);
}

/// 执行 check 命令：校验配置文件
///
/// 加载并验证配置文件，输出校验结果，不启动服务
fn run_check(config_path: &str) -> Result<()> {
    println!("Checking config file: {}", config_path);

    let config = Config::from_file(config_path)?;

    config.validate()?;

    // 尝试解析规则，确保规则配置可被正确转换
    let rules: Vec<Rule> = config
        .rules
        .iter()
        .map(Rule::from_config)
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| edepot::error::Error::Rules(e))?;

    println!("Config validation passed!");
    println!("  Worker count: {}", config.global.worker_count);
    println!("  NFT table: {}", config.global.nft_table);
    println!("  Poll interval: {}ms", config.global.poll_interval_ms);
    println!("  Log level: {}", config.global.log_level);
    println!("  Whitelist CIDRs: {}", config.whitelist_count());
    println!(
        "  Rules: {} (parsed {} successfully)",
        config.rules.len(),
        rules.len()
    );
    println!(
        "  Memory: max_entries={}, cleanup_interval={}s",
        config.memory.max_entries, config.memory.cleanup_interval
    );

    for rule in &rules {
        println!(
            "    - {} (proto={}, ports={:?}, type={:?}, threshold={}, window={}s, block={}s)",
            rule.name,
            rule.protocol,
            rule.ports,
            rule.rule_type,
            rule.threshold,
            rule.window_secs,
            rule.block_duration
        );
    }

    Ok(())
}

/// 执行 start 命令：启动防御服务
///
/// 完整启动流程：加载配置 -> 环境检查 -> 初始化存储 -> 创建通道 ->
/// 初始化 nftables -> 启动 Worker -> 启动 Dispatcher -> 启动 Collector
async fn run_start(config_path: &str) -> Result<()> {
    let config = Arc::new(Config::from_file(config_path)?);

    init_logging(&config.global.log_level);

    info!("eDepot Host Defense System starting...");
    debug!("Process ID: {}", std::process::id());

    print_environment_report();

    if !is_environment_supported() {
        error!("Environment check failed - eDepot requires Linux with nftables support");
        std::process::exit(1);
    }
    debug!("Environment check passed");

    info!("Config loaded successfully");
    debug!(
        "Config: worker_count={}, nft_table={}, rules={}, log_level={}",
        config.global.worker_count,
        config.global.nft_table,
        config.rules.len(),
        config.global.log_level
    );

    debug!("Initializing storage at edepot.db");
    let storage = Storage::new(Path::new("edepot.db"))?;
    debug!("Storage initialized successfully");

    debug!("Creating channels");
    let (event_tx, event_rx) = mpsc::channel::<NetworkEvent>(1024);
    debug!("Event channel created with capacity 1024");

    let (ban_tx, ban_rx) = mpsc::channel::<BanAction>(128);
    debug!("Ban channel created with capacity 128");

    let (storage_ban_tx, mut storage_ban_rx) = mpsc::channel::<BanAction>(128);
    debug!("Storage ban channel created with capacity 128");

    debug!("Initializing NFT controller");
    let nft_controller = NftController::new(config.clone()).await?;
    debug!("NFT controller initialized");

    debug!("Parsing rules from config");
    let rules: Vec<Rule> = config
        .rules
        .iter()
        .map(Rule::from_config)
        .collect::<std::result::Result<_, _>>()?;
    info!("Loaded {} rules", rules.len());
    for rule in &rules {
        debug!(
            "Rule: {} (protocol={}, ports={:?}, threshold={}, window={}s)",
            rule.name, rule.protocol, rule.ports, rule.threshold, rule.window_secs
        );
    }

    debug!("Creating {} workers", config.global.worker_count);
    let mut worker_senders = Vec::with_capacity(config.global.worker_count);
    for i in 0..config.global.worker_count {
        let (worker_tx, worker_rx) = mpsc::channel::<NetworkEvent>(512);
        let ban_tx_clone = ban_tx.clone();
        let storage_ban_tx_clone = storage_ban_tx.clone();
        let rules_clone = rules.clone();
        let config_clone = config.clone();

        worker_senders.push(worker_tx);

        tokio::spawn(async move {
            debug!("Starting worker {}", i);
            let rule_engine = RuleEngine::new(rules_clone, ban_tx_clone, storage_ban_tx_clone);
            let worker = Worker::new(i, config_clone, rule_engine, worker_rx);
            debug!("Worker {} started", i);
            if let Err(e) = worker.run().await {
                error!("Worker {} error: {}", i, e);
            }
            debug!("Worker {} exited", i);
        });
    }

    debug!("Creating dispatcher");
    let dispatcher = Dispatcher::new(config.clone(), worker_senders);
    tokio::spawn(async move {
        debug!("Dispatcher started");
        if let Err(e) = dispatcher.run(event_rx).await {
            error!("Dispatcher error: {}", e);
        }
        debug!("Dispatcher exited");
    });

    tokio::spawn(async move {
        debug!("NFT controller started");
        if let Err(e) = nft_controller.run(ban_rx).await {
            error!("NFT controller error: {}", e);
        }
        debug!("NFT controller exited");
    });

    tokio::spawn(async move {
        debug!("Storage writer task started");
        while let Some(ban) = storage_ban_rx.recv().await {
            debug!("Writing ban record for IP: {}", ban.src_ip);
            if let Err(e) = storage.insert_ban_record(&ban) {
                warn!("Failed to insert ban record: {}", e);
            } else {
                debug!("Ban record written successfully for IP: {}", ban.src_ip);
            }
        }
        debug!("Storage writer task exited");
    });

    debug!("Initializing collector");
    debug!(
        "Polling /proc/net with interval: {}ms",
        config.global.poll_interval_ms
    );

    let mut collector = Collector::new(event_tx, config.global.poll_interval_ms).await?;
    debug!("Collector initialized");

    debug!("Starting event loop");
    collector.start_event_loop().await?;
    debug!("Event loop started");

    info!("eDepot is now running in defense mode");
    debug!("All components started successfully");

    let _ = tokio::signal::ctrl_c().await;
    info!("Received shutdown signal");
    debug!("Initiating graceful shutdown");

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = parse_args()?;

    match cli.command.as_str() {
        "check" => run_check(&cli.config_path),
        "start" => run_start(&cli.config_path).await,
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_config_load() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();
        drop(temp_file);

        let mut file = File::create(&path).unwrap();
        writeln!(
            file,
            r#"
[global]
worker_count = 4
nft_table = "edepot"

[whitelist]
cidr = ["127.0.0.0/8"]

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

        let config = Config::from_file(path.to_str().unwrap());

        assert!(config.is_ok());
        assert_eq!(config.unwrap().global.worker_count, 4);
    }

    #[test]
    fn test_storage_init() {
        let temp_file = NamedTempFile::new().unwrap();
        let storage = Storage::new(temp_file.path());

        assert!(storage.is_ok());
    }

    #[test]
    fn test_rule_parsing() {
        let config = Config {
            global: edepot::config::GlobalConfig {
                worker_count: 4,
                nft_table: "edepot".to_string(),
                log_level: "info".to_string(),
                poll_interval_ms: 1000,
            },
            whitelist: edepot::config::WhitelistConfig { cidr: Vec::new() },
            rules: vec![edepot::config::RuleConfig {
                name: "test_rule".to_string(),
                protocol: "tcp".to_string(),
                ports: Some(vec![22]),
                rule_type: "ip".to_string(),
                window_secs: 20,
                threshold: 10,
                block_duration: 3600,
                ipv4_prefix: None,
                ipv6_prefix: None,
            }],
            memory: edepot::config::MemoryConfig {
                max_entries: 100000,
                cleanup_interval: 60,
            },
        };

        let rules_result: std::result::Result<Vec<Rule>, edepot::rules::Error> =
            config.rules.iter().map(Rule::from_config).collect();

        assert!(rules_result.is_ok());
        assert_eq!(rules_result.unwrap().len(), 1);
    }

    #[test]
    fn test_validate_valid_config() {
        let config = Config {
            global: edepot::config::GlobalConfig {
                worker_count: 4,
                nft_table: "edepot".to_string(),
                log_level: "info".to_string(),
                poll_interval_ms: 1000,
            },
            whitelist: edepot::config::WhitelistConfig {
                cidr: vec!["127.0.0.0/8".to_string(), "::1/128".to_string()],
            },
            rules: vec![edepot::config::RuleConfig {
                name: "ssh_bruteforce".to_string(),
                protocol: "tcp".to_string(),
                ports: Some(vec![22]),
                rule_type: "ip".to_string(),
                window_secs: 20,
                threshold: 8,
                block_duration: 3600,
                ipv4_prefix: None,
                ipv6_prefix: None,
            }],
            memory: edepot::config::MemoryConfig {
                max_entries: 100000,
                cleanup_interval: 60,
            },
        };

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_invalid_worker_count() {
        let config = Config {
            global: edepot::config::GlobalConfig {
                worker_count: 0,
                nft_table: "edepot".to_string(),
                log_level: "info".to_string(),
                poll_interval_ms: 1000,
            },
            whitelist: edepot::config::WhitelistConfig { cidr: Vec::new() },
            rules: Vec::new(),
            memory: edepot::config::MemoryConfig {
                max_entries: 100000,
                cleanup_interval: 60,
            },
        };

        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_invalid_cidr() {
        let config = Config {
            global: edepot::config::GlobalConfig {
                worker_count: 4,
                nft_table: "edepot".to_string(),
                log_level: "info".to_string(),
                poll_interval_ms: 1000,
            },
            whitelist: edepot::config::WhitelistConfig {
                cidr: vec!["invalid-cidr".to_string()],
            },
            rules: Vec::new(),
            memory: edepot::config::MemoryConfig {
                max_entries: 100000,
                cleanup_interval: 60,
            },
        };

        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_invalid_protocol() {
        let config = Config {
            global: edepot::config::GlobalConfig {
                worker_count: 4,
                nft_table: "edepot".to_string(),
                log_level: "info".to_string(),
                poll_interval_ms: 1000,
            },
            whitelist: edepot::config::WhitelistConfig { cidr: Vec::new() },
            rules: vec![edepot::config::RuleConfig {
                name: "bad_rule".to_string(),
                protocol: "icmp".to_string(),
                ports: None,
                rule_type: "ip".to_string(),
                window_secs: 20,
                threshold: 8,
                block_duration: 3600,
                ipv4_prefix: None,
                ipv6_prefix: None,
            }],
            memory: edepot::config::MemoryConfig {
                max_entries: 100000,
                cleanup_interval: 60,
            },
        };

        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_cidr_rule_missing_prefix() {
        let config = Config {
            global: edepot::config::GlobalConfig {
                worker_count: 4,
                nft_table: "edepot".to_string(),
                log_level: "info".to_string(),
                poll_interval_ms: 1000,
            },
            whitelist: edepot::config::WhitelistConfig { cidr: Vec::new() },
            rules: vec![edepot::config::RuleConfig {
                name: "cidr_rule".to_string(),
                protocol: "tcp".to_string(),
                ports: None,
                rule_type: "cidr".to_string(),
                window_secs: 60,
                threshold: 100,
                block_duration: 3600,
                ipv4_prefix: None,
                ipv6_prefix: None,
            }],
            memory: edepot::config::MemoryConfig {
                max_entries: 100000,
                cleanup_interval: 60,
            },
        };

        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_invalid_memory() {
        let config = Config {
            global: edepot::config::GlobalConfig {
                worker_count: 4,
                nft_table: "edepot".to_string(),
                log_level: "info".to_string(),
                poll_interval_ms: 1000,
            },
            whitelist: edepot::config::WhitelistConfig { cidr: Vec::new() },
            rules: Vec::new(),
            memory: edepot::config::MemoryConfig {
                max_entries: 0,
                cleanup_interval: 60,
            },
        };

        assert!(config.validate().is_err());
    }

    #[test]
    fn test_parse_args_no_args() {
        // 无参数应返回错误（通过进程退出）
        // 此测试验证 parse_args 在无参数时的行为
        // 由于 parse_args 直接调用 std::process::exit，
        // 我们只能测试有参数的场景
    }

    #[test]
    fn test_run_check_valid_config() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();
        drop(temp_file);

        let mut file = File::create(&path).unwrap();
        writeln!(
            file,
            r#"
[global]
worker_count = 4
nft_table = "edepot"
log_level = "info"
poll_interval_ms = 1000

[whitelist]
cidr = ["127.0.0.0/8"]

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

        let result = run_check(path.to_str().unwrap());
        assert!(result.is_ok());
    }

    #[test]
    fn test_run_check_invalid_config() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();
        drop(temp_file);

        let mut file = File::create(&path).unwrap();
        writeln!(
            file,
            r#"
[global]
worker_count = 0
nft_table = ""
poll_interval_ms = 0

[whitelist]
cidr = ["invalid"]

[memory]
max_entries = 0
cleanup_interval = 0
"#
        )
        .unwrap();

        let result = run_check(path.to_str().unwrap());
        assert!(result.is_err());
    }
}
