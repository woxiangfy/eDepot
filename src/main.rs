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

fn init_logging(log_level: &str) {
    let level = match log_level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => {
            eprintln!("Warning: Invalid log level '{}', defaulting to 'info'", log_level);
            Level::INFO
        }
    };

    tracing_subscriber::fmt()
        .with_max_level(level)
        .init();

    info!("Logging initialized with level: {}", level);
}

#[tokio::main]
async fn main() -> Result<()> {
    let config = Arc::new(Config::from_file("config.toml")?);

    init_logging(&config.global.log_level);

    info!("eDepot Host Defense System starting...");
    debug!("Process ID: {}", std::process::id());

    print_environment_report();

    if !is_environment_supported() {
        error!("Environment check failed - eDepot requires Linux with eBPF and nftables support");
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
    let mut collector = Collector::new(event_tx).await?;
    debug!("Collector initialized");

    debug!("Loading tracepoint");
    collector.load_tracepoint().await?;
    debug!("Tracepoint loaded");

    info!("eDepot is now running in defense mode");
    debug!("All components started successfully");

    let _ = tokio::signal::ctrl_c().await;
    info!("Received shutdown signal");
    debug!("Initiating graceful shutdown");

    Ok(())
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
}
