use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("config error: {0}")]
    Config(#[from] crate::config::Error),

    #[error("collector error: {0}")]
    Collector(#[from] crate::collector::Error),

    #[error("dispatcher error: {0}")]
    Dispatcher(#[from] crate::dispatcher::Error),

    #[error("worker error: {0}")]
    Worker(#[from] crate::worker::Error),

    #[error("rules error: {0}")]
    Rules(#[from] crate::rules::Error),

    #[error("nftables error: {0}")]
    Nftables(#[from] crate::nft::Error),

    #[error("storage error: {0}")]
    Storage(#[from] crate::storage::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("tokio join error: {0}")]
    TokioJoin(#[from] tokio::task::JoinError),

    #[error("channel send failed")]
    ChannelSendFailed,
}

pub type Result<T> = std::result::Result<T, Error>;
