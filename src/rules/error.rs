use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid protocol: {0}")]
    InvalidProtocol(String),

    #[error("invalid rule type: {0}")]
    InvalidRuleType(String),

    #[error("rule not found: {0}")]
    RuleNotFound(String),

    #[error("channel send error")]
    ChannelSend,
}

pub type Result<T> = std::result::Result<T, Error>;
