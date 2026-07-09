use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("channel receive error")]
    ChannelReceive,

    #[error("rule engine error")]
    RuleEngine,
}

pub type Result<T> = std::result::Result<T, Error>;
