use thiserror::Error;

use super::raw;

#[derive(Error, Debug)]
pub enum Error {
    #[error("nftables error: {0}")]
    Nftables(#[from] raw::Error),

    #[error("channel receive error")]
    ChannelReceive,
}

pub type Result<T> = std::result::Result<T, Error>;
