use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("channel send error")]
    ChannelSend,

    #[error("channel receive error")]
    ChannelReceive,
}

pub type Result<T> = std::result::Result<T, Error>;