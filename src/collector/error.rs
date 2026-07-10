use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to read events")]
    ReadEvents,

    #[error("invalid event data")]
    InvalidEventData,
}

pub type Result<T> = std::result::Result<T, Error>;
