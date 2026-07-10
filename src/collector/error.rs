use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("program not found: {0}")]
    ProgramNotFound(&'static str),

    #[error("map not found: {0}")]
    MapNotFound(&'static str),

    #[error("failed to read events")]
    ReadEvents,

    #[error("invalid event data")]
    InvalidEventData,

    #[cfg(feature = "ebpf")]
    #[error("aya error: {0}")]
    Aya(#[from] aya::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
