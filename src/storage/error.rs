use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("invalid datetime")]
    InvalidDatetime,
}

pub type Result<T> = std::result::Result<T, Error>;