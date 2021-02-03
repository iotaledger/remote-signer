pub mod common;
use thiserror::Error as DeriveError;

pub type Result<T> = std::result::Result<T, RemoteSignerError>;

#[derive(DeriveError, Debug)]
pub enum RemoteSignerError {
    #[error("Something went wrong while the server was running. '{0}'" )]
    TonicError(#[from] tonic::transport::Error),
    #[error("Something went wrong while parsing configs. `{0}'")]
    Config(#[from] config::ConfigError),
    #[error("Something went wrong with network address parsing. `{0}'")]
    AddrParse(#[from] std::net::AddrParseError),
    #[error("Something went wrong. '{0}'")]
    Anyhow(#[from] anyhow::Error),
    #[error("Something went wrong. '{0}'")]
    Unknown(String),
}