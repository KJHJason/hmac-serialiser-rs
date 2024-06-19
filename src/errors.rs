use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum Error {
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("invalid signature provided")]
    InvalidSignature,
    #[error("invalid token provided")]
    InvalidToken,
    #[error("could not expand key")]
    HkdfExpandError,
    #[error("could not fill key")]
    HkdfFillError,
    #[error("token has expired")]
    TokenExpired,
}
