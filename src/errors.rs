use derive_more::{Display, Error};

#[derive(Debug, Display, Error)]
pub enum Error {
    #[display(fmt = "invalid input")]
    InvalidInput,
    #[display(fmt = "invalid signature provided")]
    InvalidSignature,
    #[display(fmt = "invalid token provided")]
    InvalidToken,
    #[display(fmt = "could not expand key")]
    HkdfExpandError,
    #[display(fmt = "could not fill key")]
    HkdfFillError,
    #[display(fmt = "token has expired")]
    TokenExpired,
}
