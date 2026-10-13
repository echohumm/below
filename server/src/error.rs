//! the server's error type

use {
    common::ProtoError,
    core::fmt::{Display, Formatter, Result as FmtRes},
    std::{io, net::IpAddr}
};

#[derive(Debug)]
pub enum Error {
    Closed,
    InputTries,
    Timeout,
    UsernameMax,
    PasswordMax,
    CorruptedData,
    Banned(IpAddr),
    Proto(ProtoError),
    IO(io::Error)
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtRes {
        match self {
            Error::Closed => write!(f, "connection closed by client"),
            Error::InputTries => write!(f, "maximum input attempts expended"),
            Error::Timeout => write!(f, "input timed out"),
            Error::UsernameMax => write!(f, "username maximum length exceeded"),
            Error::PasswordMax => write!(f, "password maximum length exceeded"),
            Error::CorruptedData => write!(f, "received corrupted data"),
            Error::Banned(id) => write!(f, "ip is banned: {id}"),
            Error::Proto(e) => write!(f, "protocol: {e}"),
            Error::IO(e) => write!(f, "io error during operation: {e}")
        }
    }
}

// these make `?` work on io/protocol results in functions returning `Result<_, Error>`
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::IO(e)
    }
}
impl From<ProtoError> for Error {
    fn from(e: ProtoError) -> Error {
        Error::Proto(e)
    }
}
