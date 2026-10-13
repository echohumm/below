//! the client's error type

use {
    crate::net::{TIMED_OUT, TRIES_EXCEEDED},
    common::{Data, ProtoError, code_to_name},
    std::{
        fmt::{self, Display, Formatter},
        io
    }
};

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Proto(ProtoError),
    /// the server sent a valid frame, but not the kind we were expecting
    Unexpected(Data),
    /// the server sent a status code which ends the connection
    Server(u8)
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "io error: {e}"),
            Error::Proto(ProtoError::IO(e)) => match e.kind() {
                io::ErrorKind::UnexpectedEof => write!(f, "the server closed the connection"),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => {
                    write!(f, "timed out waiting for the server")
                }
                _ => write!(f, "io error: {e}")
            },
            Error::Proto(e) => write!(f, "protocol error: {e}"),
            Error::Unexpected(d) => write!(f, "the server sent an unexpected frame: {d:?}"),
            Error::Server(TRIES_EXCEEDED) => write!(f, "too many failed attempts"),
            Error::Server(TIMED_OUT) => write!(f, "the server timed out waiting for input"),
            Error::Server(code) => {
                write!(f, "the server ended the session: {}", code_to_name(*code))
            }
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::Io(e)
    }
}
impl From<ProtoError> for Error {
    fn from(e: ProtoError) -> Error {
        Error::Proto(e)
    }
}
