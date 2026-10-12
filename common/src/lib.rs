//! common protocol types and functions for the workspace

#![allow(unknown_lints)]
#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::multiple_unsafe_ops_per_block,
    clippy::undocumented_unsafe_blocks,
    clippy::unsafe_op_in_unsafe_fn,
    missing_docs
)]
#![warn(clippy::missing_errors_doc)]
#![allow(
    clippy::inline_always,
    clippy::borrow_as_ptr,
    clippy::module_name_repetitions,
    clippy::use_self,
    clippy::question_mark,
    clippy::cast_lossless,
    unused_unsafe
)]

extern crate alloc;

use std::time::Duration;
use {
    alloc::string::FromUtf8Error,
    core::{
        fmt::{Display, Formatter, Result as FmtRes},
        ops::Range,
    },
    std::io::{self, Read, Write},
};

// ---------------------------------------------------------------------------------------------
// global constants
// ---------------------------------------------------------------------------------------------

/// the port used by the server and client
pub const PORT: u16 = 6415;
/// the magic value identifier of the server
pub const MAGIC: [u8; 5] = *b"below";

/// minimum username length
pub const USERNAME_MIN_LEN: u16 = 2;
/// maximum username length
pub const USERNAME_MAX_LEN: u16 = 32;
/// maximum password length
pub const PASSWORD_MAX_LEN: u16 = 256;

/// how long to wait for the server to send its magic before deciding it isn't one of ours
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// how long to wait for the server to answer a username/password during authentication
pub const AUTH_TIMEOUT: Duration = Duration::from_secs(30);

/// how many username attempts are allowed before the server closes the connection
pub const USERNAME_TRIES: u8 = 3;

// ---------------------------------------------------------------------------------------------
// status codes
// ---------------------------------------------------------------------------------------------

/// all success codes which can be represented by a status code, in order
pub const SUCCESS_CODES: &[&str] = &["success", "user_exists", "user_verified", "congratulations"];
/// all error codes which can be represented by a status code, in order, following the success codes
pub const ERROR_CODES: &[&str] = &[
    "read_failed",
    "timed_out",
    "corrupted_data",
    "tries_exceeded",
    "username_too_long",
    "pass_too_long",
    "nonexistent_user",
    "password_incorrect",
];
/// the number of status codes
#[allow(clippy::cast_possible_truncation)]
pub const STATUS_CODES: u8 = (SUCCESS_CODES.len() + ERROR_CODES.len()) as u8;
/// the range of valid status codes
pub const VALID_STATUS_RANGE: Range<u8> = 0..STATUS_CODES;

/// compares two strings in a const context
const fn str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }

    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }

    true
}

/// converts a status code to its readable name
#[must_use]
pub const fn code_to_name(code: u8) -> &'static str {
    let code = code as usize;
    if code < SUCCESS_CODES.len() {
        SUCCESS_CODES[code]
    } else {
        ERROR_CODES[code - SUCCESS_CODES.len()]
    }
}

/// converts a readable name to its status code
///
/// # Panics
///
/// panics if the provided status name is invalid
#[must_use]
pub const fn name_to_code(name: &'static str) -> u8 {
    let mut code = 0;
    while code < STATUS_CODES {
        if str_eq(name, code_to_name(code)) {
            return code;
        }
        code += 1;
    }

    panic!("invalid status code");
}

// ---------------------------------------------------------------------------------------------
// errors
// ---------------------------------------------------------------------------------------------

/// protocol errors
#[derive(Debug)]
pub enum ProtoError {
    /// received a header which specifies an invalid type discriminant
    InvalidType(u8),
    /// data length exceeds maximum
    ExceedsMax,
    /// status code is invalid
    InvalidStatus(u8),
    /// string data received is not valid utf8
    UTF8(FromUtf8Error),
    /// an error occurred while reading from/writing to the socket
    IO(io::Error),
    /// a received boolean was not valid
    InvalidBool(u8),
    /// the magic received was not valid
    InvalidMagic([u8; 5]),
}

impl Display for ProtoError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtRes {
        match self {
            ProtoError::InvalidType(d) => write!(f, "invalid type in header: {d}"),
            ProtoError::ExceedsMax => write!(f, "header data length exceeds maximum limit"),
            ProtoError::InvalidStatus(stat) => write!(f, "invalid status code: {stat}"),
            ProtoError::UTF8(e) => write!(f, "UTF8 error: {e}"),
            ProtoError::IO(e) => write!(f, "IO error: {e}"),
            ProtoError::InvalidBool(d) => write!(f, "invalid boolean value: {d}"),
            ProtoError::InvalidMagic(magic) => write!(f, "invalid magic value: {magic:x?}"),
        }
    }
}

impl From<io::Error> for ProtoError {
    fn from(error: io::Error) -> ProtoError {
        ProtoError::IO(error)
    }
}
impl From<FromUtf8Error> for ProtoError {
    fn from(error: FromUtf8Error) -> ProtoError {
        ProtoError::UTF8(error)
    }
}

// ---------------------------------------------------------------------------------------------
// frames
// ---------------------------------------------------------------------------------------------

const TYPE_STR: u8 = 0;
const TYPE_STATUS: u8 = 1;
const TYPE_BOOL: u8 = 2;
const TYPE_MAGIC: u8 = 3;

/// data received or to be sent via the protocol
#[derive(Debug)]
pub enum Data {
    /// string data
    Str(String),
    /// a status code. see [`SUCCESS_CODES`] and [`ERROR_CODES`] for information.
    StatusCode(u8),
    /// a boolean
    Bool(bool),
    /// magic
    Magic([u8; 5])
}

/// reads exactly `N` bytes from `r`
fn read_array<R: Read, const N: usize>(r: &mut R) -> io::Result<[u8; N]> {
    let mut buf = [0; N];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

/// reads a frame from `r`.
///
/// # Errors
///
/// - [`ProtoError::IO`] if a read call fails
/// - [`ProtoError::InvalidType`] if the received data's type is not valid
/// - [`ProtoError::UTF8`] if the received data is of the [`Data::Str`] type but is not valid utf8
/// - [`ProtoError::ExceedsMax`] if the supposed length of the received data exceeds `max`
/// - [`ProtoError::InvalidStatus`] if the received data is of the [`Data::StatusCode`] type but
///   is not within [`VALID_STATUS_RANGE`]
pub fn read_frame<R: Read>(r: &mut R, max: u16) -> Result<Data, ProtoError> {
    let [ty] = read_array(r)?;

    match ty {
        TYPE_STR => {
            let len = usize::from(u16::from_be_bytes(read_array(r)?));
            if len > usize::from(max) {
                return Err(ProtoError::ExceedsMax);
            }

            let mut buf = vec![0; len];
            r.read_exact(&mut buf)?;
            Ok(Data::Str(String::from_utf8(buf)?))
        }
        TYPE_STATUS => {
            let [stat] = read_array(r)?;
            if !VALID_STATUS_RANGE.contains(&stat) {
                return Err(ProtoError::InvalidStatus(stat));
            }

            Ok(Data::StatusCode(stat))
        }
        TYPE_BOOL => {
            let [bool] = read_array(r)?;
            if bool > 1 {
                return Err(ProtoError::InvalidBool(bool))
            }

            Ok(Data::Bool(bool == 1))
        }
        TYPE_MAGIC => {
            let mut magic = [0; 5];
            r.read_exact(&mut magic)?;
            Ok(Data::Magic(magic))
        }
        _ => Err(ProtoError::InvalidType(ty)),
    }
}

/// writes `data` to `w`.
///
/// # Errors
///
/// - [`ProtoError::IO`] if a write call fails
/// - [`ProtoError::ExceedsMax`] if `data` is of a dynamic length, and the length exceeds
///   [`u16::MAX`]
pub fn write_frame<W: Write>(mut w: W, data: &Data) -> Result<(), ProtoError> {
    // the whole frame is built up front so it goes out in a single write
    let frame = match data {
        Data::Str(s) => {
            let len = u16::try_from(s.len()).map_err(|_| ProtoError::ExceedsMax)?;

            let mut frame = Vec::with_capacity(3 + s.len());
            frame.push(TYPE_STR);
            frame.extend_from_slice(&len.to_be_bytes());
            frame.extend_from_slice(s.as_bytes());
            frame
        }
        Data::StatusCode(stat) => vec![TYPE_STATUS, *stat],
        Data::Bool(b) => vec![TYPE_BOOL, *b as u8],
        Data::Magic(m) => {
            vec![TYPE_MAGIC, m[0], m[1], m[2], m[3], m[4]]
        }
    };

    w.write_all(&frame)?;
    Ok(())
}
