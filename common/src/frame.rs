//! the wire format: protocol errors, frame types, and reading/writing frames

use {
    crate::status::VALID_STATUS_RANGE,
    alloc::string::FromUtf8Error,
    core::fmt::{Display, Formatter, Result as FmtRes},
    std::io::{self, Read, Write}
};

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
    InvalidMagic([u8; 5])
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
            ProtoError::InvalidMagic(magic) => write!(f, "invalid magic value: {magic:x?}")
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
    /// a status code. see [`SUCCESS_CODES`](crate::SUCCESS_CODES) and
    /// [`ERROR_CODES`](crate::ERROR_CODES) for information.
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
/// - [`ProtoError::InvalidStatus`] if the received data is of the [`Data::StatusCode`] type but is
///   not within [`VALID_STATUS_RANGE`]
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
                return Err(ProtoError::InvalidBool(bool));
            }

            Ok(Data::Bool(bool == 1))
        }
        TYPE_MAGIC => {
            let mut magic = [0; 5];
            r.read_exact(&mut magic)?;
            Ok(Data::Magic(magic))
        }
        _ => Err(ProtoError::InvalidType(ty))
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
