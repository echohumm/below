//! the client connection: a deadline-enforcing stream wrapper, and helpers for talking to the
//! client over it

use {
    crate::error::Error,
    common::{
        AUTH_TIMEOUT,
        Data,
        PASSWORD_MAX_LEN,
        ProtoError,
        USERNAME_MAX_LEN,
        read_frame,
        write_frame
    },
    std::{
        io::{self, BufReader, Read, Write},
        net::TcpStream,
        time::Instant
    }
};

macro_rules! code {
    ($name:literal) => {
        const { common::name_to_code($name) }
    };
}

// a stream wrapper which enforces an overall deadline on every underlying read, so a client
// trickling bytes can't reset the clock. `None` means no overall deadline
pub struct DeadlineStream<'a> {
    pub stream: &'a TcpStream,
    pub deadline: Option<Instant>
}

impl Read for DeadlineStream<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(deadline) = self.deadline {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(io::ErrorKind::TimedOut.into());
            }
            self.stream.set_read_timeout(Some(left.min(AUTH_TIMEOUT)))?;
        }

        self.stream.read(buf)
    }
}
impl Write for DeadlineStream<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Some(deadline) = self.deadline {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(io::ErrorKind::TimedOut.into());
            }
            self.stream.set_write_timeout(Some(left.min(AUTH_TIMEOUT)))?;
        }

        self.stream.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

pub type Conn<'a> = BufReader<DeadlineStream<'a>>;

// write a status code to the client
pub fn send_status(conn: &mut Conn<'_>, code: u8) -> Result<(), ProtoError> {
    write_frame(conn.get_mut(), &Data::StatusCode(code))
}

// we're about to give up on this connection: try to tell the client why and hand back the error
// for the caller to return
pub fn reject(conn: &mut Conn<'_>, code: u8, err: Error) -> Error {
    let _ = send_status(conn, code);
    err
}

// the string fields a client can send during authentication
#[derive(Clone, Copy)]
pub enum Field {
    Username,
    Password
}

impl Field {
    const fn max_len(self) -> u16 {
        match self {
            Field::Username => USERNAME_MAX_LEN,
            Field::Password => PASSWORD_MAX_LEN
        }
    }

    // the status code and error used when this field exceeds its maximum length
    const fn too_long(self) -> (u8, Error) {
        match self {
            Field::Username => (code!("username_too_long"), Error::UsernameMax),
            Field::Password => (code!("pass_too_long"), Error::PasswordMax)
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Field::Username => "username",
            Field::Password => "password"
        }
    }
}

// maps an io error hit while reading from the client onto the error to return, telling the
// client why where possible
pub fn reject_io(conn: &mut Conn<'_>, e: io::Error) -> Error {
    match e.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => {
            reject(conn, code!("timed_out"), Error::Timeout)
        }
        io::ErrorKind::UnexpectedEof => Error::Closed,
        _ => reject(conn, code!("read_failed"), Error::IO(e))
    }
}

// reads a string field from the client.
// - `Ok(Some(s))`: got the string
// - `Ok(None)`: the client sent garbage but the connection is fine; it has been told so, and the
//   caller should let it retry
// - `Err(_)`: the connection is done for (the client has been told why where possible)
pub fn read_str(conn: &mut Conn<'_>, field: Field) -> Result<Option<String>, Error> {
    let name = field.name();

    match read_frame(conn, field.max_len()) {
        Ok(Data::Str(s)) => Ok(Some(s)),
        Ok(Data::StatusCode(_) | Data::Bool(_) | Data::Magic(_)) => {
            eprintln!("(read {name}) expected a string frame, got a different type");
            send_status(conn, code!("corrupted_data"))?;
            Ok(None)
        }
        Err(
            e @ (ProtoError::InvalidStatus(_)
            | ProtoError::UTF8(_)
            | ProtoError::InvalidBool(_)
            | ProtoError::InvalidMagic(_))
        ) => {
            eprintln!("(read {name}) corrupted frame: {e}");
            send_status(conn, code!("corrupted_data"))?;
            Ok(None)
        }
        Err(ProtoError::ExceedsMax) => {
            let (code, err) = field.too_long();
            Err(reject(conn, code, err))
        }
        Err(ProtoError::InvalidType(_)) => {
            Err(reject(conn, code!("corrupted_data"), Error::CorruptedData))
        }
        Err(ProtoError::IO(e)) => Err(reject_io(conn, e))
    }
}
