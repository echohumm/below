//! talking to the server: status codes, the shared connection reader, and connecting

use {
    crate::{error::Error, input::prompt},
    common::{
        Data,
        HANDSHAKE_TIMEOUT,
        MAGIC,
        PORT,
        ProtoError,
        name_to_code,
        read_frame,
        write_frame
    },
    std::{
        io::{BufReader, Read},
        net::{IpAddr, SocketAddr, TcpStream},
        str::FromStr
    }
};

pub const USER_EXISTS: u8 = name_to_code("user_exists");
pub const USER_VERIFIED: u8 = name_to_code("user_verified");
pub const CONGRATULATIONS: u8 = name_to_code("congratulations");
pub const TIMED_OUT: u8 = name_to_code("timed_out");
pub const CORRUPTED_DATA: u8 = name_to_code("corrupted_data");
pub const TRIES_EXCEEDED: u8 = name_to_code("tries_exceeded");
pub const NONEXISTENT_USER: u8 = name_to_code("nonexistent_user");
pub const PASSWORD_INCORRECT: u8 = name_to_code("password_incorrect");
pub const BANNED: u8 = name_to_code("banned");

// reads from the server through the same buffered reader for the entire connection. it must not
// be recreated between phases: the server sends `user_verified` and `congratulations` back to
// back, so the second frame can already be sitting in the buffer after the first is read
pub type Conn<'a> = BufReader<&'a TcpStream>;

pub fn read_status(conn: &mut impl Read) -> Result<u8, Error> {
    // the server only ever sends status codes after the magic, so no string data is accepted
    match read_frame(conn, 0)? {
        Data::StatusCode(code) => Ok(code),
        other => Err(Error::Unexpected(other))
    }
}

// exchanges magic values with the server, to make sure it's actually one of ours
fn handshake(stream: &TcpStream) -> Result<(), Error> {
    stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;

    // this reader is thrown away afterwards, which is fine as the server sends nothing else
    // until it has our magic
    match read_frame(&mut BufReader::new(stream), 0)? {
        Data::Magic(magic) if magic == MAGIC => Ok(write_frame(stream, &Data::Magic(MAGIC))?),
        Data::Magic(magic) => Err(ProtoError::InvalidMagic(magic).into()),
        other => Err(Error::Unexpected(other))
    }
}

// asks for the server's address until we get a connection to a valid server
pub fn connect() -> TcpStream {
    loop {
        let addr = match IpAddr::from_str(&prompt("input the server ip address: ")) {
            Ok(addr) => SocketAddr::new(addr, PORT),
            Err(e) => {
                eprintln!("please try again, that address is invalid: {e}");
                continue;
            }
        };

        let stream = match TcpStream::connect(addr) {
            Ok(stream) => stream,
            Err(e) => {
                eprintln!("please try again, failed to connect to server: {e}");
                continue;
            }
        };

        // the server does the same, as packets are small and latency matters more than batching
        if let Err(e) = stream.set_nodelay(true) {
            eprintln!("please try again, failed to configure the socket: {e}");
            continue;
        }

        match handshake(&stream) {
            Ok(()) => return stream,
            Err(e) => eprintln!(
                "please try again, the server did not respond with valid data (likely not a valid \
                 server): {e}"
            )
        }
    }
}
