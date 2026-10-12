#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::multiple_unsafe_ops_per_block,
    clippy::undocumented_unsafe_blocks,
    unsafe_op_in_unsafe_fn
)]
#![allow(
    clippy::inline_always,
    clippy::borrow_as_ptr,
    clippy::module_name_repetitions,
    clippy::use_self,
    clippy::question_mark,
    clippy::cast_lossless,
    unused_unsafe,
    unused_labels
)]

use {
    common::{
        AUTH_TIMEOUT,
        Data,
        HANDSHAKE_TIMEOUT,
        MAGIC,
        PASSWORD_MAX_LEN,
        PORT,
        ProtoError,
        USERNAME_MAX_LEN,
        USERNAME_TRIES,
        code_to_name,
        name_to_code,
        read_frame,
        write_frame
    },
    rpassword::ConfigBuilder,
    std::{
        fmt::{self, Display, Formatter},
        io::{self, BufRead, BufReader, Read, Write, stdin, stdout},
        net::{IpAddr, SocketAddr, TcpStream},
        process::{self, ExitCode},
        str::FromStr
    }
};
// ---------------------------------------------------------------------------------------------
// configuration
// ---------------------------------------------------------------------------------------------

const USER_EXISTS: u8 = name_to_code("user_exists");
const USER_VERIFIED: u8 = name_to_code("user_verified");
const CONGRATULATIONS: u8 = name_to_code("congratulations");
const TIMED_OUT: u8 = name_to_code("timed_out");
const CORRUPTED_DATA: u8 = name_to_code("corrupted_data");
const TRIES_EXCEEDED: u8 = name_to_code("tries_exceeded");
const NONEXISTENT_USER: u8 = name_to_code("nonexistent_user");
const PASSWORD_INCORRECT: u8 = name_to_code("password_incorrect");

// ---------------------------------------------------------------------------------------------
// errors
// ---------------------------------------------------------------------------------------------

#[derive(Debug)]
enum Error {
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

// ---------------------------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------------------------

// reads from the server through the same buffered reader for the entire connection. it must not
// be recreated between phases: the server sends `user_verified` and `congratulations` back to
// back, so the second frame can already be sitting in the buffer after the first is read
type Conn<'a> = BufReader<&'a TcpStream>;

// prints `msg`, then reads a trimmed line from the user. exits cleanly on EOF (ctrl-d), rather
// than spinning forever on an empty read. stdin is locked per call, as its buffer is shared
// process-wide anyway
fn prompt(msg: &str) -> String {
    print!("{msg}");
    stdout().flush().expect("flush failed");

    let mut line = String::new();
    if stdin().lock().read_line(&mut line).expect("failed to read input") == 0 {
        println!();
        process::exit(0);
    }

    line.trim().to_owned()
}

// reads a password without echoing it, re-prompting until it fits within the server's limit. we
// have to loop here rather than bail: by the time we ask, the server is already waiting on a
// password, and sending one that's too long would get us disconnected
fn read_password() -> Result<String, Error> {
    loop {
        let password = rpassword::prompt_password_with_config(
            "password: ",
            ConfigBuilder::new().password_feedback_mask('*').build()
        )?;
        if password.len() <= PASSWORD_MAX_LEN as usize {
            return Ok(password);
        }

        eprintln!("that password is too long (the maximum is {PASSWORD_MAX_LEN} bytes)");
    }
}

fn check_username(username: &str) -> Result<(), &'static str> {
    if username.len() > USERNAME_MAX_LEN as usize {
        Err("that username is too long")
    } else if !username.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        Err("usernames may only contain letters, numbers, and underscores")
    } else {
        Ok(())
    }
}

fn read_status(conn: &mut impl Read) -> Result<u8, Error> {
    // the server only ever sends status codes after the magic, so no string data is accepted
    match read_frame(conn, 0)? {
        Data::StatusCode(code) => Ok(code),
        other => Err(Error::Unexpected(other))
    }
}

// ---------------------------------------------------------------------------------------------
// connecting
// ---------------------------------------------------------------------------------------------

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
fn connect() -> TcpStream {
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

// ---------------------------------------------------------------------------------------------
// authentication and session
// ---------------------------------------------------------------------------------------------

// the server allows a limited number of username attempts, and each failed password consumes
// one, so every retry goes back to asking for the username
fn auth(stream: &TcpStream, conn: &mut Conn<'_>) -> Result<(), Error> {
    for _ in 0..USERNAME_TRIES {
        let username = prompt("username: ");
        if let Err(why) = check_username(&username) {
            eprintln!("{why}");
            continue;
        }

        write_frame(stream, &Data::Str(username))?;

        match read_status(conn)? {
            USER_EXISTS => {}
            NONEXISTENT_USER => {
                eprintln!("that user does not exist");
                continue;
            }
            CORRUPTED_DATA => {
                eprintln!("the server received corrupted data, please try again");
                continue;
            }
            code => return Err(Error::Server(code))
        }

        write_frame(stream, &Data::Str(read_password()?))?;

        match read_status(conn)? {
            USER_VERIFIED => return Ok(()),
            PASSWORD_INCORRECT => eprintln!("incorrect password"),
            CORRUPTED_DATA => eprintln!("the server received corrupted data, please try again"),
            code => return Err(Error::Server(code))
        }
    }

    Err(Error::Server(TRIES_EXCEEDED))
}

// everything the server does once we're authenticated, which for now is just saying hello and
// hanging up. we keep reading until it does
fn session(conn: &mut Conn<'_>) -> Result<(), Error> {
    loop {
        match read_frame(conn, 0) {
            Ok(Data::StatusCode(CONGRATULATIONS)) => println!("congratulations!"),
            Ok(Data::StatusCode(code)) => println!("server status: {}", code_to_name(code)),
            Ok(other) => return Err(Error::Unexpected(other)),
            Err(ProtoError::IO(e)) if e.kind() == io::ErrorKind::UnexpectedEof => {
                println!("the server closed the connection");
                return Ok(());
            }
            Err(e) => return Err(e.into())
        }
    }
}

fn run(stream: &TcpStream) -> Result<(), Error> {
    stream.set_read_timeout(Some(AUTH_TIMEOUT))?;
    let mut conn = BufReader::new(stream);

    auth(stream, &mut conn)?;
    println!("authenticated.");

    // the server may legitimately stay quiet for a long time during a session
    stream.set_read_timeout(None)?;
    session(&mut conn)
}

fn start() -> Result<(), Error> {
    run(&connect())
}

fn main() -> ExitCode {
    match start() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
