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
    unused_unsafe
)]

use {
    argon2::{
        Algorithm,
        Argon2,
        Params,
        PasswordHash,
        PasswordHasher,
        PasswordVerifier,
        Version,
        password_hash::phc::SaltString
    },
    common::{
        AUTH_TIMEOUT,
        Data,
        HANDSHAKE_TIMEOUT,
        MAGIC,
        PASSWORD_MAX_LEN,
        ProtoError,
        USERNAME_MAX_LEN,
        read_frame,
        write_frame
    },
    core::{
        fmt::{Display, Formatter, Result as FmtRes},
        net::{IpAddr, Ipv4Addr, SocketAddr},
        time::Duration
    },
    rpassword::{ConfigBuilder, prompt_password_with_config},
    std::{
        collections::HashMap,
        env,
        fs::{OpenOptions, read_to_string},
        io::{self, BufReader, Read, Write, stdin, stdout},
        net::{Shutdown, TcpListener, TcpStream},
        thread::sleep,
        time::Instant
    }
};
use common::USERNAME_TRIES;
// ---------------------------------------------------------------------------------------------
// configuration
// ---------------------------------------------------------------------------------------------


const AUTH_OVERALL_TIMEOUT: Duration = Duration::from_secs(120);
// TODO: fine-tune
const USER_TIMEOUT: Duration = Duration::from_mins(10);

const HASH_PARAMS: Params = match Params::new(32768, 2, 2, Some(32)) {
    Ok(p) => p,
    Err(_) => panic!("argon params error")
};

const ACCOUNT_FILE: &str = "./accounts";

// TEMPORARY: localhost
const ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 6415);

// ---------------------------------------------------------------------------------------------
// errors
// ---------------------------------------------------------------------------------------------

#[derive(Debug)]
enum Error {
    Closed,
    InputTries,
    Timeout,
    UsernameMax,
    PasswordMax,
    CorruptedData,
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

// ---------------------------------------------------------------------------------------------
// connection helpers
// ---------------------------------------------------------------------------------------------

// a stream wrapper which enforces an overall deadline on every underlying read, so a client
// trickling bytes can't reset the clock. `None` means no overall deadline
struct DeadlineStream<'a> {
    stream: &'a TcpStream,
    deadline: Option<Instant>
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

type Conn<'a> = BufReader<DeadlineStream<'a>>;

macro_rules! code {
    ($name:literal) => {
        const { common::name_to_code($name) }
    };
}

// write a status code to the client
fn send_status(conn: &mut Conn<'_>, code: u8) -> Result<(), ProtoError> {
    write_frame(conn.get_mut(), &Data::StatusCode(code))
}

// we're about to give up on this connection: try to tell the client why and hand back the error
// for the caller to return
fn reject(conn: &mut Conn<'_>, code: u8, err: Error) -> Error {
    let _ = send_status(conn, code);
    err
}

// the string fields a client can send during authentication
#[derive(Clone, Copy)]
enum Field {
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
fn reject_io(conn: &mut Conn<'_>, e: io::Error) -> Error {
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
fn read_str(conn: &mut Conn<'_>, field: Field) -> Result<Option<String>, Error> {
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

fn connect() -> TcpStream {
    // spin until we get a connection
    loop {
        // immediately discard the TcpListener upon a result, so next clients are refused
        // TODO: considering handling other clients and sending a proper message to
        //  differentiate "server is offline/unavailable" vs "someone is already connected"
        match TcpListener::bind(ADDR).expect("cannot bind to socket").accept() {
            Ok((stream, addr)) => {
                println!("accepted connection from {addr}");
                break stream;
            }
            Err(e) => {
                eprintln!("accept error: {e}");
                // TODO: fine tune sleep duration that prevents hot loop
                sleep(Duration::from_secs(1));
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// entry point
// ---------------------------------------------------------------------------------------------

// username and pw-authenticated server which allows strictly ONE connection at all times; nobody
// can connect until the current one is closed
fn main() {
    let hasher = Argon2::new(Algorithm::Argon2id, Version::V0x13, HASH_PARAMS);

    if env::var("GENMODE").is_ok_and(|v| v.parse() == Ok(1_u8)) {
        generate_account(&hasher);
        return;
    }

    println!("initializing server...");
    // fail fast if the account file is missing or unreadable
    load_accounts();
    println!("server initialized.");

    println!("starting server loop.");
    loop {
        let stream = connect();
        stream.set_nodelay(true).expect("server socket error setting nodelay");
        // TODO: tls is necessary

        // reload accounts for every connection (not the best way to do this but it works)
        // TODO: do better
        let accounts = load_accounts();

        handle_client(&accounts, &hasher, &stream);
    }
}

fn handle_client(accounts: &HashMap<String, String>, hasher: &Argon2<'_>, stream: &TcpStream) {
    if let Err(e) = handshake(stream) {
        eprintln!("(magic) {e}");
    } else {
        match auth(accounts, hasher, stream) {
            Ok(user) => {
                if let Err(e) = session(&user, stream) {
                    eprintln!("(session) {e}");
                }
            }
            Err(e) => eprintln!("(auth) {e}")
        }
    }

    // based on research into libc::shutdown, all error states do not apply or can be
    // ignored; discard the result.
    let _ = stream.shutdown(Shutdown::Both);
}

// prompts for a username and password on the terminal and appends the account to the account file
fn generate_account(hasher: &Argon2<'_>) {
    println!("running in hash generation mode.");

    let mut file = OpenOptions::new()
        .append(true)
        .truncate(false)
        .create(true)
        .open(ACCOUNT_FILE)
        .expect("failed to open account file");

    let mut out = stdout();
    write!(out, "username: ").expect("write failed");
    out.flush().expect("flush failed");

    let mut username = String::new();
    stdin().read_line(&mut username).expect("failed to read username");
    let username = username.trim();

    let password = prompt_password_with_config(
        "password: ",
        ConfigBuilder::new().password_feedback_mask('*').build()
    )
    .expect("failed to read password");

    let hash = hasher
        .hash_password_with_salt(password.as_bytes(), SaltString::generate().as_bytes())
        .expect("failed to hash password");

    writeln!(file, "{username}{hash}").expect("failed to write to account file");
}

// ---------------------------------------------------------------------------------------------
// verification, authentication, and session
// ---------------------------------------------------------------------------------------------

fn handshake(stream: &TcpStream) -> Result<(), Error> {
    stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT)).unwrap();
    stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT)).unwrap();
    let deadline = Some(Instant::now() + HANDSHAKE_TIMEOUT);

    let conn = &mut BufReader::new(DeadlineStream { stream, deadline });

    write_frame(conn.get_mut(), &Data::Magic(MAGIC))?;

    match read_frame(conn, 0) {
        Ok(Data::Magic(magic)) if magic == MAGIC => Ok(()),
        Err(ProtoError::IO(e)) => Err(reject_io(conn, e)),
        r => {
            eprintln!("{r:?}");
            Err(Error::CorruptedData)
        }
    }
}

fn auth(
    accounts: &HashMap<String, String>,
    hasher: &Argon2<'_>,
    stream: &TcpStream
) -> Result<String, Error> {
    // set the tcp timeout, so somebody doing nothing doesn't prevent others from connecting
    // permanently
    // unwrap is fine here as we know the duration isn't 0
    stream.set_read_timeout(Some(AUTH_TIMEOUT)).unwrap();
    stream.set_write_timeout(Some(AUTH_TIMEOUT)).unwrap();
    let deadline = Some(Instant::now() + AUTH_OVERALL_TIMEOUT);

    let conn = &mut BufReader::new(DeadlineStream { stream, deadline });

    // we allow ONE password try per username; subsequent tries require username input as well,
    // which are capped
    for _ in 0..USERNAME_TRIES {
        let Some(username) = read_str(conn, Field::Username)? else { continue };

        let Some(hash) = accounts.get(&username) else {
            // i have decided not to allow signups. if somebody wants in, i'll have them, like..
            // email me or smth. i might change this in the future but for now i
            // don't feel like figuring out a decent ux for signing up
            // TODO: consider signups
            send_status(conn, code!("nonexistent_user"))?;
            continue;
        };

        // the username exists, ask for a password
        send_status(conn, code!("user_exists"))?;

        let Some(password) = read_str(conn, Field::Password)? else { continue };

        if PasswordHash::new(hash)
            .is_ok_and(|p| hasher.verify_password(password.as_bytes(), &p).is_ok())
        {
            send_status(conn, code!("user_verified"))?;
            return Ok(username);
        }

        send_status(conn, code!("password_incorrect"))?;
    }

    Err(reject(conn, code!("tries_exceeded"), Error::InputTries))
}

fn session(_user: &str, stream: &TcpStream) -> Result<(), Error> {
    stream.set_read_timeout(Some(USER_TIMEOUT)).unwrap();
    let mut conn = BufReader::new(DeadlineStream { stream, deadline: None });

    send_status(&mut conn, code!("congratulations"))?;
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// accounts
// ---------------------------------------------------------------------------------------------

// loads username -> pw hash pairs from the account file, which is in the format:
// $(<username><pw_hash>\n)*
fn load_accounts() -> HashMap<String, String> {
    let contents = read_to_string(ACCOUNT_FILE).expect(
        "cannot read account file (btw, me, if you ever see this: there is fs corruption, or you \
         deleted it somehow)"
    );

    let mut accounts = HashMap::new();

    for line in contents.trim().lines() {
        // phc password_hash_separator
        let Some(i) = line.find('$') else {
            eprintln!("skipping missing hash separator: \"{line}\"");
            continue;
        };

        let (username, hash) = line.split_at(i);

        if username.len() > USERNAME_MAX_LEN as usize {
            eprintln!("skipping invalid username: \"{line}\"");
        } else {
            accounts.insert(username.to_string(), hash.to_string());
        }
    }

    accounts
}
