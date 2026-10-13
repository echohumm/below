//! authenticating with the server, and the session that follows

use {
    crate::{
        error::Error,
        input::{check_username, prompt, read_password},
        net::{
            BANNED,
            CONGRATULATIONS,
            CORRUPTED_DATA,
            Conn,
            NONEXISTENT_USER,
            PASSWORD_INCORRECT,
            TRIES_EXCEEDED,
            USER_EXISTS,
            USER_VERIFIED,
            read_status
        }
    },
    common::{
        AUTH_TIMEOUT,
        Data,
        ProtoError,
        USERNAME_TRIES,
        code_to_name,
        read_frame,
        write_frame
    },
    std::{
        io::{self, BufReader},
        net::TcpStream
    }
};

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
            BANNED => return Err(Error::Server(BANNED)),
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

pub fn run(stream: &TcpStream) -> Result<(), Error> {
    stream.set_read_timeout(Some(AUTH_TIMEOUT))?;
    let mut conn = BufReader::new(stream);

    auth(stream, &mut conn)?;
    println!("authenticated.");

    // the server may legitimately stay quiet for a long time during a session
    stream.set_read_timeout(None)?;
    session(&mut conn)
}
