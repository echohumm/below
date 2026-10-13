//! handling a single client from handshake through authentication to the session itself

use {
    crate::{
        blacklist::Blacklist,
        config::{AUTH_OVERALL_TIMEOUT, USER_TIMEOUT},
        conn::{DeadlineStream, Field, read_str, reject, reject_io, send_status},
        error::Error
    },
    argon2::{Argon2, PasswordHash, PasswordVerifier},
    common::{
        AUTH_TIMEOUT,
        Data,
        HANDSHAKE_TIMEOUT,
        MAGIC,
        ProtoError,
        USERNAME_TRIES,
        read_frame,
        write_frame
    },
    std::{
        collections::HashMap,
        io::BufReader,
        net::{IpAddr, Shutdown, TcpStream},
        time::Instant
    }
};

pub fn handle_client(
    accounts: &HashMap<String, String>,
    blacklist: &mut Blacklist,
    hasher: &Argon2<'_>,
    stream: &TcpStream,
    id: IpAddr
) {
    if let Err(e) = handshake(stream) {
        eprintln!("(magic) {e}");
    } else {
        match auth(accounts, blacklist, hasher, stream, id) {
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
    blacklist: &mut Blacklist,
    hasher: &Argon2<'_>,
    stream: &TcpStream,
    id: IpAddr
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
            blacklist.clear_strikes(id);
            return Ok(username);
        }
        
        // TODO: upon ban, send back the (remaining) duration
        if blacklist.strike(id) {
            return Err(reject(conn, code!("banned"), Error::Banned(id)));
        }
        send_status(conn, code!("password_incorrect"))?;
    }

    if blacklist.is_banned(id) {
        Err(reject(conn, code!("banned"), Error::Banned(id)))
    } else {
        println!("strikes: {}", blacklist.entries.get(&id).unwrap().strikes);
        Err(reject(conn, code!("tries_exceeded"), Error::InputTries))
    }
}

fn session(_user: &str, stream: &TcpStream) -> Result<(), Error> {
    stream.set_read_timeout(Some(USER_TIMEOUT)).unwrap();
    let mut conn = BufReader::new(DeadlineStream { stream, deadline: None });

    send_status(&mut conn, code!("congratulations"))?;
    Ok(())
}
