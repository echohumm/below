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

#[macro_use]
mod conn;

mod accounts;
mod blacklist;
mod config;
mod error;
mod session;

use {
    crate::{
        accounts::{generate_account, load_accounts},
        blacklist::{Blacklist, key},
        config::{ADDR, HASH_PARAMS},
        session::handle_client
    },
    argon2::{Algorithm, Argon2, Version},
    std::{
        env,
        net::{Shutdown, TcpListener, TcpStream},
        thread::sleep,
        time::Duration
    }
};

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

// username and pw-authenticated server which allows strictly ONE connection at all times; nobody
// can connect until the current one is closed
// if this is made to match the inspiration (skin caves), it will only be open (running) for a short
// time each day.
fn main() {
    let hasher = Argon2::new(Algorithm::Argon2id, Version::V0x13, HASH_PARAMS);
    let mut blacklist = Blacklist::new();

    if env::var("GENMODE").is_ok_and(|v| v.parse() == Ok(1_u8)) {
        generate_account(&hasher);
        return;
    }

    println!("initializing server...");
    // fail fast if the account file is missing or unreadable
    let mut accounts = load_accounts();
    println!("server initialized.");

    println!("starting server loop.");
    loop {
        let stream = connect();
        let Ok(client) = stream.peer_addr() else {
            continue;
        };
        let id = key(client.ip());

        stream.set_nodelay(true).expect("server socket error setting nodelay");
        // TODO: tls is necessary

        blacklist.prune();
        if blacklist.is_banned(id) {
            let _ = stream.shutdown(Shutdown::Both);
            let _ = stream;
            continue;
        }

        handle_client(&accounts, &mut blacklist, &hasher, &stream, id);

        // reload accounts for every connection (not the best way to do this but it works)
        // TODO: do better
        accounts = load_accounts();
    }
}
