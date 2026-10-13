//! global protocol constants shared by the server and client

use std::time::Duration;

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
