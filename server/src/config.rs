//! server tunables

use {
    argon2::Params,
    core::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        time::Duration
    }
};

pub const AUTH_OVERALL_TIMEOUT: Duration = Duration::from_secs(120);
// TODO: fine-tune
pub const USER_TIMEOUT: Duration = Duration::from_mins(10);

pub const HASH_PARAMS: Params = match Params::new(32768, 2, 2, Some(32)) {
    Ok(p) => p,
    Err(_) => panic!("argon params error")
};

pub const ACCOUNT_FILE: &str = "./accounts";

// TEMPORARY: localhost
pub const ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 6415);
