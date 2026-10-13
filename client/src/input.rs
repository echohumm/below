//! reading input from the user

use {
    crate::error::Error,
    common::{PASSWORD_MAX_LEN, USERNAME_MAX_LEN},
    rpassword::ConfigBuilder,
    std::{
        io::{Write, stdin, stdout},
        process
    }
};

// prints `msg`, then reads a trimmed line from the user. exits cleanly on EOF (ctrl-d), rather
// than spinning forever on an empty read. stdin is locked per call, as its buffer is shared
// process-wide anyway
pub fn prompt(msg: &str) -> String {
    print!("{msg}");
    stdout().flush().expect("flush failed");

    let mut line = String::new();
    if stdin().read_line(&mut line).expect("failed to read input") == 0 {
        println!();
        process::exit(0);
    }

    line.trim().to_owned()
}

// reads a password without echoing it, re-prompting until it fits within the server's limit. we
// have to loop here rather than bail: by the time we ask, the server is already waiting on a
// password, and sending one that's too long would get us disconnected
pub fn read_password() -> Result<String, Error> {
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

pub fn check_username(username: &str) -> Result<(), &'static str> {
    if username.len() > USERNAME_MAX_LEN as usize {
        Err("that username is too long")
    } else if !username.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        Err("usernames may only contain letters, numbers, and underscores")
    } else {
        Ok(())
    }
}
