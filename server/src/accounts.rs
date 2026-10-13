//! the account file: loading existing accounts, and generating new ones

use {
    crate::config::ACCOUNT_FILE,
    argon2::{Argon2, PasswordHasher, password_hash::phc::SaltString},
    common::USERNAME_MAX_LEN,
    rpassword::{ConfigBuilder, prompt_password_with_config},
    std::{
        collections::HashMap,
        fs::{OpenOptions, read_to_string},
        io::{Write, stdin, stdout}
    }
};

// loads username -> pw hash pairs from the account file, which is in the format:
// $(<username><pw_hash>\n)*
pub fn load_accounts() -> HashMap<String, String> {
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

// prompts for a username and password on the terminal and appends the account to the account file
pub fn generate_account(hasher: &Argon2<'_>) {
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
