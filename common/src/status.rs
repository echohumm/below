//! status codes, and conversions between their wire values and readable names

use core::ops::Range;

/// all success codes which can be represented by a status code, in order
pub const SUCCESS_CODES: &[&str] = &["success", "user_exists", "user_verified", "congratulations"];
/// all error codes which can be represented by a status code, in order, following the success codes
pub const ERROR_CODES: &[&str] = &[
    "read_failed",
    "timed_out",
    "corrupted_data",
    "tries_exceeded",
    "username_too_long",
    "pass_too_long",
    "nonexistent_user",
    "password_incorrect",
    "banned"
];
/// the number of status codes
#[allow(clippy::cast_possible_truncation)]
pub const STATUS_CODES: u8 = (SUCCESS_CODES.len() + ERROR_CODES.len()) as u8;
/// the range of valid status codes
pub const VALID_STATUS_RANGE: Range<u8> = 0..STATUS_CODES;

/// compares two strings in a const context
const fn str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }

    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }

    true
}

/// converts a status code to its readable name
#[must_use]
pub const fn code_to_name(code: u8) -> &'static str {
    let code = code as usize;
    if code < SUCCESS_CODES.len() {
        SUCCESS_CODES[code]
    } else {
        ERROR_CODES[code - SUCCESS_CODES.len()]
    }
}

/// converts a readable name to its status code
///
/// # Panics
///
/// panics if the provided status name is invalid
#[must_use]
pub const fn name_to_code(name: &'static str) -> u8 {
    let mut code = 0;
    while code < STATUS_CODES {
        if str_eq(name, code_to_name(code)) {
            return code;
        }
        code += 1;
    }

    panic!("invalid status code");
}
