//! common protocol types and functions for the workspace

#![allow(unknown_lints)]
#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::multiple_unsafe_ops_per_block,
    clippy::undocumented_unsafe_blocks,
    clippy::unsafe_op_in_unsafe_fn,
    missing_docs
)]
#![warn(clippy::missing_errors_doc)]
#![allow(
    clippy::inline_always,
    clippy::borrow_as_ptr,
    clippy::module_name_repetitions,
    clippy::use_self,
    clippy::question_mark,
    clippy::cast_lossless,
    unused_unsafe
)]

extern crate alloc;

mod consts;
mod frame;
mod status;

pub use {
    consts::{
        AUTH_TIMEOUT,
        HANDSHAKE_TIMEOUT,
        MAGIC,
        PASSWORD_MAX_LEN,
        PORT,
        USERNAME_MAX_LEN,
        USERNAME_MIN_LEN,
        USERNAME_TRIES
    },
    frame::{Data, ProtoError, read_frame, write_frame},
    status::{
        ERROR_CODES,
        STATUS_CODES,
        SUCCESS_CODES,
        VALID_STATUS_RANGE,
        code_to_name,
        name_to_code
    }
};
