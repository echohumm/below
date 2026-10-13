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
    unused_unsafe,
    unused_labels
)]

mod error;
mod input;
mod net;
mod session;

use {
    crate::{net::connect, session::run},
    std::process::ExitCode,
};

fn main() -> ExitCode {
    match run(&connect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
