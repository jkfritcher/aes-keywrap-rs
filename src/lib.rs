// Copyright (c) 2020, Jason Fritcher <jkf@wolfnet.org>
// All rights reserved.

#[cfg(test)]
#[macro_use]
extern crate hex_literal;

mod types;

mod error;
mod unwrap;
mod wrap;
pub use error::KeyWrapError;
pub use unwrap::{aes_unwrap_with_nopadding, aes_unwrap_with_padding};
pub use wrap::{aes_wrap_with_nopadding, aes_wrap_with_padding};
