// Copyright (c) 2020,2021, Jason Fritcher <jkf@wolfnet.org>
// All rights reserved.

#[cfg(test)]
#[macro_use]
extern crate hex_literal;

mod types;
mod unwrap;
mod wrap;

pub use unwrap::{UnwrapKeyError, aes_unwrap_with_nopadding, aes_unwrap_with_padding};
pub use wrap::{WrapKeyError, aes_wrap_with_nopadding, aes_wrap_with_padding};
