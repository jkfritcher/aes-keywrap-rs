// Copyright (c) 2020,2021, Jason Fritcher <jkf@wolfnet.org>
// All rights reserved.

pub(crate) use aes::{Aes128, Aes192, Aes256};
pub(crate) use block_modes::{block_padding::NoPadding, Ecb};

// create aliases for convenience
pub(crate) type Aes128Ecb = Ecb<Aes128, NoPadding>;
pub(crate) type Aes192Ecb = Ecb<Aes192, NoPadding>;
pub(crate) type Aes256Ecb = Ecb<Aes256, NoPadding>;

pub(crate) const BLOCK_LEN: usize = 8;
pub(crate) const AES_BLOCK_LEN: usize = 16;
