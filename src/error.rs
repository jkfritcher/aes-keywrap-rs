// Copyright (c) 2020, Jason Fritcher <jkf@wolfnet.org>
// All rights reserved.

use std::fmt;

#[derive(Debug)]
pub struct KeyWrapError {
    msg: String,
}

impl fmt::Display for KeyWrapError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.msg)
    }
}

impl From<&str> for KeyWrapError {
    fn from(msg: &str) -> Self {
        KeyWrapError {
            msg: msg.to_string(),
        }
    }
}

impl From<String> for KeyWrapError {
    fn from(msg: String) -> Self {
        KeyWrapError { msg }
    }
}
