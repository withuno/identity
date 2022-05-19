//
// Copyright (C) 2021 WithUno, Inc.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::array;
use std::error;
use std::fmt;
use std::string::FromUtf8Error;
use std::string::String;

#[derive(Debug)]
pub enum Error {
    /// Error at the uno library level
    Uno(String),
    /// Underlying crypto error from djb
    Curve25519(djb::Error),
    /// Shamir error from adi
    Shamir(adi::Error),
    /// SLIP-0039 Error
    S39(s39::Error),
    /// Error from `argon2` hash lib
    Hash(String),
}

impl From<adi::Error> for Error {
    fn from(e: adi::Error) -> Self {
        Error::Shamir(e)
    }
}

impl From<djb::Error> for Error {
    fn from(e: djb::Error) -> Self {
        Error::Curve25519(e)
    }
}

impl From<s39::Error> for Error {
    fn from(e: s39::Error) -> Self {
        Error::S39(e)
    }
}

impl From<argon2::Error> for Error {
    fn from(e: argon2::Error) -> Self {
        Error::Hash(format!("argon2 - {}", e))
    }
}

impl From<array::TryFromSliceError> for Error {
    fn from(e: array::TryFromSliceError) -> Self {
        Error::Uno(format!("converting slice to uno id failed: {}", e))
    }
}

impl From<FromUtf8Error> for Error {
    fn from(e: FromUtf8Error) -> Self {
        Error::Uno(format!("invalid utf8: {}", e))
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            Error::Uno(_) => None,
            Error::Curve25519(ref s) => Some(s),
            Error::Hash(_) => None,
            Error::Shamir(ref s) => Some(s),
            Error::S39(ref s) => Some(s),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Uno(ref msg) => write!(f, "{}", msg),
            Error::Curve25519(ref s) => write!(f, "curve25519 - {}", s),
            Error::Hash(ref s) => write!(f, "argon2 - {}", s),
            Error::Shamir(ref s) => write!(f, "shamir - {}", s),
            Error::S39(ref s) => write!(f, "slip - {}", s),
        }
    }
}
