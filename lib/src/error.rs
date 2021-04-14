//
// Copyright 2021 WithUno, Inc.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::error;
use std::fmt;
use std::array;
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
    /// Error from `surf` http lib
    Surf(surf::Error),
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

impl From<surf::Error> for Error {
    fn from(e: surf::Error) -> Self {
        Error::Surf(e)
    }
}

impl From<array::TryFromSliceError> for Error {
    fn from(e: array::TryFromSliceError) -> Self {
        Error::Uno(format!("converting slice to uno id failed: {}", e))
    }
}

impl From<url::ParseError> for Error {
    fn from(e: url::ParseError) -> Self {
        Error::Uno(format!("invalid url: {}", e))
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
            Error::Shamir(ref s) => Some(s),
            Error::Surf(ref s) => Some(s.as_ref()),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Uno(ref msg) => write!(f, "lib - {}", msg),
            Error::Curve25519(ref s) => write!(f, "curve25519 - {}", s),
            Error::Shamir(ref s) => write!(f, "shamir - {}", s),
            Error::Surf(ref s) => write!(f, "surf - {}", s),
        }
    }
}
