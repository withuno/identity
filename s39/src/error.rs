//
// Copyright 2021 WithUno, Inc.
// SPDX-License-Identifier: AGPL-3.0-only
//

use failure::Fail;
use std::error;
use std::fmt;

#[derive(Debug)]
pub enum Error
{
    Underlying(failure::Compat<sssmc39::ErrorKind>),
}

impl error::Error for Error
{
    fn source(&self) -> Option<&(dyn error::Error + 'static)>
    {
        match *self {
            Error::Underlying(ref e) => Some(e),
        }
    }
}

impl fmt::Display for Error
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result
    {
        match *self {
            Error::Underlying(ref e) => {
                write!(f, "invalid argument: {}", e.get_ref())
            },
        }
    }
}

impl From<sssmc39::Error> for Error
{
    fn from(e: sssmc39::Error) -> Error { Error::Underlying(e.kind().compat()) }
}
