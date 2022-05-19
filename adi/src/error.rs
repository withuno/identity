//
// Copyright 2021 WithUno, Inc.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::convert::Into;
use std::error;
use std::fmt;
use std::result::Result;

#[derive(Debug)]
pub enum Error
{
    InvalidArgument(&'static str),
}

impl error::Error for Error
{
    fn source(&self) -> Option<&(dyn error::Error + 'static)>
    {
        match *self {
            Error::InvalidArgument(_) => None,
        }
    }
}

impl fmt::Display for Error
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result
    {
        match *self {
            Error::InvalidArgument(ref msg) => {
                write!(f, "invalid argument: {}", msg)
            },
        }
    }
}

impl<T> Into<Result<T, Error>> for Error
{
    fn into(self) -> Result<T, Error> { Err(self) }
}
