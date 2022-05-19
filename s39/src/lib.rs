//
// Copyright (C) 2021 WithUno, Inc.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-only
//

mod error;
pub use error::Error;

pub use sssmc39::GroupShare;
pub use sssmc39::Share;

const PASS: &str = "uno shamir secret share";

/// Using scheme (t, n), split `data` into `n` shares such that `t` can be re-
/// combined into the original bytes. Multiple schemes can be passed in the
/// array in which case groups of shares will be constructed such that the
/// scheme is enforced for each group. For example: split with scheme `[(1,1),
/// (2,3), (3,5)]` would result in 3 groups of shares with the first group
/// being a single share, the second group requireing two of three shares, and
/// the third group requiring three of five shares.
///
/// The length of `data` must be at least 16 bytes (128 bits) and be a multiple
/// of 16 bits. The maximum number of groups (number of tuples in the scheme
/// array), cannot exceed 16. In a given group tuple (t, n), `t` must not
/// exceed `n`. If `t` equals 1, then `n` must be 1.
///
/// Group, and scheme information as well as the iteration exponent is encoded
/// in each share so that shares can be recombined without additional context.
///
pub fn split<'a>(
    data: &[u8],
    scheme: &[(u8, u8)],
) -> Result<Vec<GroupShare>, Error>
{
    // We encrypt with a fixed password and a mere 10,000 iterations of pbkdf.
    // The security of each share is managed by our software eslewhere. Each
    // share is encrypted when in transit and at rest in a user's vault. The
    // encryption component of slip39 is not applicable in our use case although
    // it's something we could consider supporting in the future if we develop
    // a compelling UX that incorporates it.
    let groups = sssmc39::generate_mnemonics(1, scheme, data, PASS, 0)?;
    Ok(groups)
}

/// Combine shares from a previous split operation. An error is returned if the
/// provided shares are not able to satisfy group threshold requirements, or if
/// the digest does not match after recombination.
///
pub fn combine<'a>(shares: &[Vec<String>]) -> Result<Vec<u8>, Error>
{
    let data = sssmc39::combine_mnemonics(shares, PASS)?;
    Ok(data)
}

#[cfg(test)]
mod unit
{
    use super::*;

    use anyhow::Result;
    use rand::RngCore;

    #[test]
    pub fn s39_roundtrip() -> Result<()>
    {
        let mut data = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut data);

        let groups = split(&data, &[(2, 3)])?;
        let group = &groups[0];

        let mnemonics1 = group.member_shares[..2]
            .iter()
            .map(|s| s.to_mnemonic())
            .collect::<Result<Vec<Vec<_>>, _>>()
            .map_err(|e| Error::from(e))?;
        let mnemonics2 = group.member_shares[1..3]
            .iter()
            .map(|s| s.to_mnemonic())
            .collect::<Result<Vec<Vec<_>>, _>>()
            .map_err(|e| Error::from(e))?;

        let r1 = combine(&mnemonics1[..])?;
        let r2 = combine(&mnemonics2[..])?;

        assert_eq!(data, &r1[..]);
        assert_eq!(data, &r2[..]);

        Ok(())
    }
}
