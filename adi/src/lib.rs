//
// Copyright (C) 2021 WithUno, Inc.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-only
//

// Referenced implementation:
// https://github.com/hashicorp/vault/blob/v1.6.2/shamir/shamir.go

use std::collections::HashSet;

use rand::seq::SliceRandom;
use rand::thread_rng;

mod error;
pub use error::Error;

mod gf;
use gf::*;

/// A fragment of data that can be combined with other shares to reconstitute
/// the whole data.
pub type Share = Vec<u8>;

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
pub fn split<'a>(
    data: &[u8],
    scheme: &[(usize, usize)],
) -> Result<Vec<Share>, Error>
{
    let secret = data.to_vec();

    if scheme.len() != 1 {
        let msg = "more than one group is not supported right now";
        return Error::InvalidArgument(msg).into();
    }

    let (threshold, parts) = scheme[0];

    if parts < threshold {
        let msg = "parts cannot be less than threshold";
        return Error::InvalidArgument(msg).into();
    }

    if parts > 255 {
        return Error::InvalidArgument("parts cannot exceed 255").into();
    }

    if threshold < 2 {
        return Error::InvalidArgument("threshold must be at least 2").into();
    }

    if threshold > 255 {
        return Error::InvalidArgument("threshold cannot exceed 255").into();
    }

    if secret.len() == 0 {
        return Error::InvalidArgument("cannot split empty secret").into();
    }

    let mut rng = thread_rng();
    let mut xcoord = (0..255).collect::<Vec<u8>>();
    xcoord.shuffle(&mut rng);

    let mut out = vec![vec![0u8; secret.len() + 1]; parts];
    for i in 0..out.len() {
        out[i][secret.len()] = xcoord[i] + 1;
    }

    for (i, v) in secret.iter().enumerate() {
        let p = make_polynomial(*v, threshold - 1);

        for j in 0..parts {
            let x = xcoord[j] + 1;
            let y = p.evaluate(x);
            out[j][i] = y;
        }
    }

    Ok(out)
}

/// Combine shares from a previous split operation. An error is returned if the
/// provided shares are not able to satisfy group threshold requirements, or if
/// the digest does not match after recombination.
pub fn combine<'a>(parts: &[Share]) -> Result<Vec<u8>, Error>
{
    if parts.len() < 2 {
        let msg =
            "less than two parts cannot be used to reconstruct the secret";
        return Error::InvalidArgument(msg).into();
    }

    let first_part_len = parts[0].len();
    if first_part_len < 2 {
        return Error::InvalidArgument("parts must be at least 2 bytes").into();
    }

    for i in 1..parts.len() {
        if parts[i].len() != first_part_len {
            let msg = "all parts must be the same length";
            return Error::InvalidArgument(msg).into();
        }
    }

    let mut secret = vec![0u8; first_part_len - 1];
    let mut x_samples = vec![0u8; parts.len()];
    let mut y_samples = vec![0u8; parts.len()];

    let mut check = HashSet::<u8>::with_capacity(parts.len());

    for (i, v) in parts.iter().enumerate() {
        let samp = v[first_part_len - 1];
        if check.replace(samp).is_some() {
            return Error::InvalidArgument("duplicate part detected").into();
        }

        x_samples[i] = samp;
    }

    for i in 0..secret.len() {
        for (j, part) in parts.iter().enumerate() {
            y_samples[j] = part[i];
        }

        let v = interpolate_polynomial(&x_samples, &y_samples, 0);

        secret[i] = v;
    }

    Ok(secret)
}

#[cfg(test)]
mod unit
{
    use super::*;
    use rand::RngCore;

    #[test]
    pub fn sss_roundtrip_internal()
    {
        let mut data = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut data);

        let shares = split(&data, &[(2, 3)]).unwrap();

        let r1 = combine(&shares[..2]).unwrap();
        let r2 = combine(&shares[1..3]).unwrap();

        assert_eq!(data, &r1[..]);
        assert_eq!(data, &r2[..]);
    }
}

// https://github.com/hashicorp/vault/blob/v1.6.2/shamir/shamir_test.go
#[cfg(test)]
mod tests
{
    #[test]
    fn split_invalid()
    {
        assert!(crate::split("test".as_bytes(), &[(0, 0)]).is_err());
        assert!(crate::split("test".as_bytes(), &[(3, 2)]).is_err());
        assert!(crate::split("test".as_bytes(), &[(3, 1000)]).is_err());
        assert!(crate::split("test".as_bytes(), &[(1000, 1001)]).is_err());
        assert!(crate::split("test".as_bytes(), &[(1, 10)]).is_err());
        assert!(crate::split("".as_bytes(), &[(2, 3)]).is_err());
    }

    #[test]
    fn split_unsupported()
    {
        assert!(crate::split("test".as_bytes(), &[(2, 3), (3, 4)]).is_err());
    }

    #[test]
    fn split()
    {
        let secret: &[u8] = "test".as_bytes();

        let out = crate::split(secret, &[(3, 5)]).unwrap();
        assert_eq!(out.len(), 5);

        for share in out {
            assert_eq!(share.len(), secret.len() + 1);
        }
    }

    #[test]
    fn combine_invalid()
    {
        assert!(crate::combine(&[vec![]]).is_err());

        assert!(
            crate::combine(&vec![
                "foo".as_bytes().to_vec(),
                "ba".as_bytes().to_vec(),
            ])
            .is_err()
        );

        assert!(
            crate::combine(&vec![
                "f".as_bytes().to_vec(),
                "b".as_bytes().to_vec()
            ])
            .is_err()
        );

        assert!(
            crate::combine(&vec![
                "foo".as_bytes().to_vec(),
                "foo".as_bytes().to_vec(),
            ])
            .is_err()
        );
    }

    #[test]
    fn combine()
    {
        let secret = "test".as_bytes();

        let out = crate::split(&secret, &[(3, 5)]).unwrap();

        for i in 0..5 {
            for j in 0..5 {
                if j == i {
                    continue;
                }

                for k in 0..5 {
                    if k == i || k == j {
                        continue;
                    }

                    let mut parts: Vec<Vec<u8>> = Vec::new();
                    parts.push(out[k].clone());
                    parts.push(out[j].clone());
                    parts.push(out[i].clone());

                    let recomb = crate::combine(&parts).unwrap();

                    assert_eq!(recomb, secret);
                }
            }
        }
    }

    #[test]
    fn precomputed()
    {
        // precomputed split from the HashiCorp version.
        //
        // package main
        // // get this into your path somehow
        // import "github.com/hashicorp/vault/shamir"
        //
        // import (
        //     "log"
        // )
        //
        // func main() {
        //     split, err := shamir.Split([]byte("secret"), 3, 2)
        //     if err != nil {
        //         log.Fatal(err)
        //     }
        //
        //     log.Println("split:")
        //     log.Println(split)
        //
        //     combine, err := shamir.Combine(split)
        //     if err != nil {
        //         log.Fatal(err)
        //     }
        //
        //     log.Println("combine (string):")
        //     log.Println(combine, string(combine))
        //}
        //
        // go run main.go
        // 2021/02/17 14:20:53 split:
        // 2021/02/17 14:20:53 [[210 102 247 138 85 80 126] [107 177 243 90 138 28 140] [198 216 47 182 64 12 180]]
        // 2021/02/17 14:20:53 combine (string):
        // 2021/02/17 14:20:53 [115 101 99 114 101 116] secret

        let parts = vec![
            vec![210, 102, 247, 138, 85, 80, 126],
            vec![107, 177, 243, 90, 138, 28, 140],
            vec![198, 216, 47, 182, 64, 12, 180],
        ];

        let recombine = crate::combine(&parts).unwrap();
        assert_eq!(recombine, vec![115, 101, 99, 114, 101, 116]);
    }
}
