//
// Copyright 2021 WithUno, Inc.
// SPDX-License-Identifier: AGPL-3.0-only
//


#![feature(vec_into_raw_parts, maybe_uninit_extra)]

///
/// The Uno ffi module contains a c-compatible abi for calling into libuno.
///
/// There are a few conventions to be aware of. All ffi functions are prefaced
/// with `uno_` since C does not have namespaces. Following the prefix,
/// functions that are specified with `get_` return rust-owned (usually heap
/// allocated) data while functions with `copy_` operate on C (or generally
/// caller) allocated data.
///
/// The types from the uno crate are either aliased, newtyped, or wrapped so
/// they become FFI-safe. The prefix `Uno` is appened to the uno::Type typename
/// since, again, C does not have namespaces.
/// 

use std::convert::TryFrom; 
use std::ffi::CStr;
use std::ffi::CString;
use std::mem::MaybeUninit;
use std::option::Option;
use std::os::raw::c_char;
use std::ptr::NonNull;


///
/// The Uno FFI uses a trailing error out param call style. The return value
/// of FFI functions is most always a pointer to a rust allocated, sometimes
/// opaque, struct.
/// ```
/// pub extern "C" fn uno_frob(...) -> Option<NonNull<Frob>>
/// ```
/// Null is not a valid value for any of the FFI types and represents the None
/// value of the Option. If you wish only for a pass/fail result when calling
/// a function, you can pass null as the err out-param and simply match on the
/// returned Option.
///
/// If you desire more error information such as a code and a message, then you
/// must use the trailing error out-parameter.
/// ```
/// pub extern "C" fn uno_frob(..., err: Option<&mut MaybeUninit<Error>>) -> ...
/// ```
/// After calling the function, check the value of your local Error type for a
/// code that specifies the exact error.
///
/// Error codes can be used to lookup an error message using
/// `uno_get_msg_for_error`.
///
type Error = u32;

// TODO: make enum
pub const UNO_ERR_SUCCESS: u32 = 0;
pub const UNO_ERR_ILLEGAL_ARG: u32 = 1;
pub const UNO_ERR_SPLIT: u32 = 2;
pub const UNO_ERR_SHARE_ID: u32 = 3;
pub const UNO_ERR_SHARE_MISS: u32 = 4;
pub const UNO_ERR_CHECKSUM: u32 = 5;
pub const UNO_ERR_MNEMONIC: u32 = 6;

const ERR_SUCCESS_STR: &[u8] =
    b"success\0";

const ERR_ILLEGAL_ARG_STR: &[u8] =
    b"illegal argument\0";

const ERR_S39_SPLIT_STR: &[u8] =
    b"s39 split failed\0";

const ERR_S39_SHARE_ID_MISMATCH_STR: &[u8] =
    b"s39 combine share id mismatch\0";

const ERR_S39_SHARE_MISSING_STR: &[u8] =
    b"s39 combine missing shares\0";

const ERR_S39_CHECKSUM_FAILURE_STR: &[u8] =
    b"s39 combine share checksum invalid\0";

const ERR_S39_MNEMONIC_STR: &[u8] =
    b"s39 mnemonic conversion failed\0";

const ERR_UNRECOGNIZED: &[u8] =
    b"s39 unrecognized error\0";


///
/// Get a description for the provided error code. The lifetime of the returned
/// string does not need to be managed by the caller.
///
#[no_mangle]
pub extern "C"
fn uno_get_msg_from_err(err: Error) -> *const c_char
{
    let msg = match err {
        UNO_ERR_SUCCESS => ERR_SUCCESS_STR,
        UNO_ERR_ILLEGAL_ARG => ERR_ILLEGAL_ARG_STR,
        UNO_ERR_SPLIT => ERR_S39_SPLIT_STR,
        UNO_ERR_SHARE_ID => ERR_S39_SHARE_ID_MISMATCH_STR,
        UNO_ERR_SHARE_MISS => ERR_S39_SHARE_MISSING_STR,
        UNO_ERR_CHECKSUM => ERR_S39_CHECKSUM_FAILURE_STR,
        UNO_ERR_MNEMONIC => ERR_S39_MNEMONIC_STR,
        _ => ERR_UNRECOGNIZED,
    };

    // SAFETY: err "strings" are static and can be verified manually above ^ 
    let cstr = unsafe { CStr::from_bytes_with_nul_unchecked(msg) };

    // TODO: This may possibly be unsound. as_ptr() says the returned pointer
    //       is valid as long as the cstr is, and cstr falls out of scope.     
    cstr.as_ptr()
}

///
/// 32 bytes of seed entropy. See uno::Id.
///
#[repr(transparent)]
pub struct UnoId(uno::Id);

///
/// Create an uno id struct from a 32 byte seed data array. The caller is
/// responsible calling `uno_free_id` on the returned struct once finished.
///
#[no_mangle]
pub extern "C"
fn uno_get_id_from_bytes
(
    bytes: NonNull<u8>,
    len: usize,
    err: Option<&mut MaybeUninit<Error>>
)
-> Option<NonNull<UnoId>>
{
    let seed = unsafe { std::slice::from_raw_parts(bytes.as_ptr(), len) };
  
    let id = match uno::Id::try_from(seed) {
        Ok(id) => UnoId(id),
        Err(_) => {
            err.map(|e| e.write(UNO_ERR_ILLEGAL_ARG));
            return None;
        },
    };

    NonNull::new(Box::leak(Box::new(id)))
}

///
/// Copy the raw 32 bytes backing an uno id.
///
#[no_mangle]
pub extern "C"
fn uno_copy_id_bytes
(
    uno_id: NonNull<UnoId>,
    bytes: NonNull<u8>,
    len: usize,
    err: Option<&mut MaybeUninit<Error>>,
)
{
    if len < 32 {
        err.map(|e| e.write(UNO_ERR_ILLEGAL_ARG));
        return;
    }
    for i in 0..32 {
        unsafe { bytes.as_ptr().add(i).write(uno_id.as_ref().0.0[i]) }
    }
}

///
/// Free a previously allocated UnoId from `uno_get_id_from_bytes`.
///
#[no_mangle]
pub extern "C"
fn uno_free_id(maybe_id: Option<NonNull<UnoId>>)
{ 
    maybe_id.map(|id| unsafe { Box::from_raw(id.as_ptr()) } );
}

#[repr(C)]
#[derive(Debug)]
pub struct UnoByteSlice {
    ptr: NonNull<u8>,
    len: usize,
    _cap: usize,
}

///
/// Get the raw bytes backing an uno id. 
///
#[no_mangle]
pub extern "C"
fn uno_id_get_bytes
(
    uno_id: NonNull<UnoId>,
)
-> UnoByteSlice
{
    let out = Vec::<u8>::with_capacity(32);
    let (ptr, len, cap) = out.into_raw_parts();
    // SAFETY: ptr is never null
    let nnptr = unsafe { NonNull::new_unchecked(ptr) };

    uno_copy_id_bytes(uno_id, nnptr, len, None);

    // assume init

    UnoByteSlice { ptr: nnptr, len: len, _cap: cap, }
}

///
/// Free the backing array on an UnoByteSlice from a function that returns an
/// allocated UnoByteSlice, e.g. `uno_get_id_bytes`.
///
#[no_mangle]
pub extern "C"
fn uno_free_byte_slice(byte_slice: UnoByteSlice)
{
    let bs = byte_slice;
    unsafe {
        Vec::from_raw_parts(bs.ptr.as_ptr(), bs.len, bs._cap)
    };
}

///
/// A GroupSpec is a tuple of (threshold, total) shares in a given s39 group
/// split. For instance, if you want a group go be split into 3 pieces, two
/// of which are requred to reconstitute the group secret, you'd pass (2, 3).
///
#[repr(C)]
#[derive(Debug)]
pub struct UnoGroupSpec 
{
    threshold: u8,
    total: u8,
}

///
/// A SplitResult is the output of successfully running `uno_s39_split` on an
/// UnoId. The result is a list of GroupSplits, but for now there is only ever
/// one. Generally, there can be up to 16 so the value is returned as an opaque
/// list.
///
#[derive(Debug)]
pub struct UnoSplitResult
{
    ptr: NonNull<uno::GroupShare>,
    len: usize,
    cap: usize,
}

///
/// See s39::split
///
/// Rather than an array of tuples, the caller provides an array of GroupSpec
/// structs. The group_threshold is fixed at 1 so this parameter is currently
/// unused.
///
#[no_mangle]
pub extern "C"
fn uno_s39_split
(
    uno_id: NonNull<UnoId>,
    _group_threshold: usize,
    group_total: usize,
    group_specs: NonNull<UnoGroupSpec>,
    err: Option<&mut MaybeUninit<Error>>,
)
-> Option<NonNull<UnoSplitResult>>
{
    // convert group specs to spec tuples
    let mut specs = Vec::<(u8,u8)>::with_capacity(group_total);
    for i in 0..group_total {
        // SAFETY: TODO I don't know why this is safe!!
        let gs = unsafe { &*group_specs.as_ptr().add(i) };
        specs.push( (gs.threshold, gs.total) );
    }

    // SAFETY: TODO I don't know why this is safe!!
    let id = unsafe { uno_id.as_ref().0 };

    let group_splits = match uno::split(id, &specs[..]) {
        Ok(sp) => sp,
        Err(_) => {
            err.map(|e| e.write(UNO_ERR_ILLEGAL_ARG) );
            return None;
        },
    };
    let (ptr, len, cap) = group_splits.into_raw_parts();

    let res = UnoSplitResult {
        // SAFETY: ptr is never null
        ptr: unsafe { NonNull::new_unchecked(ptr) },
        len: len,
        cap: cap
    };
    NonNull::new(Box::leak(Box::new(res)))
}

///
/// Free a previously allocated SplitResult from `uno_s39_split`.
///
#[no_mangle]
pub extern "C"
fn uno_free_split_result(maybe_sr: Option<NonNull<UnoSplitResult>>)
{ 
    maybe_sr.map(|sr| unsafe { 
        let srb = Box::from_raw(sr.as_ptr());
        Vec::from_raw_parts((*srb).ptr.as_ptr(), (*srb).len, (*srb).cap);
    });
}

///
/// A GroupSplit represents one of the group splits requested during the split
/// call. For now, there is only ever one. But there can be up to 16 so the
/// value is returned in a list.
///
#[repr(C)]
#[derive(Debug)]
pub struct UnoGroupSplit
{
    pub group_id: u16,
    pub iteration_exponent: u8,
    pub group_index: u8,
    pub group_threshold: u8,
    pub group_count: u8,
    /// The number of shares from this group required to reconstitue the group
    /// secret.
    pub member_threshold: u8,
    /// Total number of member_shares
    pub share_count: usize,
    /// Opaque reference to the constituent member shares. Acquire one of the
    /// shares with `uno_get_member_share_by_index`.
    pub member_shares: NonNull<UnoMemberSharesVec>,
}

///
/// Opaque array containing share metadata. Get a member share by index using
/// `uno_get_member_share_by_index`.
///
#[derive(Debug)]
pub struct UnoMemberSharesVec
{
    ptr: NonNull<uno::Share>,
    len: usize,
    cap: usize,
}

///
/// uno_get_group_from_split_result 
///
#[no_mangle]
pub extern "C"
fn uno_get_group_from_split_result
(
    split_result: NonNull<UnoSplitResult>,
    index: usize,
    err: Option<&mut MaybeUninit<Error>>,
)
-> Option<NonNull<UnoGroupSplit>>
{
    let groups = unsafe {
        let sr = split_result.as_ref();
        std::slice::from_raw_parts(sr.ptr.as_ptr(), sr.len)
    };

    if index >= groups.len() {
        err.map(|e| e.write(UNO_ERR_ILLEGAL_ARG));
        return None;
    }
    let item = &groups[index];

    // TODO: figure out if we can avoid clone().
    let (ptr, len, cap) = item.member_shares.clone().into_raw_parts();

    let shares = UnoMemberSharesVec { 
        // SAFETY: ptr is never null
        ptr: unsafe { NonNull::new_unchecked(ptr) },
        len: len,
        cap: cap,
    };

    let res = UnoGroupSplit { 
        group_id: item.group_id,
        iteration_exponent: item.iteration_exponent,
        group_index: item.group_index,
        group_threshold: item.group_threshold,
        group_count: item.group_count,
        member_threshold: item.member_threshold,
        share_count: shares.len,
        // SAFETY: prt will never be null
        member_shares: unsafe {
            NonNull::new_unchecked(Box::leak(Box::new(shares)))
        },
    };

    NonNull::new(Box::leak(Box::new(res)))
}

///
/// Free a previously allocated GroupSplit returned by
/// `uno_get_group_from_split_result`.
///
#[no_mangle]
pub extern "C"
fn uno_free_group_split(maybe_gs: Option<NonNull<UnoGroupSplit>>)
{ 
    maybe_gs.map(|gs| unsafe { 
        let gsb = Box::from_raw(gs.as_ptr());
        let msb = Box::from_raw((*gsb).member_shares.as_ptr());
        Vec::from_raw_parts((*msb).ptr.as_ptr(), (*msb).len, (*msb).cap);
    });
}

///
/// Share mnemonic string. Obtained by index from an UnoGroupSplit type using
/// `uno_get_s39_share_by_index`. The mnemonic share data is a c string
/// reference and can be handled in a read-only (const) fashion using the
/// standard c string api. An UnoShare must be freed using `uno_free_s39_share`
/// when you are done using it.
///
#[repr(C)]
#[derive(Debug)]
pub struct UnoShare
{
    mnemonic: NonNull<c_char>,
}

///
/// Returns the actual member share by index. 
///
#[no_mangle]
pub extern "C"
fn uno_get_s93_share_by_index
(
    group_split: NonNull<UnoGroupSplit>,
    index: u8,
    err: Option<&mut MaybeUninit<Error>>,
)
-> Option<NonNull<UnoShare>>
{
    let shares = unsafe {
        let mbs = group_split.as_ref().member_shares.as_ref();
        std::slice::from_raw_parts(mbs.ptr.as_ptr(), mbs.len)
    };

    if usize::from(index) >= shares.len() {
        err.map(|e| e.write(UNO_ERR_ILLEGAL_ARG));
        return None;
    }
    let share = &shares[usize::from(index)];

    let mnemonic = match share.to_mnemonic() {
        Ok(words) => words.join(" "),
        Err(_) => {
            err.map(|e| e.write(UNO_ERR_MNEMONIC));
            return None;
        },
    };
    let c_string = match CString::new(mnemonic) {
        Ok(cs) => cs,
        Err(_) => {
            err.map(|e| e.write(UNO_ERR_MNEMONIC)); 
            return None;
        },
    };  
    let res = UnoShare {
        // SAFETY: into_raw is never null
        mnemonic: unsafe { NonNull::new_unchecked(c_string.into_raw()) },
    };

    NonNull::new(Box::leak(Box::new(res)))
}

///
/// Free a previously allocated share returned by `uno_get_s39_share_by_index`.
///
#[no_mangle]
pub extern "C"
fn uno_free_s39_share(maybe_share: Option<NonNull<UnoShare>>)
{
    maybe_share.map(|s| unsafe { 
        let share = Box::from_raw(s.as_ptr());
        CString::from_raw((*share).mnemonic.as_ptr());
    });
}

///
/// Share metadata struct. Metadata about a share can be obtained by calling
/// `uno_get_share_metadata` with an UnoS39Share. 
///
#[repr(C)]
#[derive(Debug)]
pub struct UnoShareMetadata
{
    /// Random 15 bit value which is the same for all shares and is used to
    /// verify that the shares belong together; it is also used as salt in the
    /// encryption of the master secret. (15 bits)
    pub identifier: u16,

    /// Indicates the total number of iterations to be used in PBKDF2. The
    /// number of iterations is calculated as 10000x2^e. (5 bits)
    pub iteration_exponent: u8,

    /// The x value of the group share (4 bits)
    pub group_index: u8,

    /// indicates how many group shares are needed to reconstruct the master
    /// secret. The actual value is endoded as Gt = GT - 1, so a value of 0
    /// indicates that a single group share is needed (GT = 1), a value of 1
    /// indicates that two group shares are needed (GT = 2) etc. (4 bits)
    pub group_threshold: u8,

    /// indicates the total number of groups. The actual value is encoded as
    /// g = G - 1 (4 bits)
    pub group_count: u8,

    /// Member index, or x value of the member share in the given group (4 bits)
    pub member_index: u8,

    /// indicates how many member shares are needed to reconstruct the group
    /// share. The actual value is encoded as t = T − 1. (4 bits)
    pub member_threshold: u8,

    /// corresponds to a list of the SSS part's fk(x) values 1 ≤ k ≤ n. Each
    /// fk(x) value is encoded as a string of eight bits in big-endian order.
    /// The concatenation of these bit strings is the share value. This value is
    /// left-padded with "0" bits so that the length of the padded share value
    /// in bits becomes the nearest multiple of 10. (padding + 8n bits)
    pub share_value: UnoByteSlice,

    /// an RS1024 checksum of the data part of the share
    /// (that is id || e || GI || Gt || g || I || t || ps). The customization
    /// string (cs) of RS1024 is "shamir". (30 bits)
    pub checksum: u32,
}

///
/// Get the share metadata from an UnoShare.
///
#[no_mangle]
pub extern "C"
fn uno_get_s39_share_metadata
(
    share: NonNull<UnoShare>,
    err: Option<&mut MaybeUninit<Error>>,
)
-> Option<NonNull<UnoShareMetadata>>
{
    let mnemonic_c = unsafe { 
        CStr::from_ptr(share.as_ref().mnemonic.as_ptr())
    };
    let mnemonic_str = match mnemonic_c.to_str() {
        Ok(ms) => ms,
        Err(_) => {
            err.map(|e| e.write(UNO_ERR_ILLEGAL_ARG));
            return None;
        },
    };

    let words: Vec<String> = mnemonic_str.split(' ')
        .map(|s| s.to_owned())
        .collect();

    let share = match uno::Share::from_mnemonic(&words) {
        Ok(s) => s,
        Err(_) => {
            err.map(|e| e.write(UNO_ERR_ILLEGAL_ARG));
            return None;
        }
    };

    let (ptr, len, cap) = share.share_value.into_raw_parts();
    let share_value = UnoByteSlice {
        // SAFETY: ptr from Vec::into_raw_parts is never null.
        ptr: unsafe { NonNull::new_unchecked(ptr) },
        len: len,
        _cap: cap,
    };
    let res = UnoShareMetadata {
        identifier: share.identifier,
        iteration_exponent: share.iteration_exponent,
        group_index: share.group_index,
        group_threshold: share.group_threshold,
        group_count: share.group_count,
        member_index: share.member_index,
        member_threshold: share.member_threshold,
        share_value: share_value,
        checksum: share.checksum,
    };

    NonNull::new(Box::leak(Box::new(res)))
}

///
/// Free a previously allocated ShareMetadata returned by
/// `uno_get_s39_share_metadata`.
///
#[no_mangle]
pub extern "C"
fn uno_free_s39_share_metadata(maybe_md: Option<NonNull<UnoShareMetadata>>)
{ 
    maybe_md.map(|md| unsafe { 
        let md = Box::from_raw(md.as_ptr());
        uno_free_byte_slice((*md).share_value);
    });
}

///
/// See s39::combine.
///
/// Provided an array of c-stirng s39 shamir's shares, recombine and recover 
/// the original UnoId. The returned UnoId must be freed using `uno_free_id`.
/// 
#[no_mangle]
pub extern "C"
fn uno_s39_combine
(
    share_mnemonics: NonNull<NonNull<c_char>>,
    total_shares: usize,
    err: Option<&mut MaybeUninit<Error>>,
)
-> Option<NonNull<UnoId>>
{
    let shares_ptr = share_mnemonics.as_ptr();
    let mut shares = Vec::<Vec<String>>::with_capacity(total_shares);
    for i in 0..total_shares {
        let mnemonic_c = unsafe { 
            CStr::from_ptr((*shares_ptr.add(i)).as_ptr())
        };
        let mnemonic_str = match mnemonic_c.to_str() {
            Ok(s) => s,
            Err(_) => {
                err.map(|e| e.write(UNO_ERR_ILLEGAL_ARG));
                return None;
            },
        };
        let words: Vec<String> = mnemonic_str.split(' ')
            .map(|s| s.to_owned())
            .collect();
 
        shares[i] = words; 
    }

    let uno_id = match uno::combine(&shares[..]) {
        Ok(id) => UnoId(id),
        Err(_) => {
            err.map(|e| e.write(UNO_ERR_ILLEGAL_ARG));
            return None;
        },
    };

    NonNull::new(Box::leak(Box::new(uno_id)))
}


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}

