//
// Copyright 2021 WithUno, Inc.
// SPDX-License-Identifier: AGPL-3.0-only
//

//!
//! The Uno ffi module presents a C compatible ABI for calling into libuno.
//!
//! There are a few conventions to be aware of. All ffi functions are prefaced
//! with `uno_` since C does not have namespaces. Following the prefix,
//! functions that are specified with `get_` return rust-owned (usually heap
//! allocated) data while functions with `copy_` operate on C (or generally
//! caller) allocated data.
//!
//! The types from the uno crate are either aliased, newtyped, or wrapped so
//! they become FFI-safe. The prefix `Uno` is appened to the uno::Type typename
//! since, again, C does not have namespaces.
//! 
//! The Uno FFI uses a the conventional C "error as return value" call style.
//! The actual data being returned is conveyed through a trailing out param.
//! The output of FFI functions is most always a pointer to a rust allocated,
//! sometimes opaque, struct. If you're expecting a Frob:
//! ```
//! pub extern "C" fn uno_get_frob(..., Option<NonNull<*const Frob>>) -> Error
//! ```
//! Null is not a valid value for any of the FFI types and represents the None
//! value of the Option. You must pass a non-null pointer as the value of the 
//! out param, but you should not allocate (and cannot in the case of opaque
//! types) underlying memory for the out value. That is handled by Rust.
//! 
//! If the call succeeds, the return value will be 0 and you may safely
//! use the pointer returned to you by the function in future calls to `uno_`
//! api functions and, if the type is not opaque, dereference the pointer in
//! order to access the allocated data. If Rust allocated memory for you, then
//! it is your responsibility to, when finished with the memory, call
//! `uno_free_...` passing the pointer associated with the memory that Rust
//! originally allocated on your behalf.
//!
//! If the call fails the return value will be > 0 and nothing will be written
//! to the location specified in the out param. Error codes can be used to
//! lookup an error message using:
//! ```
//! uno_get_msg_for_error.
//! ``` 
//!


#![feature(vec_into_raw_parts, maybe_uninit_extra)]


use std::convert::TryFrom; 
use std::ffi::CStr;
use std::ffi::CString;
use std::mem::MaybeUninit;
use std::option::Option;
use std::os::raw::c_char;
use std::os::raw::c_int;
use std::ptr::NonNull;

// TODO: generally convert everything to _Nonnull compatible declarations. This
// involves using refs and NonNull<> instead of const * and MaybeUninit<>. 

// TODO: make enum
pub const UNO_ERR_SUCCESS: c_int = 0;
pub const UNO_ERR_ILLEGAL_ARG: c_int = 1;
pub const UNO_ERR_SPLIT: c_int = 2;
pub const UNO_ERR_COMBINE: c_int = 3;
pub const UNO_ERR_SHARE_ID: c_int = 4;
pub const UNO_ERR_SHARE_MISS: c_int = 5;
pub const UNO_ERR_CHECKSUM: c_int = 6;
pub const UNO_ERR_MNEMONIC: c_int = 7;

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
fn uno_get_msg_from_err(err: c_int) -> *const c_char
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
    bytes: Option<&u8>,
    len: usize,
    out: Option<&mut MaybeUninit<Option<&UnoId>>>,
)
-> c_int
{
    let seed = match bytes {
        // SAFETY: "nullable pointer optimization"
        Some(ptr) => unsafe { std::slice::from_raw_parts(ptr, len) },
        None => return UNO_ERR_ILLEGAL_ARG,
    };
  
    let id = match uno::Id::try_from(seed) {
        Ok(id) => UnoId(id),
        Err(_) => return UNO_ERR_ILLEGAL_ARG,
    };

    let raw = Box::into_raw(Box::new(id)); 
    // SAFETY: box raw ptr is valid ^
    let res = unsafe { raw.as_ref() };

    out.map(|ptr| ptr.write(res));
    UNO_ERR_SUCCESS
}

///
/// Copy the raw 32 bytes backing an uno Id into caller-owned memory.
///
#[no_mangle]
pub extern "C"
fn uno_copy_id_bytes
(
    uno_id: Option<&UnoId>,
    bytes: Option<NonNull<u8>>,
    len: usize,
)
-> c_int
{
    let id = match uno_id {
        Some(id) => id.0,
        None => return UNO_ERR_ILLEGAL_ARG,
    };
    let bptr = match bytes {
        Some(nn) => nn.as_ptr(),
        None => return UNO_ERR_ILLEGAL_ARG,
    };
    if len < 32 {
        return UNO_ERR_ILLEGAL_ARG;
    }
 
    for i in 0..32 {
        // SAFETY: bptr is not null and is obtained mutable
        unsafe { bptr.add(i).write(id.0[i]) }
    }
    UNO_ERR_SUCCESS
}

///
/// Free a previously allocated UnoId from `uno_get_id_from_bytes`.
///
#[no_mangle]
pub extern "C"
fn uno_free_id(id: Option<NonNull<UnoId>>)
{ 
    id.map(|nn| unsafe { Box::from_raw(nn.as_ptr()) } );
}

///
/// UnoByteSlice can be treated like an array of uint8_t bytes on the C side.
/// You may not modify the bytes and the struct must be freed once it is no
/// longer needed.
///
#[repr(C)]
#[derive(Debug)]
pub struct UnoByteSlice
{
    ptr: *const u8,
    len: usize,
   _cap: usize,
}

///
/// Get the raw bytes backing an uno Id.
///
#[no_mangle]
pub extern "C"
fn uno_get_bytes_from_id
(
    uno_id: Option<&UnoId>,
    out: Option<&mut MaybeUninit<UnoByteSlice>>,
)
-> c_int
{
    let mut bytes = Vec::<u8>::with_capacity(32);
    {
        let bptr = NonNull::new(bytes.as_mut_ptr());
        let err = uno_copy_id_bytes(uno_id, bptr, bytes.len());
        if err > 0 {
            return err;
        }
    }

    // forget the vec
    let (rptr, len, cap) = bytes.into_raw_parts();

    let res = UnoByteSlice { ptr: rptr, len: len, _cap: cap, };

    out.map(|ptr| ptr.write(res));
    UNO_ERR_SUCCESS 
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
    // SAFETY: the ptr is originally mutable acquired from into_raw_parts ^
    unsafe {
        Vec::from_raw_parts(bs.ptr as *mut u8, bs.len, bs._cap)
    };
}

///
/// A GroupSpec is a tuple of (threshold, total) shares in a given s39 group
/// split. For instance, if you want a group to be split into 3 pieces, two
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
/// UnoId. The structure represents an opaque array of UnoGroupSplit structs. 
///
#[derive(Debug)]
pub struct UnoSplitResult
{
    ptr: NonNull<uno::GroupShare>,
    len: usize,
    cap: usize,
}

///
/// See s39::split.
///
/// Rather than an array of tuples, the caller provides an array of GroupSpec
/// structs. The group_threshold is fixed at 1 so this parameter is currently
/// unused.
///
/// Upon success, the SplitResult represents an array of UnoGroupSplits of
/// length group_total.
///
#[no_mangle]
pub extern "C"
fn uno_s39_split
(
    uno_id: Option<&UnoId>,
   _group_threshold: usize,
    group_specs: Option<&UnoGroupSpec>,
    group_total: usize,
    out: Option<&mut MaybeUninit<Option<&UnoSplitResult>>>,
)
-> c_int
{
    let id = match uno_id {
        Some(id) => id.0,
        None => return UNO_ERR_ILLEGAL_ARG,
    };
    let base = match group_specs {
        Some(gs) => gs as *const UnoGroupSpec,
        None => return UNO_ERR_ILLEGAL_ARG,
    };

    // convert group specs to spec tuples
    // 
    let mut specs = Vec::<(u8,u8)>::with_capacity(group_total);
    for i in 0..group_total {
        //
        // SAFETY: data is initialized by caller, we're just reborrowing
        //         caller provides the bounds and we stay within them
        //
        let gs = unsafe {
            &*base.add(i)
        };
        specs.push(
            (gs.threshold, gs.total)
        );
    }

    let group_splits = match uno::split(id, &specs[..]) {
        Ok(sp) => sp,
        Err(_) => return UNO_ERR_SPLIT,
    };

    let (ptr, len, cap) = group_splits.into_raw_parts();

    let split_result = UnoSplitResult {
        // SAFETY: ptr is never null
        ptr: unsafe { NonNull::new_unchecked(ptr) },
        len: len,
        cap: cap,
    };

    let raw = Box::into_raw(Box::new(split_result));
    let res = unsafe { raw.as_ref() };

    out.map(|ptr| ptr.write(res));
    UNO_ERR_SUCCESS
}

///
/// Free a previously allocated UnoSplitResult from `uno_s39_split`.
///
#[no_mangle]
pub extern "C"
fn uno_free_split_result(split_result: Option<NonNull<UnoSplitResult>>)
{ 
    split_result.map(|sr| unsafe { 
        let srb = Box::from_raw(sr.as_ptr());
        Vec::from_raw_parts((*srb).ptr.as_ptr(), (*srb).len, (*srb).cap);
    });
}

///
/// A GroupSplit contains metadata related to one of the groups of shares
/// requested during the split call. The actual shares are contained in the
/// opaque UnoMemberSharesVec struct.
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
    pub member_shares: *const UnoMemberSharesVec,
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
/// Get an UnoGroupSplit by index from an opaque UnoSplitResult.
///
#[no_mangle]
pub extern "C"
fn uno_get_group_from_split_result
(
    split_result: Option<&UnoSplitResult>,
    index: usize,
    out: Option<&mut MaybeUninit<UnoGroupSplit>>,
)
-> c_int
{
    let sr = match split_result {
        Some(sr) => sr,
        None => return UNO_ERR_ILLEGAL_ARG,
    };
    let groups = unsafe {
        std::slice::from_raw_parts(sr.ptr.as_ptr(), sr.len)
    };
    if index >= groups.len() {
        return UNO_ERR_ILLEGAL_ARG;
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
        member_shares: Box::into_raw(Box::new(shares)),
    };

    out.map(|ptr| ptr.write(res));
    UNO_ERR_SUCCESS
}

///
/// Free a previously allocated GroupSplit returned by
/// `uno_get_group_from_split_result`.
///
#[no_mangle]
pub extern "C"
fn uno_free_group_split(group_split: UnoGroupSplit)
{ 
    // ptr originally obtained mutable but presented as const for C
    let raw = group_split.member_shares as *mut UnoMemberSharesVec;
    let nnraw = NonNull::new(raw);
    let mbs = match nnraw {
        // SAFETY: originally boxed by us unless caller passes in uninit
        //         memory which they shant do.
        Some(ref nn) => unsafe { nn.as_ref() },
        None => return,
    };
    // SAFETY: we generated these values ourself, mbs is opaque
    unsafe {
        Vec::from_raw_parts(mbs.ptr.as_ptr(), mbs.len, mbs.cap);
        Box::from_raw(raw);
    };
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
    mnemonic: *const c_char,
}

///
/// Returns the actual member share by index. 
///
#[no_mangle]
pub extern "C"
fn uno_get_s39_share_by_index
(
    group_split: UnoGroupSplit,
    index: u8,
    out: Option<&mut MaybeUninit<UnoShare>>,
)
-> c_int
{
    let mbsp = group_split.member_shares as *mut UnoMemberSharesVec;

    let maybe_mbsp = NonNull::new(mbsp);
    let mbsr = match maybe_mbsp {
        Some(ref nn) => unsafe { nn.as_ref() },
        None => return UNO_ERR_ILLEGAL_ARG,
    };
    let shares = unsafe {
        std::slice::from_raw_parts(mbsr.ptr.as_ptr(), mbsr.len)
    };

    if usize::from(index) >= shares.len() {
        return UNO_ERR_ILLEGAL_ARG;
    }
    let share = &shares[usize::from(index)];

    let mnemonic = match share.to_mnemonic() {
        Ok(words) => words.join(" "),
        Err(_) => return UNO_ERR_MNEMONIC,
    };
    let c_string = match CString::new(mnemonic) {
        Ok(cs) => cs,
        Err(_) => return UNO_ERR_MNEMONIC,
    };  

    out.map(|ptr| ptr.write(
        UnoShare { mnemonic: c_string.into_raw(), })
    );
    UNO_ERR_SUCCESS
}

///
/// Convert a mnemonic string of 33 space separated words to an internal share
/// representation.
///
#[no_mangle]
pub extern "C"
fn uno_get_s39_share_from_mnemonic(
    ptr: *const c_char,
    out: Option<&mut MaybeUninit<UnoShare>>,
)
-> c_int
{
    // Looks like this if we pas ptr as an &c_char:    
    // let cstr = unsafe { CStr::from_ptr(ptr as *const c_char) };

    // SAFETY: call is responsible for providing a valid c_char
    // TODO: maybe have the caller pass a byte pointer and len?
    let cstr = unsafe { CStr::from_ptr(ptr) };
    let str = match cstr.to_str() {
        Ok(str) => str,
        Err(_) => return UNO_ERR_ILLEGAL_ARG,
    };

    let words: Vec<String> = str.split(' ')
        .map(|s| s.to_owned())
        .collect();

    let share = match uno::Share::from_mnemonic(&words) {
        Ok(share) => share,
        Err(_) => return UNO_ERR_MNEMONIC,
    };
    let mnemonic = match share.to_mnemonic() {
        Ok(words) => words.join(" "),
        Err(_) => return UNO_ERR_MNEMONIC,
    };
    let c_string = match CString::new(mnemonic) {
        Ok(cs) => cs,
        Err(_) => return UNO_ERR_MNEMONIC,
    };  
    let res = UnoShare { mnemonic: c_string.into_raw(), };

    out.map(|ptr| ptr.write(res));
    UNO_ERR_SUCCESS
}

///
/// Free a previously allocated share returned by `uno_get_s39_share_by_index`
/// or `uno_get_s39_share_from_mnemonic`.
///
#[no_mangle]
pub extern "C"
fn uno_free_s39_share(share: UnoShare)
{
    unsafe { 
        CString::from_raw(share.mnemonic as *mut c_char);
    };
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
    share: UnoShare,
    out: Option<&mut MaybeUninit<UnoShareMetadata>>,
)
-> c_int
{
    let mnemonic_c = unsafe { CStr::from_ptr(share.mnemonic) };

    let mnemonic_str = match mnemonic_c.to_str() {
        Ok(ms) => ms,
        Err(_) => return UNO_ERR_ILLEGAL_ARG,
    };

    let words: Vec<String> = mnemonic_str.split(' ')
        .map(|s| s.to_owned())
        .collect();

    let share = match uno::Share::from_mnemonic(&words) {
        Ok(s) => s,
        Err(_) => return UNO_ERR_ILLEGAL_ARG,
    };

    let (ptr, len, cap) = share.share_value.into_raw_parts();

    let res = UnoShareMetadata {
        identifier: share.identifier,
        iteration_exponent: share.iteration_exponent,
        group_index: share.group_index,
        group_threshold: share.group_threshold,
        group_count: share.group_count,
        member_index: share.member_index,
        member_threshold: share.member_threshold,
        share_value: UnoByteSlice {
            ptr: ptr,
            len: len,
           _cap: cap,
        },
        checksum: share.checksum,
    };

    out.map(|o| o.write(res));
    UNO_ERR_SUCCESS
}

///
/// Free a previously allocated ShareMetadata returned by
/// `uno_get_s39_share_metadata`.
///
#[no_mangle]
pub extern "C"
fn uno_free_s39_share_metadata(metadata: UnoShareMetadata)
{ 
    uno_free_byte_slice(metadata.share_value);
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
    share_nmemonics: Option<&Option<&c_char>>,
    total_shares: usize,
    out: Option<&mut MaybeUninit<Option<&UnoId>>>,
)
-> c_int
{
    let shares_ptr = match share_nmemonics {
        Some(ptr) => ptr as *const Option<&c_char>,
        None => return UNO_ERR_ILLEGAL_ARG,
    };

    let mut shares = Vec::<Vec<String>>::with_capacity(total_shares);

    for i in 0..total_shares {
        // SAFETY: call is responsible for providing an array of cstrs
        let mnemonic_c = match unsafe { *shares_ptr.add(i) } {
            Some(ptr) => unsafe { CStr::from_ptr(ptr) },
            None => return UNO_ERR_ILLEGAL_ARG,
        };
        let mnemonic_str = match mnemonic_c.to_str() {
            Ok(ms) => ms,
            Err(_) => return UNO_ERR_ILLEGAL_ARG,
        };
        let words: Vec<String> = mnemonic_str.split(' ')
            .map(|s| s.to_owned())
            .collect();
 
        shares.push(words);
    }

    let uno_id = match uno::combine(&shares[..]) {
        Ok(id) => UnoId(id),
        Err(_) => return UNO_ERR_COMBINE,
    };

    let raw = Box::into_raw(Box::new(uno_id));
    let res = unsafe { raw.as_ref() };

    out.map(|ptr| ptr.write(res));
    UNO_ERR_SUCCESS
}


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}

