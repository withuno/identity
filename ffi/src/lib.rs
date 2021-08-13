//
// Copyright 2021 WithUno, Inc.
// SPDX-License-Identifier: AGPL-3.0-only
//


use std::option::Option;
use std::convert::TryFrom; 

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
mod ffi;

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

const ERR_SUCCESS_STR: CString =
    CString::new("success");

const ERR_ILLEGAL_ARG_STR: CString =
    CString::new("illegal argument");

const ERR_S39_SPLIT_STR: CString =
    CString::new("s39 split failed");

const ERR_S39_SHARE_ID_MISMATCH_STR: CString =
    CString::new("s39 combine share id mismatch");

const ERR_S39_SHARE_MISSING_STR: CString =
    CString::new("s39 combine missing shares");

const ERR_S39_CHECKSUM_FAILURE_STR: CString =
    CString::new("s39 combine share checksum invalid");

///
/// Get a description for the provided error code. The lifetime of the returned
/// string does not need to be managed by the caller.
///
#[no_mangle]
pub extern "C"
fn uno_get_msg_from_err(err: Error) -> NonNull<c_char>
{
    let msg = match err {
        UNO_ERR_SUCCESS => ERR_SUCCESS_STR,
        UNO_ERR_ILLEGAL_ARG => ERR_ILLEGAL_ARG_STR,
        UNO_ERR_SPLIT => ERR_S39_SPLIT_STR,
        UNO_ERR_SHARE_ID => ERR_S39_SHARE_ID_MISMATCH_STR,
        UNO_ERR_SHARE_MISS => ERR_S39_SHARE_MISSING_STR,
        UNO_ERR_CHECKSUM => ERR_S39_CHECKSUM_FAILURE_STR,
    }
    NonNull::from(msg)
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
    if len < 0 {
        err.map(|e| e.write(UNO_ERR_ILLEGAL_ARG);
        return None;
    }

    // TODO: make sure this copies, I have doubts
    let seed = unsafe { std::slice::from_raw_parts(bytes, len) };
   
    UnoId::try_from(seed)
        .map(|id| Box::leak(Box::new(id)) )
        .ok()
}

///
/// Copy the raw 32 bytes backing an uno id.
///
#[no_mangle]
pub extern "C"
fn uno_copy_id_bytes
(
    uno_id: NonNull<UnoId>,
    bytes: NonNull<MaybeUninit<[u8]>>,
    len: usize,
    err: Option<&mut MaybeUninit<Error>>,
)
{
    if len < 32 {
        err.map(|e| e.write(UNO_ERR_ILLEGAL_ARG);
        return;
    }
    for i in 0..32 {
        unsafe { *bytes.add(i) = uno_id.0[i] }
    }
}

///
/// Free a previously allocated UnoId from `uno_get_id_from_bytes`.
///
#[no_mangle]
pub extern "C"
fn uno_free_id(id: Option<NonNull<UnoId>>)
{ 
    id.map(|i| drop( unsafe { Box::from_raw(i) } ));
}

#[repr(C)]
struct UnoByteSlice {
    ptr: NonNull<u8>,
    len: usize,
    cap: usize,
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
    let out = ManuallyDrop::new(Vec<u8>::with_capacity(32));
    uno_copy_id_bytes(uno_id, &out, out.len(), None);

    UnoByteSlice{ NonNull::new(out), out.len(), out.capacity() }
}

///
/// Free the backing array on an UnoByteSlice from `uno_get_id_bytes`.
///
#[no_mangle]
pub extern "C"
fn uno_id_get_bytes(byte_slice: UnoByteSlice)
{
    Vec::from_raw_parts(byte_slice.ptr, byte_slice.len, byte_slice.cap));
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
    group_threshold: usize,
    group_total: usize,
    group_specs: NonNull<[UnoGroupSpec]>,
    err: Option<&mut MaybeUninit<Error>>,
)
-> Option<NonNull<UnoSplitResult>>
{
    // convert group specs
    let mut specs = Vec::<(u8,u8)>::with_capacity(group_total);
    for i in 0..group_total {
        let gs: &UnoGroupSpec;
        unsafe { 
            gs = *group_specs.add(i) as &UnoGroupSpec;
        }
        specs.push( (gs.threshold, gs.total) );
    }

    let group_splits = match uno::split(uno_id, &specs[..]) {
        Ok(sp) => sp,
        Err(_) => {
            err.map(|e| e.write(UNO_ERR_ILLEGAL_ARG) );
            return None;
        },
    };
    let (ptr, len, cap) = group_splits.into_raw_parts();
    let res = SplitResult { NonNull::new(ptr), len, cap }

    Some(Box::leak(Box::new(res)))
}

///
/// Free a previously allocated SplitResult from `uno_s39_split`.
///
#[no_mangle]
pub extern "C"
fn uno_free_split_result(id: Option<NonNull<UnoSplitResult>>)
{ 
    id.map(|i| unsafe { 
        Vec::from_raw_parts(i.ptr, i.len, i.cap);
        Box::from_raw(i);
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
    pub share_count: u8,
    /// Opaque reference to the constituent member shares. Acquire one of the
    /// shares with `uno_get_member_share_by_index`.
    pub member_shares: UnoMemberSharesVec,
}

///
/// Opaque array containing share metadata. Get a member share by index using
/// `uno_get_member_share_by_index`.
///
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
    let groups = ManuallyDrop::new(Vec<uno::GroupShare>.from_raw_parts(
        split_result.ptr,
        split_result.len,
        split_result.cap,
    ));
    if index >= groups.len() {
        err.map(|e| e.write(1));
        return None;
    }
    let item = groups[index];

    // prune unused vector capacity
    item.member_shares.shrink_to_fit();
    // leak the share vector
    let share_vec = ManuallyDrop::new(item.member_shares);

    let shares = UnoMemberSharesVec { 
        ptr: share_vec.as_mut_ptr()
        len: share_vec.len(),
        cap: share_vec.capacity(),
    }
    let res = UnoGroupSplit { 
        group_id: item.group_id,
        iteration_exponent: item.iteration_exponent,
        group_index: item.group_index,
        group_threshold: item.group_threshold,
        group_count: item.group_count,
        member_threshold: item.member_threshold,
        share_count: share_vec.len(),
        member_shares: Box::leak(Box::new(shares)),
    };

    Some(Box::leak(Box::new(res)))
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
        let gsb = Box::from_raw(gs);
        let msb = Box::from_raw(gs.member_shares);
        Vec::from_raw_parts(msb.ptr, msb.len, mbs.cap);
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
    mnemonic: *const c_char,
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
    let mbs = group_split.member_shares
    let shares = ManuallyDrop::new(Vec::from_raw_parts(
        mbs.ptr,
        mbs.len,
        mbs.cap
    ));

    if index >= shares.len() {
        err.map(|e| e.write(UNO_ERR_ILLEGAL_ARG));
        return None;
    }
    let share = shares[index];

    // the mnemonic form as a slice of words rather than a whole string
    let mnemonic = share.to_mnemonic().join(" ");
    let c_string = match CString::new(mnemonic) {
        OK(cs) => cs,
        Err(e) => {
            err.map(|e| e.write(ErrInternal)); 
            return None;
        },
    };  
    
    let res = UnoShare(mnemonic: c_string.into_raw());

    Some(Box::leak(Box::new(res))
}

///
/// Free a previously allocated share returned by `uno_get_s39_share_by_index`.
///
fn uno_free_s39_share(share: Option<NonNull<UnoS39Share>>)
{
    share.map(|s| 
        CString::from_raw(s.mnemonic);
        Box::from_raw(s);
    );
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

    // configuration values
//    pub config: ShareConfig,
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
    let mnemonic_c = ManuallyDrop::new(CString::from_raw(share.mnemonic));
    let mnemonic_str = String::from_utf8(mnemonic_c.as_bytes());

    let words: Vec<String> = mnemonic_str.split(' ')
        .map(|s| s.to_owned())
        .collect();

    let share = uno::Share::from_mnemonic(&words); 

    let (ptr, len, cap) = share.share_value.into_raw_parts();
    let share_value = UnoByteSlice {
        ptr: NonNull::new(ptr),
        len: len,
        cap: cap,
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

    Some(Box::leak(Box::new(res)))
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
        let md = Box::from_raw(md);
        let bs = md.share_value;
        Vec::from_raw_parts(bs.ptr, sb.len, bs.cap);
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
    /// An array of mnemonic strings.
    share_mnemonics: NonNull<[NonNull<c_char>]>,
    total_shares: usize,
    err: Option<&mut MaybeUninit<Error>>,
)
-> Option<NonNull<UnoId>>
{
    let mut shares = Vec::<Vec<String>>::with_capacity(total_shares);
    for i in 0..total_shares {
        let mnemonic_c = CStr::from_ptr(share_mnemonics.add(i));
        let mnemonic_str = match mnemonic_c.to_str() {
            Ok(s) => s,
            Err(e) => {
                err.map(|e| e.write(UNO_ERR_ILLEGAL_ARG));
                return None;
            },
        };
        let words: Vec<String> = mnemonic.split(' ')
            .map(|s| s.to_owned())
            .collect();
 
        shares[i] = words; 
    }

    let uno_id = match uno::combine(&shares[..]) {
        Ok(id) => id,
        Err(e) => {
            err.map(|e| e.write(UNO_ERR_ILLEGAL_ARG));
            return None;
        },
    };

    Some(Box::leak(Box::new(uno_id)))
}


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}

