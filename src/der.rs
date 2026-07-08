//! Hand-rolled minimal ASN.1 DER encoder + parser.
//!
//! Used by [`super::tsa`] (RFC 3161) and [`super::ocsp`] (RFC 6960)
//! to build/parse the few specific structures we need without
//! dragging in a full ASN.1 dependency tree.
//!
//! Only handles definite-length DER (no BER, no constructed
//! OCTET STRINGs, etc.) — sufficient for the request/response
//! shapes both protocols mandate.

use crate::error::{Result, SignatureError};

pub(crate) fn encode_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len <= 0xff {
        vec![0x81, len as u8]
    } else if len <= 0xffff {
        vec![0x82, (len >> 8) as u8, (len & 0xff) as u8]
    } else if len <= 0xff_ffff {
        vec![
            0x83,
            (len >> 16) as u8,
            ((len >> 8) & 0xff) as u8,
            (len & 0xff) as u8,
        ]
    } else {
        let bytes = (len as u32).to_be_bytes();
        let mut out = Vec::with_capacity(5);
        out.push(0x84);
        out.extend_from_slice(&bytes);
        out
    }
}

pub(crate) fn encode_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let len_bytes = encode_length(value.len());
    let mut out = Vec::with_capacity(1 + len_bytes.len() + value.len());
    out.push(tag);
    out.extend(len_bytes);
    out.extend_from_slice(value);
    out
}

/// Read a single TLV from the start of `input`, expecting `tag`,
/// and return the value bytes only (no tag, no length prefix).
/// Errors if there are trailing bytes beyond the TLV.
pub(crate) fn read_tlv<'a>(
    input: &'a [u8],
    tag: u8,
) -> std::result::Result<&'a [u8], &'static str> {
    let (value, rest) = read_tlv_with_remainder(input, tag)?;
    if !rest.is_empty() {
        return Err("trailing bytes after TLV");
    }
    Ok(value)
}

/// Read a single TLV from the start of `input`, expecting `tag`,
/// and return (value, remaining bytes after the TLV).
pub(crate) fn read_tlv_with_remainder<'a>(
    input: &'a [u8],
    tag: u8,
) -> std::result::Result<(&'a [u8], &'a [u8]), &'static str> {
    if input.is_empty() {
        return Err("empty DER input");
    }
    if input[0] != tag {
        return Err("unexpected DER tag");
    }
    let (len, len_size) = read_length(&input[1..])?;
    let total = 1 + len_size + len;
    if input.len() < total {
        return Err("DER value truncated");
    }
    Ok((&input[1 + len_size..total], &input[total..]))
}

/// Total byte size (tag + length + value) of the TLV that starts
/// at `input[0]`. Used to slice out a sub-DER blob without
/// peeking at its content.
pub(crate) fn total_tlv_length(input: &[u8]) -> std::result::Result<usize, &'static str> {
    if input.is_empty() {
        return Err("empty DER input");
    }
    let (len, len_size) = read_length(&input[1..])?;
    Ok(1 + len_size + len)
}

pub(crate) fn read_length(input: &[u8]) -> std::result::Result<(usize, usize), &'static str> {
    if input.is_empty() {
        return Err("missing length byte");
    }
    let first = input[0];
    if first < 0x80 {
        return Ok((first as usize, 1));
    }
    let n = (first & 0x7f) as usize;
    if n == 0 || n > 4 {
        return Err("unsupported DER length form");
    }
    if input.len() < 1 + n {
        return Err("length bytes truncated");
    }
    let mut len: usize = 0;
    for &b in &input[1..1 + n] {
        len = (len << 8) | b as usize;
    }
    Ok((len, 1 + n))
}

pub(crate) fn decode_unsigned_int(value: &[u8]) -> Result<u64> {
    if value.is_empty() || value.len() > 9 {
        return Err(SignatureError::GeneralError(
            "INTEGER out of range for u64".into(),
        ));
    }
    // Allow a leading 0x00 byte that DER uses to keep large
    // values unsigned.
    let bytes = if value[0] == 0 && value.len() > 1 {
        &value[1..]
    } else {
        value
    };
    if bytes.len() > 8 {
        return Err(SignatureError::GeneralError("INTEGER > 64 bits".into()));
    }
    let mut out: u64 = 0;
    for &b in bytes {
        out = (out << 8) | b as u64;
    }
    Ok(out)
}
