//! Payload framing shared by IKEv1 (RFC 2408 §3.2) and IKEv2 (RFC 7296 §3.2).
//!
//! Both versions chain payloads behind the same 4-byte generic header — next
//! payload type, a flags octet, and a length covering the header — and differ
//! only in the payload bodies and in what the flags octet means. The
//! structures each version defines model the *body* alone, so their `len` and
//! `to_bytes` exclude those four bytes; this module owns the header itself.

use std::io::Read;

use anyhow::Context;
use byteorder::{BigEndian, ReadBytesExt};
use bytes::{BufMut, Bytes, BytesMut};

/// Length of the generic payload header that precedes every payload body.
pub const PAYLOAD_HEADER_LEN: usize = 4;

/// Upper bound on a single payload, to keep a corrupt length field from
/// asking for an arbitrarily large allocation.
pub const MAX_PAYLOAD_SIZE: u16 = 16384;

/// Critical bit in the second octet of the generic payload header. Only IKEv2
/// defines it (RFC 7296 §2.5); IKEv1 sends the octet as zero.
pub(crate) const CRITICAL_BIT: u8 = 0x80;

/// A payload body that can be encoded and decoded on its own, without the
/// generic header.
pub trait PayloadLike: Sized {
    fn to_bytes(&self) -> Bytes;
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn parse<R: Read>(reader: &mut R) -> anyhow::Result<Self>;
}

pub(crate) fn read_bytes<R: Read>(reader: &mut R, len: usize) -> anyhow::Result<Bytes> {
    let mut data = vec![0u8; len];
    reader.read_exact(&mut data)?;
    Ok(data.into())
}

pub(crate) fn read_to_end<R: Read>(reader: &mut R) -> anyhow::Result<Bytes> {
    let mut data = Vec::new();
    reader.read_to_end(&mut data)?;
    Ok(data.into())
}

/// Reads one generic payload header and the body it describes, returning the
/// type of the *next* payload in the chain, whether this one is flagged
/// critical, and the body.
pub(crate) fn read_next_payload<R: Read, T: From<u8>>(reader: &mut R) -> anyhow::Result<(T, bool, Bytes)> {
    let next_payload = reader.read_u8()?.into();
    let critical = reader.read_u8()? & CRITICAL_BIT != 0;
    let length = reader.read_u16::<BigEndian>()?;

    if length > MAX_PAYLOAD_SIZE {
        anyhow::bail!("Payload too large: {} > {}", length, MAX_PAYLOAD_SIZE);
    }
    let length = length
        .checked_sub(PAYLOAD_HEADER_LEN as u16)
        .context("Payload length below header size")?;

    Ok((next_payload, critical, read_bytes(reader, length as usize)?))
}

/// Appends one generic payload header and `body` to `buf`.
pub(crate) fn write_payload(buf: &mut BytesMut, next_payload: u8, body: &Bytes) {
    buf.put_u8(next_payload);
    buf.put_u8(0);
    buf.put_u16((PAYLOAD_HEADER_LEN + body.len()) as u16);
    buf.put_slice(body);
}

/// A payload whose body is opaque: nonce, vendor ID, hash, EAP, SK, or
/// anything unrecognised.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct BasicPayload {
    pub data: Bytes,
}

impl BasicPayload {
    pub fn new(data: Bytes) -> Self {
        Self { data }
    }
}

impl<T: AsRef<[u8]>> From<T> for BasicPayload {
    fn from(value: T) -> Self {
        Self::new(Bytes::copy_from_slice(value.as_ref()))
    }
}

impl PayloadLike for BasicPayload {
    fn to_bytes(&self) -> Bytes {
        self.data.clone()
    }

    fn len(&self) -> usize {
        self.data.len()
    }

    fn parse<R: Read>(reader: &mut R) -> anyhow::Result<Self> {
        Ok(Self {
            data: read_to_end(reader)?,
        })
    }
}
