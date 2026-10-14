use std::io::Cursor;

use anyhow::Context;
use byteorder::{BigEndian, ReadBytesExt};

use crate::{
    ikev1::{
        model::{ExchangeType, IsakmpFlags, NotifyMessageType, PayloadType},
        payload::Payload,
    },
    message::{IKEV1_VERSION, ISAKMP_HEADER_LEN},
    payload::PAYLOAD_HEADER_LEN,
    transport::CheckInformational,
};

// RFC 2408 notify message types
const NOTIFY_CONNECTED: u16 = 31;
const NOTIFY_RESPONDER_LIFETIME: u16 = 37;
const NOTIFY_CHECKPOINT_SPECIFIC: u16 = 9101;

#[derive(Debug, Clone)]
pub struct Ikev1Message {
    pub initiator_spi: u64,
    pub responder_spi: u64,
    pub version: u8,
    pub exchange_type: ExchangeType,
    pub flags: IsakmpFlags,
    pub message_id: u32,
    pub payloads: Vec<Payload>,
}

impl Ikev1Message {
    /// Checks that `data` holds exactly one structurally valid IKEv1 message, before any of it is
    /// trusted: the header (RFC 2408 §3.1) must be complete, carry major version 1 and a length equal to
    /// the size of `data`, and an unencrypted payload chain (RFC 2408 §3.2) must fill the body exactly.
    /// An encrypted body cannot be walked before decryption, so only its presence is checked.
    ///
    /// Anything can arrive on the IKE port, e.g. a stray datagram on UDP 4500, and must be rejected
    /// here rather than fail deep inside the decoder.
    pub fn validate(data: &[u8]) -> anyhow::Result<()> {
        if data.len() < ISAKMP_HEADER_LEN {
            anyhow::bail!("IKEv1 message shorter than its header: {} bytes", data.len());
        }

        let mut reader = Cursor::new(&data[16..]);
        let mut next_payload = reader.read_u8()?;
        let version = reader.read_u8()?;
        reader.read_u8()?;
        let flags = IsakmpFlags::from_bits_retain(reader.read_u8()?);
        reader.read_u32::<BigEndian>()?;
        let length = reader.read_u32::<BigEndian>()? as usize;

        if version >> 4 != IKEV1_VERSION >> 4 {
            anyhow::bail!("Not an IKEv1 message: version {:#04x}", version);
        }
        if length != data.len() {
            anyhow::bail!("IKEv1 message claims {} bytes, got {}", length, data.len());
        }

        let body = &data[ISAKMP_HEADER_LEN..];

        if flags.contains(IsakmpFlags::ENCRYPTION) {
            if body.is_empty() {
                anyhow::bail!("Encrypted IKEv1 message has no body");
            }
            return Ok(());
        }

        let mut offset = 0;
        while next_payload != u8::from(PayloadType::None) {
            let header = body
                .get(offset..offset + PAYLOAD_HEADER_LEN)
                .context("IKEv1 payload header outside the message")?;
            let payload_len = u16::from_be_bytes([header[2], header[3]]) as usize;
            if payload_len < PAYLOAD_HEADER_LEN || offset + payload_len > body.len() {
                anyhow::bail!("IKEv1 payload length {} outside the message", payload_len);
            }
            next_payload = header[0];
            offset += payload_len;
        }

        if offset != body.len() {
            anyhow::bail!("{} bytes after the last IKEv1 payload", body.len() - offset);
        }

        Ok(())
    }

    /// Type of the payload at `index`, for the Next Payload field that
    /// precedes it. `None` past the end of the chain.
    pub fn next_payload(&self, index: usize) -> PayloadType {
        self.payloads
            .get(index)
            .map_or(PayloadType::None, |p| p.as_payload_type())
    }
}

impl CheckInformational for Ikev1Message {
    fn check_informational(&self) -> anyhow::Result<()> {
        if self.exchange_type != ExchangeType::Informational {
            return Ok(());
        }

        for payload in &self.payloads {
            if let Payload::Notification(notify) = payload {
                if matches!(
                    notify.message_type,
                    NotifyMessageType::Other(NOTIFY_CONNECTED | NOTIFY_RESPONDER_LIFETIME | NOTIFY_CHECKPOINT_SPECIFIC)
                ) {
                    anyhow::bail!(String::from_utf8_lossy(&notify.data).into_owned());
                } else if notify.message_type < NOTIFY_CONNECTED.into() {
                    anyhow::bail!("IKE notify error {:?}", notify.message_type);
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MM: &[u8] = include_bytes!("../../tests/mm.bin");

    /// A header for a message of `length` bytes whose first payload is `next_payload`.
    fn header(next_payload: u8, flags: u8, length: u32) -> Vec<u8> {
        let mut data = vec![0x11; 16];
        data.extend([next_payload, IKEV1_VERSION, 2, flags, 0, 0, 0, 0]);
        data.extend(length.to_be_bytes());
        data
    }

    fn with_length(mut data: Vec<u8>) -> Vec<u8> {
        let length = (data.len() as u32).to_be_bytes();
        data[24..28].copy_from_slice(&length);
        data
    }

    #[test]
    fn test_validate_captured_main_mode() {
        Ikev1Message::validate(MM).unwrap();
    }

    #[test]
    fn test_validate_header_only() {
        Ikev1Message::validate(&header(0, 0, 28)).unwrap();
    }

    #[test]
    fn test_validate_payload_chain() {
        // vendor ID (13) followed by a nonce (10), both with 2-byte bodies
        let mut data = header(13, 0, 0);
        data.extend([10, 0, 0, 6, 1, 2, 0, 0, 0, 6, 3, 4]);
        Ikev1Message::validate(&with_length(data)).unwrap();
    }

    #[test]
    fn test_validate_rejects_short_data() {
        for len in [0, 1, 4, 27] {
            assert!(Ikev1Message::validate(&MM[..len]).is_err(), "{len}");
        }
    }

    #[test]
    fn test_validate_rejects_wrong_version() {
        let mut data = MM.to_vec();
        data[17] = 0x20;
        assert!(Ikev1Message::validate(&data).is_err());
    }

    #[test]
    fn test_validate_rejects_length_mismatch() {
        assert!(Ikev1Message::validate(&MM[..MM.len() - 1]).is_err());

        let mut data = MM.to_vec();
        data.push(0);
        assert!(Ikev1Message::validate(&data).is_err());

        for length in [0u32, 27, u32::MAX] {
            let mut data = MM.to_vec();
            data[24..28].copy_from_slice(&length.to_be_bytes());
            assert!(Ikev1Message::validate(&data).is_err(), "{length}");
        }
    }

    #[test]
    fn test_validate_rejects_bad_payload_chain() {
        // payload length below its own header
        let mut data = header(13, 0, 0);
        data.extend([0, 0, 0, 3]);
        assert!(Ikev1Message::validate(&with_length(data)).is_err());

        // payload runs past the end of the message
        let mut data = header(13, 0, 0);
        data.extend([0, 0, 0, 8, 1, 2]);
        assert!(Ikev1Message::validate(&with_length(data)).is_err());

        // chain announces a further payload that is not there
        let mut data = header(13, 0, 0);
        data.extend([10, 0, 0, 6, 1, 2]);
        assert!(Ikev1Message::validate(&with_length(data)).is_err());

        // bytes after the last payload
        let mut data = header(13, 0, 0);
        data.extend([0, 0, 0, 6, 1, 2, 0xff]);
        assert!(Ikev1Message::validate(&with_length(data)).is_err());

        // payloads announced, but no body
        assert!(Ikev1Message::validate(&header(13, 0, 28)).is_err());
    }

    #[test]
    fn test_validate_encrypted_body() {
        let encryption = IsakmpFlags::ENCRYPTION.bits();

        // the chain is inside the ciphertext, so it is not walked
        let mut data = header(8, encryption, 0);
        data.extend([0xaa; 16]);
        Ikev1Message::validate(&with_length(data)).unwrap();

        assert!(Ikev1Message::validate(&header(8, encryption, 28)).is_err());
    }
}
