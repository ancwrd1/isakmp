use std::io::Cursor;

use anyhow::Context;
use byteorder::{BigEndian, ReadBytesExt};

use crate::{
    ikev2::{
        model::{ExchangeType, Flags, NotifyType, PayloadType},
        payload::{NotifyPayload, Payload},
    },
    message::{IKEV2_VERSION, ISAKMP_HEADER_LEN},
    payload::PAYLOAD_HEADER_LEN,
    transport::CheckInformational,
};

#[derive(Debug, Clone)]
pub struct Ikev2Message {
    pub initiator_spi: u64,
    pub responder_spi: u64,
    pub version: u8,
    pub exchange_type: ExchangeType,
    pub flags: Flags,
    pub message_id: u32,
    pub payloads: Vec<Payload>,
}

impl Ikev2Message {
    /// Checks that `data` holds exactly one structurally valid IKEv2 message, before any of it is
    /// trusted: the header (RFC 7296 §3.1) must be complete, carry major version 2 and a length equal to
    /// the size of `data`, and the top-level payload chain (RFC 7296 §3.2) must fill the body exactly.
    /// An SK or SKF payload (RFC 7296 §3.14, RFC 7383 §2.5) must be the last one; its Next Payload names
    /// the first inner payload, and the chain inside the ciphertext cannot be walked before decryption.
    ///
    /// Anything can arrive on the IKE port, e.g. a stray datagram on UDP 4500, and must be rejected
    /// here rather than fail deep inside the decoder.
    pub fn validate(data: &[u8]) -> anyhow::Result<()> {
        if data.len() < ISAKMP_HEADER_LEN {
            anyhow::bail!("IKEv2 message shorter than its header: {} bytes", data.len());
        }

        let mut reader = Cursor::new(&data[16..]);
        let mut next_payload: PayloadType = reader.read_u8()?.into();
        let version = reader.read_u8()?;
        reader.read_u16::<BigEndian>()?;
        reader.read_u32::<BigEndian>()?;
        let length = reader.read_u32::<BigEndian>()? as usize;

        if version >> 4 != IKEV2_VERSION >> 4 {
            anyhow::bail!("Not an IKEv2 message: version {:#04x}", version);
        }
        if length != data.len() {
            anyhow::bail!("IKEv2 message claims {} bytes, got {}", length, data.len());
        }

        let body = &data[ISAKMP_HEADER_LEN..];

        let mut offset = 0;
        while next_payload != PayloadType::None {
            let header = body
                .get(offset..offset + PAYLOAD_HEADER_LEN)
                .context("IKEv2 payload header outside the message")?;
            let payload_len = u16::from_be_bytes([header[2], header[3]]) as usize;
            if payload_len < PAYLOAD_HEADER_LEN || offset + payload_len > body.len() {
                anyhow::bail!("IKEv2 payload length {} outside the message", payload_len);
            }
            offset += payload_len;

            if matches!(next_payload, PayloadType::Encrypted | PayloadType::EncryptedFragment) {
                if offset != body.len() {
                    anyhow::bail!("The SK payload must be the last payload in the message");
                }
                return Ok(());
            }
            next_payload = header[0].into();
        }

        if offset != body.len() {
            anyhow::bail!("{} bytes after the last IKEv2 payload", body.len() - offset);
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

    pub fn is_response(&self) -> bool {
        self.flags.contains(Flags::RESPONSE)
    }

    pub fn notifies(&self) -> impl Iterator<Item = &NotifyPayload> {
        self.payloads.iter().filter_map(|p| match p {
            Payload::Notify(n) => Some(n),
            _ => None,
        })
    }

    pub fn find_notify(&self, notify_type: NotifyType) -> Option<&NotifyPayload> {
        self.notifies().find(|n| n.notify_type == notify_type)
    }

    /// The error notify carried by this message, if any.
    pub fn error_notify(&self) -> Option<NotifyType> {
        self.payloads.iter().find_map(|p| match p {
            Payload::Notify(n) if n.notify_type.is_error() => Some(n.notify_type),
            _ => None,
        })
    }
}

impl CheckInformational for Ikev2Message {
    /// Only INFORMATIONAL exchanges abort here. Error notifies in an
    /// IKE_SA_INIT or IKE_AUTH response are left to the exchange state machine,
    /// which has the context to act on the recoverable ones — COOKIE,
    /// INVALID_KE_PAYLOAD — by retrying rather than failing.
    fn check_informational(&self) -> anyhow::Result<()> {
        if self.exchange_type != ExchangeType::Informational {
            return Ok(());
        }

        match self.error_notify() {
            Some(notify_type) => anyhow::bail!("IKEv2 notify error {:?}", notify_type),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A header whose first payload is `next_payload`; the length is filled in by `with_length`.
    fn header(next_payload: u8) -> Vec<u8> {
        let mut data = vec![0x11; 16];
        data.extend([next_payload, IKEV2_VERSION, 34, 0x08, 0, 0, 0, 0, 0, 0, 0, 0]);
        data
    }

    fn with_length(mut data: Vec<u8>) -> Vec<u8> {
        let length = (data.len() as u32).to_be_bytes();
        data[24..28].copy_from_slice(&length);
        data
    }

    fn validate(data: Vec<u8>) -> anyhow::Result<()> {
        Ikev2Message::validate(&with_length(data))
    }

    #[test]
    fn test_validate_header_only() {
        validate(header(0)).unwrap();
    }

    #[test]
    fn test_validate_payload_chain() {
        // nonce (40) followed by a vendor ID (43), both with 2-byte bodies
        let mut data = header(40);
        data.extend([43, 0, 0, 6, 1, 2, 0, 0, 0, 6, 3, 4]);
        validate(data).unwrap();
    }

    #[test]
    fn test_validate_sk_payload() {
        // the SK Next Payload names the first inner payload (IDi, 35), not the end of the chain
        let mut data = header(46);
        data.extend([35, 0, 0, 20]);
        data.extend([0xaa; 16]);
        validate(data.clone()).unwrap();

        // a notify (41) in front of the SK payload
        let mut data = header(41);
        data.extend([46, 0, 0, 8, 0, 0, 0, 0, 35, 0, 0, 8, 0xaa, 0xaa, 0xaa, 0xaa]);
        validate(data).unwrap();

        // SKF (53)
        let mut data = header(53);
        data.extend([35, 0, 0, 8, 0, 1, 0, 1]);
        validate(data).unwrap();
    }

    #[test]
    fn test_validate_rejects_short_data() {
        let data = with_length(header(0));
        for len in [0, 1, 4, 27] {
            assert!(Ikev2Message::validate(&data[..len]).is_err(), "{len}");
        }
    }

    #[test]
    fn test_validate_rejects_wrong_version() {
        let mut data = header(0);
        data[17] = 0x10;
        assert!(validate(data).is_err());
    }

    #[test]
    fn test_validate_rejects_length_mismatch() {
        let data = with_length(header(0));

        let mut longer = data.clone();
        longer.push(0);
        assert!(Ikev2Message::validate(&longer).is_err());

        // a length below the header size used to panic in the decoder
        for length in [0u32, 20, 27, 29, u32::MAX] {
            let mut data = data.clone();
            data[24..28].copy_from_slice(&length.to_be_bytes());
            assert!(Ikev2Message::validate(&data).is_err(), "{length}");
        }
    }

    #[test]
    fn test_validate_rejects_bad_payload_chain() {
        // payload length below its own header
        let mut data = header(40);
        data.extend([0, 0, 0, 3]);
        assert!(validate(data).is_err());

        // payload runs past the end of the message
        let mut data = header(40);
        data.extend([0, 0, 0, 8, 1, 2]);
        assert!(validate(data).is_err());

        // chain announces a further payload that is not there
        let mut data = header(40);
        data.extend([43, 0, 0, 6, 1, 2]);
        assert!(validate(data).is_err());

        // bytes after the last payload
        let mut data = header(40);
        data.extend([0, 0, 0, 6, 1, 2, 0xff]);
        assert!(validate(data).is_err());

        // a payload after the SK payload
        let mut data = header(46);
        data.extend([35, 0, 0, 8, 0xaa, 0xaa, 0xaa, 0xaa, 0, 0, 0, 4]);
        assert!(validate(data).is_err());

        // payloads announced, but no body
        assert!(validate(header(46)).is_err());
    }
}
