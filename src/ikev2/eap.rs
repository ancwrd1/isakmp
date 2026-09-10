//! EAP framing carried inside IKE_AUTH (RFC 3748 §4).
//!
//! Only the envelope lives here: the code, which tells the IKE_AUTH loop
//! whether to keep going, the identifier, which every response must echo, and
//! the method type. What a method's data *means* — EAP-GTC's prompt, the OTP
//! flow behind it — is phase 6.

use anyhow::Context;
use byteorder::{BigEndian, ReadBytesExt};
use bytes::{BufMut, Bytes, BytesMut};

use crate::ikev2::model::{EapCode, EapType};

/// Code, identifier and length; Success and Failure are exactly this long.
const EAP_HEADER_LEN: usize = 4;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EapMessage {
    pub code: EapCode,
    pub identifier: u8,
    /// Absent on Success and Failure, which carry nothing after the header.
    pub eap_type: Option<EapType>,
    pub data: Bytes,
}

impl EapMessage {
    /// A response to `request`, echoing its identifier and method type as
    /// RFC 3748 §4.1 requires.
    pub fn response(request: &EapMessage, data: Bytes) -> Self {
        Self {
            code: EapCode::Response,
            identifier: request.identifier,
            eap_type: request.eap_type,
            data,
        }
    }

    /// Whether this message ends the EAP conversation.
    pub fn is_final(&self) -> bool {
        matches!(self.code, EapCode::Success | EapCode::Failure)
    }

    pub fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(self.len());
        buf.put_u8(self.code.into());
        buf.put_u8(self.identifier);
        buf.put_u16(self.len() as u16);
        if let Some(eap_type) = self.eap_type {
            buf.put_u8(eap_type.into());
            buf.put_slice(&self.data);
        }
        buf.freeze()
    }

    pub fn len(&self) -> usize {
        match self.eap_type {
            Some(_) => EAP_HEADER_LEN + 1 + self.data.len(),
            None => EAP_HEADER_LEN,
        }
    }

    pub fn is_empty(&self) -> bool {
        false
    }

    pub fn parse(data: &[u8]) -> anyhow::Result<Self> {
        let mut reader = std::io::Cursor::new(data);

        let code: EapCode = reader.read_u8()?.into();
        let identifier = reader.read_u8()?;
        let length = reader.read_u16::<BigEndian>()? as usize;

        anyhow::ensure!(
            (EAP_HEADER_LEN..=data.len()).contains(&length),
            "EAP message claims {length} bytes, got {}",
            data.len()
        );

        // Success and Failure stop at the header; anything else names a method
        let (eap_type, body) = match code {
            EapCode::Success | EapCode::Failure => (None, Bytes::new()),
            _ => {
                let eap_type = reader
                    .read_u8()
                    .ok()
                    .context("EAP request or response without a method type")?;

                (
                    Some(EapType::from(eap_type)),
                    Bytes::copy_from_slice(&data[EAP_HEADER_LEN + 1..length]),
                )
            }
        };

        Ok(Self {
            code,
            identifier,
            eap_type,
            data: body,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(data: &'static [u8]) -> EapMessage {
        EapMessage {
            code: EapCode::Request,
            identifier: 80,
            eap_type: Some(EapType::GenericTokenCard),
            data: Bytes::from_static(data),
        }
    }

    #[test]
    fn test_roundtrip() {
        for message in [
            request(b"Enter your password"),
            request(b""),
            EapMessage {
                code: EapCode::Success,
                identifier: 80,
                eap_type: None,
                data: Bytes::new(),
            },
            EapMessage {
                code: EapCode::Other(9),
                identifier: 1,
                eap_type: Some(EapType::Other(200)),
                data: Bytes::from_static(&[0xff; 64]),
            },
        ] {
            let encoded = message.to_bytes();
            assert_eq!(encoded.len(), message.len());
            assert_eq!(u16::from_be_bytes([encoded[2], encoded[3]]) as usize, message.len());
            assert_eq!(EapMessage::parse(&encoded).unwrap(), message);
        }
    }

    #[test]
    fn test_success_and_failure_are_header_only() {
        let success = EapMessage {
            code: EapCode::Success,
            identifier: 7,
            eap_type: None,
            data: Bytes::new(),
        };

        assert_eq!(success.to_bytes(), Bytes::from_static(&[3, 7, 0, 4]));
        assert!(success.is_final());
        assert!(!request(b"prompt").is_final());
    }

    /// RFC 3748 §4.1: a response echoes the request's identifier and type.
    #[test]
    fn test_response_echoes_the_request() {
        let response = EapMessage::response(&request(b"Enter your password"), Bytes::from_static(b"secret"));

        assert_eq!(response.code, EapCode::Response);
        assert_eq!(response.identifier, 80);
        assert_eq!(response.eap_type, Some(EapType::GenericTokenCard));
        assert_eq!(response.data, Bytes::from_static(b"secret"));
    }

    #[test]
    fn test_parse_rejects_bad_lengths() {
        // claims more than it carries
        assert!(EapMessage::parse(&[1, 80, 0, 32, 6]).is_err());
        // below the header size
        assert!(EapMessage::parse(&[1, 80, 0, 2, 6]).is_err());
        // truncated before the length field
        assert!(EapMessage::parse(&[1, 80]).is_err());
        // a request with no method type
        assert!(EapMessage::parse(&[1, 80, 0, 4]).is_err());
    }

    /// A message longer than its declared length keeps only what it declares:
    /// the EAP payload may be padded by the SK framing around it.
    #[test]
    fn test_parse_stops_at_the_declared_length() {
        let mut data = request(b"prompt").to_bytes().to_vec();
        data.extend_from_slice(&[0xaa; 8]);

        assert_eq!(EapMessage::parse(&data).unwrap(), request(b"prompt"));
    }
}
