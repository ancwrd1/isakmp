//! IKEv2 message framing: the fixed header and the SK (Encrypted) payload.

use std::{io::Cursor, sync::Arc};

use anyhow::Context;
use byteorder::{BigEndian, ReadBytesExt};
use bytes::{BufMut, Bytes, BytesMut};
use tracing::trace;

use crate::{
    crypto::Crypto,
    ikev2::{
        message::Ikev2Message,
        model::{ExchangeType, Flags, IntegrityAlgorithm, PayloadType},
        payload::Payload,
        session::Ikev2Session,
    },
    message::{IKEV2_VERSION, ISAKMP_HEADER_LEN, IsakmpMessageCodec},
};

#[derive(Debug, Clone, Default)]
pub struct DirectionalKeys {
    pub sk_e: Bytes,
    pub sk_a: Bytes,
}

pub struct Ikev2Crypt {
    crypto: Arc<Crypto>,
    checksum_len: usize,
    outbound: DirectionalKeys,
    inbound: DirectionalKeys,
}

impl Ikev2Crypt {
    pub fn new(
        crypto: impl Into<Arc<Crypto>>,
        integrity: IntegrityAlgorithm,
        outbound: DirectionalKeys,
        inbound: DirectionalKeys,
    ) -> anyhow::Result<Self> {
        let crypto = crypto.into();
        let checksum_len = integrity.checksum_len()?;

        if crypto.is_aead() {
            if integrity != IntegrityAlgorithm::None {
                anyhow::bail!("AEAD cipher must be negotiated with INTEG_NONE, got {integrity:?}");
            }
        } else {
            if checksum_len != crypto.integrity_len() {
                anyhow::bail!(
                    "Integrity transform {integrity:?} wants a {checksum_len}-byte checksum, \
                     {:?} produces {}",
                    crypto.digest_type(),
                    crypto.integrity_len()
                );
            }
            if checksum_len == 0 {
                anyhow::bail!("A non-AEAD cipher requires an integrity transform");
            }
        }

        let sk_e_len = crypto.key_material_len();
        for (name, keys) in [("outbound", &outbound), ("inbound", &inbound)] {
            if keys.sk_e.len() != sk_e_len {
                anyhow::bail!("{name} SK_e is {} bytes, expected {}", keys.sk_e.len(), sk_e_len);
            }
            if keys.sk_a.len() != crypto.hash_len() * usize::from(checksum_len != 0) {
                anyhow::bail!(
                    "{name} SK_a is {} bytes, expected {}",
                    keys.sk_a.len(),
                    crypto.hash_len() * usize::from(checksum_len != 0)
                );
            }
        }

        Ok(Self {
            crypto,
            checksum_len,
            outbound,
            inbound,
        })
    }

    pub fn crypto(&self) -> &Crypto {
        &self.crypto
    }

    /// Octets the SK payload adds around the ciphertext: IV plus ICV.
    fn overhead(&self) -> usize {
        self.crypto.iv_len() + self.icv_len()
    }

    fn icv_len(&self) -> usize {
        if self.crypto.is_aead() {
            self.crypto.icv_len()
        } else {
            self.checksum_len
        }
    }
}

// Pads `plaintext` to the cipher's block size, appending the Pad Length octet
// (RFC 7296 §3.14). Padding content is unspecified; zeroes are conventional.
fn pad(plaintext: &[u8], block_size: usize) -> Bytes {
    let pad_len = (block_size - ((plaintext.len() + 1) % block_size)) % block_size;

    let mut buf = BytesMut::with_capacity(plaintext.len() + pad_len + 1);
    buf.put_slice(plaintext);
    buf.put_bytes(0, pad_len);
    buf.put_u8(pad_len as u8);
    buf.freeze()
}

fn unpad(plaintext: &[u8]) -> anyhow::Result<Bytes> {
    let (&pad_len, rest) = plaintext.split_last().context("Empty SK plaintext")?;

    rest.len()
        .checked_sub(pad_len as usize)
        .map(|len| Bytes::copy_from_slice(&rest[..len]))
        .context("SK padding longer than the plaintext")
}

fn random_bytes(len: usize) -> Bytes {
    let mut buf = vec![0u8; len];
    rand::fill(&mut buf[..]);
    buf.into()
}

enum CryptSource {
    Fixed(Option<Arc<Ikev2Crypt>>),
    Session(Ikev2Session),
}

impl CryptSource {
    fn crypt(&self) -> Option<Arc<Ikev2Crypt>> {
        match self {
            Self::Fixed(crypt) => crypt.clone(),
            Self::Session(session) => session.crypt(),
        }
    }
}

pub struct Ikev2Codec {
    source: CryptSource,
}

impl Default for Ikev2Codec {
    fn default() -> Self {
        Self::new()
    }
}

impl Ikev2Codec {
    /// A codec for the unprotected IKE_SA_INIT exchange.
    pub fn new() -> Self {
        Self {
            source: CryptSource::Fixed(None),
        }
    }

    pub fn with_crypt(crypt: Ikev2Crypt) -> Self {
        Self {
            source: CryptSource::Fixed(Some(Arc::new(crypt))),
        }
    }

    /// A codec that follows a session
    pub fn for_session(session: Ikev2Session) -> Self {
        Self {
            source: CryptSource::Session(session),
        }
    }

    pub fn set_crypt(&mut self, crypt: Ikev2Crypt) {
        self.source = CryptSource::Fixed(Some(Arc::new(crypt)));
    }

    fn record_sa_init(&self, message: &Ikev2Message, data: &[u8]) {
        if message.exchange_type == ExchangeType::IkeSaInit
            && let CryptSource::Session(session) = &self.source
        {
            session.set_sa_init_octets(message.is_response(), Bytes::copy_from_slice(data));
        }
    }

    fn header(message: &Ikev2Message, next_payload: PayloadType, length: usize) -> Bytes {
        let mut buf = BytesMut::with_capacity(ISAKMP_HEADER_LEN);
        buf.put_u64(message.initiator_spi);
        buf.put_u64(message.responder_spi);
        buf.put_u8(next_payload.into());
        buf.put_u8(IKEV2_VERSION);
        buf.put_u8(message.exchange_type.into());
        buf.put_u8(message.flags.bits());
        buf.put_u32(message.message_id);
        buf.put_u32(length as u32);
        buf.freeze()
    }

    fn encode_encrypted(&self, message: &Ikev2Message, crypt: &Ikev2Crypt) -> anyhow::Result<Bytes> {
        let inner = Payload::write_all(&message.payloads);
        let plaintext = pad(&inner, crypt.crypto.block_size());

        let sk_len = 4 + crypt.overhead() + plaintext.len();
        let header = Self::header(message, PayloadType::Encrypted, ISAKMP_HEADER_LEN + sk_len);

        let mut buf = BytesMut::with_capacity(ISAKMP_HEADER_LEN + sk_len);
        buf.put_slice(&header);
        buf.put_u8(message.next_payload(0).into());
        buf.put_u8(0);
        buf.put_u16(sk_len as u16);

        let iv = random_bytes(crypt.crypto.iv_len());
        buf.put_slice(&iv);

        if crypt.crypto.is_aead() {
            // RFC 5282 §5.1: everything ahead of the IV is the associated data.
            let aad = buf[..ISAKMP_HEADER_LEN + 4].to_vec();
            let salt = &crypt.outbound.sk_e[crypt.crypto.key_len()..];

            let mut nonce = BytesMut::with_capacity(crypt.crypto.salt_len() + iv.len());
            nonce.put_slice(salt);
            nonce.put_slice(&iv);

            let sealed =
                crypt
                    .crypto
                    .encrypt_aead(&crypt.outbound.sk_e[..crypt.crypto.key_len()], &plaintext, &nonce, &aad)?;
            buf.put_slice(&sealed);
        } else {
            let ciphertext = crypt.crypto.encrypt(&crypt.outbound.sk_e, &plaintext, &iv)?;
            buf.put_slice(&ciphertext);

            let checksum = crypt.crypto.integrity(&crypt.outbound.sk_a, [&buf[..]])?;
            buf.put_slice(&checksum);
        }

        Ok(buf.freeze())
    }

    /// Verifies and unwraps an SK payload, returning the inner payload chain.
    fn decode_encrypted(
        crypt: &Ikev2Crypt,
        data: &[u8],
        sk_header_offset: usize,
        sk_end: usize,
        first_payload: PayloadType,
    ) -> anyhow::Result<Vec<Payload>> {
        let sk_body = &data[sk_header_offset + 4..sk_end];

        let iv_len = crypt.crypto.iv_len();
        let icv_len = crypt.icv_len();

        let ciphertext_len = sk_body
            .len()
            .checked_sub(iv_len + icv_len)
            .context("SK payload shorter than its IV and ICV")?;

        let iv = &sk_body[..iv_len];
        let ciphertext = &sk_body[iv_len..iv_len + ciphertext_len];

        let plaintext = if crypt.crypto.is_aead() {
            let aad = &data[..sk_header_offset + 4];
            let salt = &crypt.inbound.sk_e[crypt.crypto.key_len()..];

            let mut nonce = BytesMut::with_capacity(crypt.crypto.salt_len() + iv_len);
            nonce.put_slice(salt);
            nonce.put_slice(iv);

            // the ICV is the AEAD tag, so hand it to the cipher with the ciphertext
            crypt.crypto.decrypt_aead(
                &crypt.inbound.sk_e[..crypt.crypto.key_len()],
                &sk_body[iv_len..],
                &nonce,
                aad,
            )?
        } else {
            let checksum_at = sk_end - icv_len;
            let expected = crypt.crypto.integrity(&crypt.inbound.sk_a, [&data[..checksum_at]])?;

            if !openssl::memcmp::eq(&expected, &data[checksum_at..sk_end]) {
                anyhow::bail!("SK payload integrity check failed");
            }

            crypt.crypto.decrypt(&crypt.inbound.sk_e, ciphertext, iv)?
        };

        Payload::parse_all(first_payload, &mut Cursor::new(unpad(&plaintext)?))
    }
}

impl IsakmpMessageCodec<Ikev2Message> for Ikev2Codec {
    fn encode(&mut self, message: &Ikev2Message) -> anyhow::Result<Bytes> {
        // IKE_SA_INIT is the only exchange that travels unprotected
        let encoded = match self.source.crypt() {
            Some(crypt) if message.exchange_type != ExchangeType::IkeSaInit => {
                self.encode_encrypted(message, &crypt)?
            }
            _ => {
                let payloads = Payload::write_all(&message.payloads);
                let header = Self::header(message, message.next_payload(0), ISAKMP_HEADER_LEN + payloads.len());

                let mut buf = BytesMut::with_capacity(header.len() + payloads.len());
                buf.put_slice(&header);
                buf.put_slice(&payloads);
                buf.freeze()
            }
        };

        self.record_sa_init(message, &encoded);

        Ok(encoded)
    }

    fn decode(&mut self, data: &[u8]) -> anyhow::Result<Option<Ikev2Message>> {
        if data.len() < ISAKMP_HEADER_LEN {
            anyhow::bail!("IKEv2 message shorter than its header");
        }

        let mut reader = Cursor::new(data);

        let initiator_spi = reader.read_u64::<BigEndian>()?;
        let responder_spi = reader.read_u64::<BigEndian>()?;
        let next_payload: PayloadType = reader.read_u8()?.into();
        let version = reader.read_u8()?;
        let exchange_type: ExchangeType = reader.read_u8()?.into();
        let flags = Flags::from_bits_retain(reader.read_u8()?);
        let message_id = reader.read_u32::<BigEndian>()?;
        let length = reader.read_u32::<BigEndian>()? as usize;

        if version >> 4 != IKEV2_VERSION >> 4 {
            anyhow::bail!("Not an IKEv2 message: version {:#04x}", version);
        }
        if length > data.len() {
            anyhow::bail!("IKEv2 message claims {} bytes, got {}", length, data.len());
        }

        trace!(
            "Decoding IKEv2 message: exchange={:?}, flags={:?}, id={}, len={}",
            exchange_type, flags, message_id, length
        );

        let data = &data[..length];

        let payloads = if next_payload == PayloadType::Encrypted {
            // the SK payload is the only one at the top level, so its generic
            // header sits immediately after the message header
            let mut sk_header = Cursor::new(&data[ISAKMP_HEADER_LEN..]);
            let first_payload: PayloadType = sk_header.read_u8()?.into();
            sk_header.read_u8()?;
            let sk_len = sk_header.read_u16::<BigEndian>()? as usize;

            let sk_end = ISAKMP_HEADER_LEN
                .checked_add(sk_len)
                .filter(|end| *end <= data.len() && sk_len >= 4)
                .context("SK payload length outside the message")?;

            if sk_end != data.len() {
                anyhow::bail!("The SK payload must be the last payload in the message");
            }

            let crypt = self
                .source
                .crypt()
                .context("Received an SK payload before the SA is keyed")?;

            Self::decode_encrypted(&crypt, data, ISAKMP_HEADER_LEN, sk_end, first_payload)?
        } else {
            let mut cursor = Cursor::new(&data[ISAKMP_HEADER_LEN..]);
            Payload::parse_all(next_payload, &mut cursor)?
        };

        let message = Ikev2Message {
            initiator_spi,
            responder_spi,
            version,
            exchange_type,
            flags,
            message_id,
            payloads,
        };

        self.record_sa_init(&message, data);

        Ok(Some(message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::{CipherType, DigestType, GroupType, IcvLength},
        ikev2::{
            model::{
                AuthMethod, DhGroup, EncryptionAlgorithm, IdentificationType, NotifyType, ProtocolId,
                PseudoRandomFunction,
            },
            payload::{
                AuthenticationPayload, IdentificationPayload, KeyExchangePayload, NotifyPayload, Proposal,
                SecurityAssociationPayload, TrafficSelector, TrafficSelectorPayload, Transform,
            },
        },
        payload::BasicPayload,
    };

    fn keys(sk_e: usize, sk_a: usize) -> (DirectionalKeys, DirectionalKeys) {
        (
            DirectionalKeys {
                sk_e: Bytes::from(vec![0x11; sk_e]),
                sk_a: Bytes::from(vec![0x22; sk_a]),
            },
            DirectionalKeys {
                sk_e: Bytes::from(vec![0x33; sk_e]),
                sk_a: Bytes::from(vec![0x44; sk_a]),
            },
        )
    }

    /// AES-CBC with a separate HMAC-SHA2-256-128 integrity transform.
    fn cbc_crypt(swap: bool) -> Ikev2Crypt {
        let crypto = Crypto::with_parameters(DigestType::Sha256, CipherType::Aes256Cbc, GroupType::Oakley2)
            .unwrap()
            .with_prf(DigestType::Sha384);
        let (out, inb) = keys(32, 32);
        let (out, inb) = if swap { (inb, out) } else { (out, inb) };

        Ikev2Crypt::new(crypto, IntegrityAlgorithm::HmacSha256_128, out, inb).unwrap()
    }

    /// AES-GCM-16, where the cipher supplies the ICV and INTEG is NONE.
    fn gcm_crypt(swap: bool) -> Ikev2Crypt {
        let crypto = Crypto::with_parameters(
            DigestType::Sha256,
            CipherType::Aes256Gcm(IcvLength::Sixteen),
            GroupType::Oakley2,
        )
        .unwrap();
        // SK_e carries the 4-octet salt after the key
        let (out, inb) = keys(36, 0);
        let (out, inb) = if swap { (inb, out) } else { (out, inb) };

        Ikev2Crypt::new(crypto, IntegrityAlgorithm::None, out, inb).unwrap()
    }

    fn sa_init(payloads: Vec<Payload>) -> Ikev2Message {
        Ikev2Message {
            initiator_spi: 0x0011223344556677,
            responder_spi: 0,
            version: IKEV2_VERSION,
            exchange_type: ExchangeType::IkeSaInit,
            flags: Flags::INITIATOR,
            message_id: 0,
            payloads,
        }
    }

    fn ike_auth(payloads: Vec<Payload>) -> Ikev2Message {
        Ikev2Message {
            initiator_spi: 0x0011223344556677,
            responder_spi: 0x8899aabbccddeeff,
            version: IKEV2_VERSION,
            exchange_type: ExchangeType::IkeAuth,
            flags: Flags::INITIATOR,
            message_id: 1,
            payloads,
        }
    }

    fn sa_init_payloads() -> Vec<Payload> {
        vec![
            Payload::SecurityAssociation(SecurityAssociationPayload {
                proposals: vec![Proposal {
                    proposal_num: 1,
                    protocol_id: ProtocolId::Ike,
                    spi: Bytes::new(),
                    transforms: vec![
                        Transform::encryption(EncryptionAlgorithm::AesCbc, Some(32)),
                        Transform::prf(PseudoRandomFunction::HmacSha256),
                        Transform::integrity(IntegrityAlgorithm::HmacSha256_128),
                        Transform::dh_group(DhGroup::Ecp256),
                    ],
                }],
            }),
            Payload::KeyExchange(KeyExchangePayload {
                dh_group: DhGroup::Ecp256,
                data: Bytes::from(vec![0x42; 64]),
            }),
            Payload::Nonce(BasicPayload::new(Bytes::from(vec![0xaa; 32]))),
            Payload::Notify(NotifyPayload::new(
                NotifyType::NatDetectionSourceIp,
                Bytes::from(vec![0x11; 20]),
            )),
        ]
    }

    fn ike_auth_payloads() -> Vec<Payload> {
        vec![
            Payload::IdentificationInitiator(IdentificationPayload {
                id_type: IdentificationType::Rfc822Address,
                data: Bytes::from_static(b"user@example.com"),
            }),
            Payload::Authentication(AuthenticationPayload {
                auth_method: AuthMethod::DigitalSignature,
                data: Bytes::from(vec![0x5a; 260]),
            }),
            Payload::TrafficSelectorInitiator(TrafficSelectorPayload {
                selectors: vec![TrafficSelector::any_ipv4()],
            }),
        ]
    }

    #[test]
    fn test_unencrypted_round_trip() {
        let message = sa_init(sa_init_payloads());

        let mut codec = Ikev2Codec::new();
        let encoded = codec.encode(&message).unwrap();
        let decoded = codec.decode(&encoded).unwrap().unwrap();

        assert_eq!(decoded.initiator_spi, message.initiator_spi);
        assert_eq!(decoded.responder_spi, 0);
        assert_eq!(decoded.exchange_type, ExchangeType::IkeSaInit);
        assert_eq!(decoded.flags, Flags::INITIATOR);
        assert_eq!(decoded.message_id, 0);
        assert_eq!(decoded.payloads, message.payloads);

        // header fields at their RFC 7296 §3.1 offsets
        assert_eq!(encoded[16], u8::from(PayloadType::SecurityAssociation));
        assert_eq!(encoded[17], IKEV2_VERSION);
        assert_eq!(encoded[18], u8::from(ExchangeType::IkeSaInit));
        assert_eq!(encoded[19], Flags::INITIATOR.bits());
        assert_eq!(
            u32::from_be_bytes(encoded[28 - 4..28].try_into().unwrap()),
            encoded.len() as u32
        );
    }

    #[test]
    fn test_encrypted_round_trip() {
        for (name, mut initiator, mut responder) in [
            (
                "aes-cbc + hmac-sha2-256-128",
                Ikev2Codec::with_crypt(cbc_crypt(false)),
                Ikev2Codec::with_crypt(cbc_crypt(true)),
            ),
            (
                "aes-gcm-16",
                Ikev2Codec::with_crypt(gcm_crypt(false)),
                Ikev2Codec::with_crypt(gcm_crypt(true)),
            ),
        ] {
            let message = ike_auth(ike_auth_payloads());
            let encoded = initiator.encode(&message).unwrap();

            // a single SK payload wraps everything
            assert_eq!(encoded[16], u8::from(PayloadType::Encrypted), "{name}");
            assert_eq!(encoded[28], u8::from(PayloadType::IdentificationInitiator), "{name}");
            assert_eq!(
                u32::from_be_bytes(encoded[24..28].try_into().unwrap()),
                encoded.len() as u32,
                "{name}"
            );

            // the plaintext must not be visible
            assert!(
                !encoded.windows(16).any(|w| w == b"user@example.com"),
                "{name}: identity leaked in the clear"
            );

            let decoded = responder.decode(&encoded).unwrap().unwrap();
            assert_eq!(decoded.payloads, message.payloads, "{name}");
            assert_eq!(decoded.exchange_type, ExchangeType::IkeAuth, "{name}");
            assert_eq!(decoded.message_id, 1, "{name}");
        }
    }

    /// Encoding is not deterministic: each message carries a fresh IV.
    #[test]
    fn test_each_message_uses_a_fresh_iv() {
        let mut codec = Ikev2Codec::with_crypt(cbc_crypt(false));
        let message = ike_auth(ike_auth_payloads());

        let first = codec.encode(&message).unwrap();
        let second = codec.encode(&message).unwrap();

        assert_eq!(first.len(), second.len());
        assert_ne!(first, second);
        assert_eq!(first[..28], second[..28], "only the SK body differs");
    }

    #[test]
    fn test_ike_sa_init_is_never_encrypted() {
        // even once the SA is keyed, a retried IKE_SA_INIT travels in the clear
        let mut codec = Ikev2Codec::with_crypt(cbc_crypt(false));
        let encoded = codec.encode(&sa_init(sa_init_payloads())).unwrap();

        assert_eq!(encoded[16], u8::from(PayloadType::SecurityAssociation));
    }

    #[test]
    fn test_sk_payload_without_keys_is_rejected() {
        let mut initiator = Ikev2Codec::with_crypt(cbc_crypt(false));
        let encoded = initiator.encode(&ike_auth(ike_auth_payloads())).unwrap();

        let err = Ikev2Codec::new().decode(&encoded).unwrap_err();
        assert!(err.to_string().contains("before the SA is keyed"), "{err}");
    }

    #[test]
    fn test_tampering_is_detected() {
        for (name, mut initiator, mut responder) in [
            (
                "aes-cbc",
                Ikev2Codec::with_crypt(cbc_crypt(false)),
                Ikev2Codec::with_crypt(cbc_crypt(true)),
            ),
            (
                "aes-gcm",
                Ikev2Codec::with_crypt(gcm_crypt(false)),
                Ikev2Codec::with_crypt(gcm_crypt(true)),
            ),
        ] {
            let encoded = initiator.encode(&ike_auth(ike_auth_payloads())).unwrap();

            // ciphertext, ICV, the SK header and the message header are all covered
            for offset in [0, 19, 28, 40, encoded.len() - 1] {
                let mut tampered = encoded.to_vec();
                tampered[offset] ^= 1;
                assert!(
                    responder.decode(&tampered).is_err(),
                    "{name}: tampering at offset {offset} went undetected"
                );
            }

            assert!(
                responder.decode(&encoded).is_ok(),
                "{name}: untampered message must verify"
            );
        }
    }

    /// Keys are directional: SK_ei/SK_ai protect one way only.
    #[test]
    fn test_wrong_direction_keys_fail() {
        let mut initiator = Ikev2Codec::with_crypt(cbc_crypt(false));
        let encoded = initiator.encode(&ike_auth(ike_auth_payloads())).unwrap();

        // decoding with the same directional assignment uses SK_er against a
        // message written with SK_ei
        assert!(Ikev2Codec::with_crypt(cbc_crypt(false)).decode(&encoded).is_err());
        assert!(Ikev2Codec::with_crypt(cbc_crypt(true)).decode(&encoded).is_ok());
    }

    #[test]
    fn test_ciphertext_is_block_aligned() {
        let mut codec = Ikev2Codec::with_crypt(cbc_crypt(false));

        for extra in 0..20 {
            let message = ike_auth(vec![Payload::Nonce(BasicPayload::new(Bytes::from(vec![0x5a; extra])))]);
            let encoded = codec.encode(&message).unwrap();

            // total = header + SK header + IV + ciphertext + ICV
            let ciphertext_len = encoded.len() - 28 - 4 - 16 - 16;
            assert_eq!(ciphertext_len % 16, 0, "extra={extra}");

            assert_eq!(
                Ikev2Codec::with_crypt(cbc_crypt(true))
                    .decode(&encoded)
                    .unwrap()
                    .unwrap()
                    .payloads,
                message.payloads
            );
        }
    }

    #[test]
    fn test_non_ikev2_version_is_rejected() {
        let mut codec = Ikev2Codec::new();
        let mut encoded = codec.encode(&sa_init(sa_init_payloads())).unwrap().to_vec();
        encoded[17] = 0x10; // IKEv1

        let err = codec.decode(&encoded).unwrap_err();
        assert!(err.to_string().contains("Not an IKEv2 message"), "{err}");
    }

    #[test]
    fn test_truncated_and_overlong_messages_are_rejected() {
        let mut codec = Ikev2Codec::new();
        let encoded = codec.encode(&sa_init(sa_init_payloads())).unwrap();

        assert!(codec.decode(&encoded[..20]).is_err());

        let mut overlong = encoded.to_vec();
        overlong[27] = overlong[27].wrapping_add(16);
        assert!(codec.decode(&overlong).is_err());
    }

    /// An AEAD cipher may not be paired with an integrity transform, and a
    /// non-AEAD cipher requires one.
    #[test]
    fn test_transform_combinations_are_validated() {
        let aead = || {
            Crypto::with_parameters(
                DigestType::Sha256,
                CipherType::Aes256Gcm(IcvLength::Sixteen),
                GroupType::Oakley2,
            )
            .unwrap()
        };
        let cbc = || Crypto::with_parameters(DigestType::Sha256, CipherType::Aes256Cbc, GroupType::Oakley2).unwrap();

        let (out, inb) = keys(36, 0);
        assert!(Ikev2Crypt::new(aead(), IntegrityAlgorithm::HmacSha256_128, out.clone(), inb.clone()).is_err());
        assert!(Ikev2Crypt::new(aead(), IntegrityAlgorithm::None, out, inb).is_ok());

        let (out, inb) = keys(32, 32);
        assert!(Ikev2Crypt::new(cbc(), IntegrityAlgorithm::None, out.clone(), inb.clone()).is_err());
        // HMAC-SHA1-160 truncates to 20 bytes, which `Crypto::integrity` cannot produce
        assert!(Ikev2Crypt::new(cbc(), IntegrityAlgorithm::HmacSha1_160, out.clone(), inb.clone()).is_err());
        assert!(Ikev2Crypt::new(cbc(), IntegrityAlgorithm::HmacSha256_128, out, inb).is_ok());

        // wrong key sizes are caught up front
        let (out, inb) = keys(16, 32);
        assert!(Ikev2Crypt::new(cbc(), IntegrityAlgorithm::HmacSha256_128, out, inb).is_err());
    }

    #[test]
    fn test_padding_round_trip() {
        for len in 0..40usize {
            let plaintext = vec![0x5a; len];
            let padded = pad(&plaintext, 16);

            assert_eq!(padded.len() % 16, 0, "len={len}");
            assert_eq!(unpad(&padded).unwrap(), Bytes::from(plaintext), "len={len}");
        }

        assert!(unpad(&[]).is_err());
        assert!(unpad(&[9]).is_err(), "pad length past the start of the buffer");
    }

    #[test]
    fn test_set_crypt_switches_from_plaintext_to_sk() {
        let mut codec = Ikev2Codec::new();
        let message = ike_auth(ike_auth_payloads());

        assert_eq!(
            codec.encode(&message).unwrap()[16],
            u8::from(PayloadType::IdentificationInitiator)
        );

        codec.set_crypt(cbc_crypt(false));
        assert_eq!(codec.encode(&message).unwrap()[16], u8::from(PayloadType::Encrypted));
    }
}
