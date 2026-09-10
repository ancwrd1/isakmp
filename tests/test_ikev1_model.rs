//! Guards the IKEv1 registries, the shared attribute TLV and the payload
//! chain writer against regressions from the ikev1/ikev2 model split.

use isakmp::{
    ikev1::{codec::Ikev1Codec, model::*, payload::AttributesPayload, session::Ikev1Session},
    message::IsakmpMessageCodec,
    model::{DataAttribute, Identity},
    session::SessionType,
};

macro_rules! check {
    ($name:ident, $repr:ty) => {{
        for v in <$repr>::MIN..=<$repr>::MAX {
            let e: $name = v.into();
            assert_eq!(<$repr>::from(e), v, "{} round trip at {}", stringify!($name), v);
        }
    }};
}

#[test]
fn registries_round_trip() {
    check!(ProtocolId, u8);
    check!(TransformId, u8);
    check!(IdentityType, u8);
    check!(PayloadType, u8);
    check!(ExchangeType, u8);
    check!(CertificateType, u8);
    check!(AttributesPayloadType, u8);
    check!(IkeEncryptionAlgorithm, u16);
    check!(IkeGroupDescription, u16);
    check!(IkeHashAlgorithm, u16);
    check!(LifeType, u16);
    check!(IkeAuthMethod, u16);
    check!(EspAuthAlgorithm, u16);
    check!(EspEncapMode, u16);
    check!(NotifyMessageType, u16);
    check!(UserAuthType, u16);
    check!(IkeAttributeType, u16);
    check!(EspAttributeType, u16);
    check!(ConfigAttributeType, u16);
}

/// Spot-check the values that were hand-written before the macro conversion.
#[test]
fn known_values() {
    assert_eq!(u8::from(ProtocolId::Isakmp), 1);
    assert_eq!(u8::from(TransformId::EspAesCbc), 12);
    assert_eq!(u16::from(IkeEncryptionAlgorithm::AesCbc), 7);
    assert_eq!(u16::from(IkeHashAlgorithm::Sha512), 6);
    assert_eq!(u16::from(IkeAuthMethod::HybridInitRsa), 64221);
    assert_eq!(u16::from(EspAuthAlgorithm::HmacSha160), 7);
    assert_eq!(u16::from(EspEncapMode::CheckpointEspInUdp), 0xf003);
    assert_eq!(u8::from(IdentityType::Ipv4Subnet), 4);
    assert_eq!(u8::from(PayloadType::MachineSignature), 0xf9);
    assert_eq!(u8::from(ExchangeType::Quick), 32);
    assert_eq!(u16::from(NotifyMessageType::CccAuth), 0x8004);
    assert_eq!(u16::from(ConfigAttributeType::CccConnectAllowed), 0x404c);
    assert_eq!(u8::from(CertificateType::X509ForAttribute), 10);
    // defaults
    assert_eq!(ProtocolId::default(), ProtocolId::Isakmp);
    assert_eq!(IkeHashAlgorithm::default(), IkeHashAlgorithm::Sha256);
    assert_eq!(EspAuthAlgorithm::default(), EspAuthAlgorithm::HmacSha256);
    assert_eq!(CertificateType::default(), CertificateType::None);
    assert_eq!(AttributesPayloadType::default(), AttributesPayloadType::Request);
    // notify ordering, which transport error handling relies on
    assert!(NotifyMessageType::from(9101) > NotifyMessageType::from(31));
    assert!(NotifyMessageType::UnequalPayloadLengths < NotifyMessageType::from(31));
}

#[test]
fn passwords_are_redacted_in_debug() {
    let payload = AttributesPayload {
        attributes_payload_type: AttributesPayloadType::Reply,
        identifier: 1,
        attributes: vec![
            DataAttribute::long(ConfigAttributeType::UserName.into(), "alice".into()),
            DataAttribute::long(ConfigAttributeType::UserPassword.into(), "hunter2".into()),
            DataAttribute::long(ConfigAttributeType::Passcode.into(), "123456".into()),
        ],
    };
    let debug = format!("{payload:?}");
    assert!(debug.contains("alice"), "{debug}");
    assert!(!debug.contains("hunter2"), "{debug}");
    assert!(!debug.contains("123456"), "{debug}");
}

/// Decoding and re-encoding the captured main-mode message must be byte for
/// byte identical.
#[test]
fn mm_reencode_is_byte_identical() {
    const DATA: &[u8] = include_bytes!("mm.bin");
    let session = Ikev1Session::new(Identity::None, SessionType::Initiator).unwrap();
    let mut codec = Ikev1Codec::new(session);
    let msg = codec.decode(DATA).unwrap().unwrap();
    let encoded = codec.encode(&msg).unwrap();
    assert_eq!(encoded.as_ref(), DATA);
}
