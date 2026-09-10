//! Parses a hand-laid-out IKE_SA_INIT request, byte for byte against
//! RFC 7296 §3. A round-trip test can agree with itself while every field sits
//! at the wrong offset; this one cannot.

use isakmp::{
    ikev2::{
        codec::Ikev2Codec,
        model::{
            DhGroup, EncryptionAlgorithm, ExchangeType, Flags, IntegrityAlgorithm, NotifyType, PayloadType, ProtocolId,
            PseudoRandomFunction, TransformType,
        },
        payload::Payload,
    },
    message::{IKEV2_VERSION, ISAKMP_HEADER_LEN, IsakmpMessageCodec},
};

/// SPIs, then SA (one IKE proposal with ENCR/PRF/INTEG/D-H), KE, Ni and a
/// NAT_DETECTION_SOURCE_IP notify.
const DATA: &str = "00112233445566778899aabbccddeeff2120220800000000000000d4220000300000002c010100040300000c0100000c\
                    800e01000300000802000005030000080300000c00000008040000132800004800130000000102030405060708090a0b\
                    0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b\
                    3c3d3e3f29000024aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000001c00004004\
                    1111111111111111111111111111111111111111";

#[test]
fn test_parse_ike_sa_init() {
    let data = hex::decode(DATA.replace(' ', "")).unwrap();
    assert_eq!(data.len(), 212);

    let message = Ikev2Codec::new().decode(&data).unwrap().unwrap();

    assert_eq!(message.initiator_spi, 0x0011223344556677);
    assert_eq!(message.responder_spi, 0x8899aabbccddeeff);
    assert_eq!(message.version, IKEV2_VERSION);
    assert_eq!(message.exchange_type, ExchangeType::IkeSaInit);
    assert_eq!(message.flags, Flags::INITIATOR);
    assert_eq!(message.message_id, 0);
    assert_eq!(message.payloads.len(), 4);

    let Payload::SecurityAssociation(sa) = &message.payloads[0] else {
        panic!("expected an SA payload, got {:?}", message.payloads[0]);
    };
    assert_eq!(sa.proposals.len(), 1);

    let proposal = &sa.proposals[0];
    assert_eq!(proposal.proposal_num, 1);
    assert_eq!(proposal.protocol_id, ProtocolId::Ike);
    assert!(proposal.spi.is_empty(), "an initial IKE proposal carries no SPI");
    assert_eq!(proposal.transforms.len(), 4);

    let encr = proposal.find(TransformType::EncryptionAlgorithm).unwrap();
    assert_eq!(encr.as_encryption(), Some(EncryptionAlgorithm::AesCbc));
    assert_eq!(encr.key_len(), Some(32), "Key Length attribute is 256 bits");

    assert_eq!(
        proposal.find(TransformType::PseudoRandomFunction).unwrap().as_prf(),
        Some(PseudoRandomFunction::HmacSha256)
    );
    assert_eq!(
        proposal.find(TransformType::IntegrityAlgorithm).unwrap().as_integrity(),
        Some(IntegrityAlgorithm::HmacSha256_128)
    );
    assert_eq!(
        proposal.find(TransformType::DiffieHellmanGroup).unwrap().as_dh_group(),
        Some(DhGroup::Ecp256)
    );
    assert_eq!(proposal.find(TransformType::ExtendedSequenceNumbers), None);

    let Payload::KeyExchange(ke) = &message.payloads[1] else {
        panic!("expected a KE payload, got {:?}", message.payloads[1]);
    };
    assert_eq!(ke.dh_group, DhGroup::Ecp256);
    assert_eq!(ke.data.len(), 64, "P-256 carries x || y");
    assert_eq!(&ke.data[..4], &[0x00, 0x01, 0x02, 0x03]);

    let Payload::Nonce(nonce) = &message.payloads[2] else {
        panic!("expected a nonce payload, got {:?}", message.payloads[2]);
    };
    assert_eq!(nonce.data.len(), 32);
    assert!(nonce.data.iter().all(|b| *b == 0xaa));

    let Payload::Notify(notify) = &message.payloads[3] else {
        panic!("expected a notify payload, got {:?}", message.payloads[3]);
    };
    assert_eq!(notify.notify_type, NotifyType::NatDetectionSourceIp);
    assert!(!notify.notify_type.is_error());
    assert_eq!(notify.protocol_id, ProtocolId::None);
    assert!(notify.spi.is_empty());
    assert_eq!(notify.data.len(), 20, "SHA-1 of SPIs, IP and port");
}

/// Re-encoding must reproduce the original octets, which pins the encoder to
/// the same field layout the decoder was checked against.
#[test]
fn test_reencode_is_byte_identical() {
    let data = hex::decode(DATA.replace(' ', "")).unwrap();

    let mut codec = Ikev2Codec::new();
    let message = codec.decode(&data).unwrap().unwrap();

    assert_eq!(codec.encode(&message).unwrap(), data);
}

#[test]
fn test_header_offsets() {
    let data = hex::decode(DATA.replace(' ', "")).unwrap();

    assert_eq!(data[16], u8::from(PayloadType::SecurityAssociation));
    assert_eq!(data[17], IKEV2_VERSION);
    assert_eq!(data[18], u8::from(ExchangeType::IkeSaInit));
    assert_eq!(data[19], Flags::INITIATOR.bits());
    assert_eq!(&data[20..24], &[0, 0, 0, 0], "message ID 0");
    assert_eq!(
        u32::from_be_bytes(data[24..ISAKMP_HEADER_LEN].try_into().unwrap()) as usize,
        data.len()
    );
}
