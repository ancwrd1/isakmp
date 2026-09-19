//! IKEv2 numeric registries per RFC 7296.
//!
//! IKEv2 shares no payload numbering, exchange numbering or transform encoding
//! with IKEv1, so these live alongside [`crate::ikev1::model`] rather than
//! inside [`crate::model`]. Both are built with [`crate::model::registry`], so
//! every value round-trips through an `Other` fallback unchanged.

use bitflags::bitflags;

use crate::{
    crypto::{CipherType, DigestType, GroupType},
    model::{EspAuthentication, registry},
};

/// Attribute type carried by a transform: the only one RFC 7296 defines.
pub const ATTRIBUTE_TYPE_KEY_LENGTH: u16 = 14;

/// Notify types below this are errors, at or above it are status messages.
pub const NOTIFY_STATUS_BASE: u16 = 16384;

registry! {
    /// Payload types, RFC 7296 §3.2. IKEv1 uses 1..14 for entirely different
    /// payloads; IKEv2 starts at 33.
    PayloadType: u8 {
        None = 0,
        SecurityAssociation = 33,
        KeyExchange = 34,
        IdentificationInitiator = 35,
        IdentificationResponder = 36,
        Certificate = 37,
        CertificateRequest = 38,
        Authentication = 39,
        Nonce = 40,
        Notify = 41,
        Delete = 42,
        VendorId = 43,
        TrafficSelectorInitiator = 44,
        TrafficSelectorResponder = 45,
        /// SK, the encrypted-and-authenticated envelope around every other
        /// payload once the IKE SA is keyed.
        Encrypted = 46,
        Configuration = 47,
        ExtensibleAuthentication = 48,
        GenericSecurePasswordMethod = 49,
        GroupIdentification = 50,
        GroupSecurityAssociation = 51,
        KeyDownload = 52,
        /// SKF, RFC 7383 IKE fragmentation.
        EncryptedFragment = 53,
    }
}

registry! {
    /// Exchange types, RFC 7296 §3.1.
    ExchangeType: u8 {
        IkeSaInit = 34,
        IkeAuth = 35,
        CreateChildSa = 36,
        Informational = 37,
    }
}

bitflags! {
    /// Header flags, RFC 7296 §3.1. The bit positions have no relation to the
    /// IKEv1 flags in [`crate::ikev1::model::IsakmpFlags`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct Flags: u8 {
        /// Sent by the original initiator of the IKE SA.
        const INITIATOR = 0b0000_1000;
        /// Peer is able to speak a higher major version.
        const VERSION = 0b0001_0000;
        /// This message responds to a request with the same message ID.
        const RESPONSE = 0b0010_0000;
    }
}

registry! {
    /// Protocol IDs used by proposals, notifies and deletes, RFC 7296 §3.3.1.
    ProtocolId: u8 {
        None = 0,
        Ike = 1,
        Ah = 2,
        Esp = 3,
    }
}

registry! {
    /// Transform types, RFC 7296 §3.3.2. Which types a proposal must carry
    /// depends on the protocol: IKE needs ENCR, PRF, INTEG and D-H; ESP needs
    /// ENCR, INTEG and ESN.
    TransformType: u8 {
        EncryptionAlgorithm = 1,
        PseudoRandomFunction = 2,
        IntegrityAlgorithm = 3,
        DiffieHellmanGroup = 4,
        ExtendedSequenceNumbers = 5,
    }
}

registry! {
    /// Transform type 1 (ENCR) IDs.
    EncryptionAlgorithm: u16 {
        DesEde3Cbc = 3,
        Null = 11,
        AesCbc = 12,
        AesCtr = 13,
        AesGcm8 = 18,
        AesGcm12 = 19,
        AesGcm16 = 20,
        ChaCha20Poly1305 = 28,
    }
}

impl EncryptionAlgorithm {
    /// Resolve to a concrete cipher, given the negotiated key length.
    pub fn to_cipher_type(self, key_len: usize) -> anyhow::Result<CipherType> {
        CipherType::new_for_ikev2(self.into(), key_len)
    }

    /// Whether this algorithm authenticates its own output, in which case the
    /// proposal's integrity transform must be `IntegrityAlgorithm::None`.
    pub fn is_aead(&self) -> bool {
        matches!(
            self,
            Self::AesGcm8 | Self::AesGcm12 | Self::AesGcm16 | Self::ChaCha20Poly1305
        )
    }
}

registry! {
    /// Transform type 2 (PRF) IDs.
    PseudoRandomFunction: u16 {
        HmacMd5 = 1,
        HmacSha1 = 2,
        HmacTiger = 3,
        AesXCbc = 4,
        HmacSha256 = 5,
        HmacSha384 = 6,
        HmacSha512 = 7,
        AesCmac = 8,
    }
}

impl PseudoRandomFunction {
    pub fn to_digest_type(self) -> anyhow::Result<DigestType> {
        match self {
            Self::HmacMd5 => Ok(DigestType::Md5),
            Self::HmacSha1 => Ok(DigestType::Sha1),
            Self::HmacSha256 => Ok(DigestType::Sha256),
            Self::HmacSha384 => Ok(DigestType::Sha384),
            Self::HmacSha512 => Ok(DigestType::Sha512),
            other => anyhow::bail!("Unsupported PRF: {:?}", other),
        }
    }
}

registry! {
    /// Transform type 3 (INTEG) IDs. `None` is the only legal value alongside
    /// an AEAD encryption transform.
    IntegrityAlgorithm: u16 {
        None = 0,
        HmacMd5_96 = 1,
        HmacSha1_96 = 2,
        AesXCbc96 = 5,
        HmacMd5_128 = 6,
        HmacSha1_160 = 7,
        AesCmac96 = 8,
        HmacSha256_128 = 12,
        HmacSha384_192 = 13,
        HmacSha512_256 = 14,
    }
}

impl IntegrityAlgorithm {
    pub fn to_digest_type(self) -> anyhow::Result<DigestType> {
        match self {
            Self::HmacMd5_96 | Self::HmacMd5_128 => Ok(DigestType::Md5),
            Self::HmacSha1_96 | Self::HmacSha1_160 => Ok(DigestType::Sha1),
            Self::HmacSha256_128 => Ok(DigestType::Sha256),
            Self::HmacSha384_192 => Ok(DigestType::Sha384),
            Self::HmacSha512_256 => Ok(DigestType::Sha512),
            other => anyhow::bail!("Unsupported integrity algorithm: {:?}", other),
        }
    }

    /// Resolve to the crypto-layer algorithm, for
    /// [`crate::model::EspCryptMaterial`]. `None` for `INTEG_NONE`, which is
    /// what an AEAD child SA negotiates.
    pub fn to_authentication(self) -> anyhow::Result<Option<EspAuthentication>> {
        match self {
            Self::None => Ok(None),
            _ => Ok(Some(EspAuthentication {
                digest: self.to_digest_type()?,
                icv_len: self.checksum_len()?,
            })),
        }
    }

    /// Checksum length on the wire, which is not always half the digest size.
    pub fn checksum_len(self) -> anyhow::Result<usize> {
        match self {
            Self::None => Ok(0),
            Self::HmacMd5_96 | Self::HmacSha1_96 | Self::AesXCbc96 | Self::AesCmac96 => Ok(12),
            Self::HmacMd5_128 => Ok(16),
            Self::HmacSha1_160 => Ok(20),
            Self::HmacSha256_128 => Ok(16),
            Self::HmacSha384_192 => Ok(24),
            Self::HmacSha512_256 => Ok(32),
            other => anyhow::bail!("Unsupported integrity algorithm: {:?}", other),
        }
    }
}

registry! {
    /// Transform type 4 (D-H) IDs.
    DhGroup: u16 {
        None = 0,
        Modp768 = 1,
        Modp1024 = 2,
        Modp1536 = 5,
        Modp2048 = 14,
        Modp3072 = 15,
        Modp4096 = 16,
        Ecp256 = 19,
        Ecp384 = 20,
        Ecp521 = 21,
        Curve25519 = 31,
    }
}

impl DhGroup {
    pub fn to_group_type(self) -> anyhow::Result<GroupType> {
        GroupType::from_group_id(self.into())
    }
}

impl From<GroupType> for DhGroup {
    fn from(value: GroupType) -> Self {
        value.group_id().into()
    }
}

registry! {
    /// Transform type 5 (ESN) IDs.
    ExtendedSequenceNumbers: u16 {
        None = 0,
        Enabled = 1,
    }
}

/// The transforms a responder selected out of our IKE_SA_INIT proposal, with
/// the SPIs of the IKE SA they key. The IKEv2 counterpart of
/// [`crate::ikev1::model::SaProposal`], which carries an IKEv1 attribute set
/// instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ikev2SaProposal {
    pub initiator_spi: u64,
    pub responder_spi: u64,
    pub encryption: EncryptionAlgorithm,
    /// Cipher key length in bytes, from the transform's Key Length attribute.
    pub key_len: usize,
    pub prf: PseudoRandomFunction,
    /// `None` when the encryption transform is AEAD, which carries its own.
    pub integrity: IntegrityAlgorithm,
    pub dh_group: DhGroup,
}

registry! {
    /// EAP codes, RFC 3748 §4. Success and Failure carry no type or data and
    /// end the EAP conversation.
    EapCode: u8 {
        Request = 1,
        Response = 2,
        Success = 3,
        Failure = 4,
    }
}

registry! {
    /// EAP method types, RFC 3748 §5. The Check Point gateway uses Generic
    /// Token Card; the rest are here to name what a capture might show.
    EapType: u8 {
        Identity = 1,
        Notification = 2,
        LegacyNak = 3,
        Md5Challenge = 4,
        OneTimePassword = 5,
        GenericTokenCard = 6,
        Tls = 13,
        MsChapV2 = 26,
    }
}

/// The child SA transforms a responder selected from our SAi2 proposal, with
/// both ESP SPIs. Unlike the IKE SA, each direction has its own SPI: the one we
/// chose is for packets arriving, the one the responder chose for packets we
/// send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ikev2EspProposal {
    /// SPI we put in SAi2, which the responder will send to.
    pub spi_i: u32,
    /// SPI from SAr2, which we send to.
    pub spi_r: u32,
    pub encryption: EncryptionAlgorithm,
    pub key_len: usize,
    pub integrity: IntegrityAlgorithm,
}

registry! {
    /// Notify message types, RFC 7296 §3.10.1. Values below
    /// [`NOTIFY_STATUS_BASE`] are errors and abort the exchange.
    NotifyType: u16 {
        UnsupportedCriticalPayload = 1,
        InvalidIkeSpi = 4,
        InvalidMajorVersion = 5,
        InvalidSyntax = 7,
        InvalidMessageId = 9,
        InvalidSpi = 11,
        NoProposalChosen = 14,
        InvalidKePayload = 17,
        AuthenticationFailed = 24,
        SinglePairRequired = 34,
        NoAdditionalSas = 35,
        InternalAddressFailure = 36,
        FailedCpRequired = 37,
        TsUnacceptable = 38,
        InvalidSelectors = 39,
        TemporaryFailure = 43,
        ChildSaNotFound = 44,
        InitialContact = 16384,
        SetWindowSize = 16385,
        AdditionalTsPossible = 16386,
        IpcompSupported = 16387,
        NatDetectionSourceIp = 16388,
        NatDetectionDestinationIp = 16389,
        Cookie = 16390,
        UseTransportMode = 16391,
        HttpCertLookupSupported = 16392,
        RekeySa = 16393,
        EspTfcPaddingNotSupported = 16394,
        NonFirstFragmentsAlso = 16395,
        MobikeSupported = 16396,
        /// RFC 4478: how long the authentication stays valid, after which the
        /// gateway expects a fresh one.
        AuthLifetime = 16403,
        /// RFC 4739 multiple authentication, advertised by both the Check Point
        /// client and gateway in the phase-1 capture.
        MultipleAuthSupported = 16404,
        AnotherAuthFollows = 16405,
        RedirectSupported = 16406,
        /// RFC 6290. The Check Point gateway sends a 32-octet token with the
        /// final IKE_AUTH response.
        QuickCrashDetection = 16419,
        Ikev2FragmentationSupported = 16430,
        SignatureHashAlgorithms = 16431,
        /// RFC 9242. Offered by the Check Point gateway; we do not use it.
        IntermediateExchangeSupported = 16438,
        /// Check Point's CCC authentication blob, sent in IKE_AUTH #1.
        ///
        /// **Not** the IKEv1 number. `CCC_SESSION_COOKIE` = 0x4045 carries over
        /// from IKEv1, so this was assumed to as well, at 0x8004 — but 0x8004
        /// is 32772, inside IKEv2's IANA-reserved status range (16384-40959)
        /// rather than the private-use range, and a status notify the
        /// responder does not recognise is ignored rather than refused
        /// (RFC 7296 §3.10.1). The blob was being dropped in silence, which
        /// cost nothing until the gateway stopped tolerating clients that
        /// never identify themselves and began answering *"Your client is not
        /// supported"*. Found by sending the blob under several candidates at
        /// once and bisecting; it sits between the two below, as the block
        /// suggests it would.
        CccAuth = 42772,
        /// Observed in the IKE_SA_INIT response, 4 octets.
        CccPolicyId = 42771,
        /// Observed in the IKE_SA_INIT response, 16 octets.
        CccRealm = 42773,
        /// Observed with EAP success: a NUL-terminated status line followed by
        /// a NUL-terminated `msg_obj` S-expression, the same shape the IKEv1
        /// path already parses.
        CpRaAuthLog = 42780,
        /// Zero-length, last payload of IKE_SA_INIT. The captured Windows
        /// client sends it on every login, password or certificate, and the
        /// gateway **echoes it** in its own IKE_SA_INIT response — so it reads
        /// as a capability both sides confirm rather than an announcement that
        /// machine authentication is in use.
        CpRaUsingMachineAuth = 42781,
    }
}

impl NotifyType {
    pub fn is_error(&self) -> bool {
        u16::from(*self) < NOTIFY_STATUS_BASE
    }
}

registry! {
    /// AUTH payload methods, RFC 7296 §3.8.
    AuthMethod: u8 {
        RsaDigitalSignature = 1,
        SharedKeyMic = 2,
        DssDigitalSignature = 3,
        EcdsaSha256P256 = 9,
        EcdsaSha384P384 = 10,
        EcdsaSha512P521 = 11,
        GenericSecurePasswordMethod = 12,
        /// RFC 7427: the signature is prefixed by an ASN.1 AlgorithmIdentifier
        /// naming the hash and signature algorithm, rather than being implied
        /// by the method number.
        DigitalSignature = 14,
    }
}

registry! {
    /// Identification types, RFC 7296 §3.5.
    IdentificationType: u8 {
        Ipv4Address = 1,
        Fqdn = 2,
        Rfc822Address = 3,
        Ipv6Address = 5,
        DerAsn1Dn = 9,
        DerAsn1Gn = 10,
        KeyId = 11,
        FcName = 12,
        Null = 13,
    }
}

registry! {
    /// Certificate encodings, RFC 7296 §3.6.
    CertificateEncoding: u8 {
        None = 0,
        Pkcs7WrappedX509 = 1,
        PgpCertificate = 2,
        DnsSignedKey = 3,
        X509CertificateSignature = 4,
        KerberosToken = 6,
        CertificateRevocationList = 7,
        AuthorityRevocationList = 8,
        SpkiCertificate = 9,
        X509CertificateAttribute = 10,
        HashAndUrlX509Certificate = 12,
        HashAndUrlX509Bundle = 13,
        OcspContent = 14,
        RawPublicKey = 15,
    }
}

registry! {
    /// Traffic selector types, RFC 7296 §3.13.1.
    TrafficSelectorType: u8 {
        Ipv4AddrRange = 7,
        Ipv6AddrRange = 8,
        FcAddrRange = 9,
    }
}

registry! {
    /// Configuration payload types, RFC 7296 §3.15. The IKEv2 counterpart of
    /// the IKEv1 ISAKMP-config (office mode) transaction exchange.
    ConfigurationType: u8 {
        Request = 1,
        Reply = 2,
        Set = 3,
        Ack = 4,
    }
}

registry! {
    /// Configuration attribute types, RFC 7296 §3.15.1.
    ConfigurationAttributeType: u16 {
        InternalIp4Address = 1,
        InternalIp4Netmask = 2,
        InternalIp4Dns = 3,
        InternalIp4Nbns = 4,
        /// Seconds the assigned address stays valid.
        InternalAddressExpiry = 5,
        InternalIp4Dhcp = 6,
        ApplicationVersion = 7,
        InternalIp6Address = 8,
        InternalIp6Dns = 10,
        InternalIp6Dhcp = 12,
        InternalIp4Subnet = 13,
        SupportedAttributes = 14,
        InternalIp6Subnet = 15,
        // CheckPoint private attributes
        InternalDnsDomain = 0x4003,
        CccSessionCookie = 0x4045,
        CccVariableLeaseTime = 0x4046,
        CccOfficeModeAllowed = 0x4047,
        CccConnectAllowed = 0x404c,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every registry must survive a decode/encode cycle, including values it
    /// does not know.
    macro_rules! assert_round_trips {
        ($name:ident : $repr:ty, $($value:expr),+ $(,)?) => {
            for value in [$($value as $repr),+] {
                assert_eq!(
                    <$repr>::from($name::from(value)),
                    value,
                    "{} did not round-trip {}", stringify!($name), value,
                );
            }
        };
    }

    #[test]
    fn test_registries_round_trip() {
        assert_round_trips!(PayloadType: u8, 0, 33, 46, 53, 1, 32, 54, 255);
        assert_round_trips!(ExchangeType: u8, 34, 35, 36, 37, 0, 2, 33, 38, 255);
        assert_round_trips!(ProtocolId: u8, 0, 1, 2, 3, 4, 255);
        assert_round_trips!(TransformType: u8, 1, 2, 3, 4, 5, 0, 6, 255);
        assert_round_trips!(EncryptionAlgorithm: u16, 3, 12, 18, 19, 20, 28, 0, 1, 65535);
        assert_round_trips!(PseudoRandomFunction: u16, 1, 2, 4, 5, 6, 7, 8, 0, 9, 65535);
        assert_round_trips!(IntegrityAlgorithm: u16, 0, 1, 2, 5, 12, 13, 14, 3, 15, 65535);
        assert_round_trips!(DhGroup: u16, 0, 2, 14, 19, 20, 21, 31, 3, 65535);
        assert_round_trips!(ExtendedSequenceNumbers: u16, 0, 1, 2, 65535);
        assert_round_trips!(NotifyType: u16, 1, 14, 17, 24, 16384, 16390, 16393, 16431, 2, 20000, 65535);
        assert_round_trips!(AuthMethod: u8, 1, 2, 3, 9, 10, 11, 14, 0, 15, 255);
        assert_round_trips!(IdentificationType: u8, 1, 2, 3, 5, 9, 11, 13, 4, 255);
        assert_round_trips!(CertificateEncoding: u8, 0, 1, 4, 12, 15, 5, 11, 255);
        assert_round_trips!(TrafficSelectorType: u8, 7, 8, 9, 0, 6, 255);
        assert_round_trips!(ConfigurationType: u8, 1, 2, 3, 4, 0, 5, 255);
        assert_round_trips!(ConfigurationAttributeType: u16, 1, 2, 3, 7, 13, 15, 5, 9, 65535);
    }

    #[test]
    fn test_payload_numbering_does_not_overlap_ikev1() {
        // IKEv1 uses 1..=14 for entirely different payloads; the only value the
        // two versions agree on is 0.
        assert_eq!(u8::from(PayloadType::None), 0);
        assert_eq!(u8::from(PayloadType::SecurityAssociation), 33);
        assert_eq!(u8::from(PayloadType::Encrypted), 46);
    }

    #[test]
    fn test_notify_error_classification() {
        for notify in [
            NotifyType::NoProposalChosen,
            NotifyType::AuthenticationFailed,
            NotifyType::InvalidKePayload,
            NotifyType::Other(1),
        ] {
            assert!(notify.is_error(), "{notify:?}");
        }

        for notify in [
            NotifyType::Cookie,
            NotifyType::InitialContact,
            NotifyType::NatDetectionSourceIp,
            NotifyType::RekeySa,
            NotifyType::Other(NOTIFY_STATUS_BASE),
        ] {
            assert!(!notify.is_error(), "{notify:?}");
        }
    }

    #[test]
    fn test_flag_bits() {
        assert_eq!(Flags::INITIATOR.bits(), 0x08);
        assert_eq!(Flags::VERSION.bits(), 0x10);
        assert_eq!(Flags::RESPONSE.bits(), 0x20);

        // an initiator's request, the most common combination
        assert_eq!(Flags::INITIATOR.bits(), 0b0000_1000);
        assert_eq!((Flags::INITIATOR | Flags::RESPONSE).bits(), 0x28);
    }

    /// The two versions number ESP integrity algorithms differently, which is
    /// why [`crate::model::EspCryptMaterial`] stores resolved crypto types
    /// rather than a raw transform ID.
    #[test]
    fn test_esp_integrity_numbering_differs_from_ikev1() {
        use crate::ikev1::model::EspAuthAlgorithm;

        // transform 5: HMAC-SHA2-256 for IKEv1, AUTH_AES_XCBC_96 for IKEv2 —
        // not an HMAC at all, so it does not even resolve to a digest
        assert_eq!(
            EspAuthAlgorithm::from(5u16).to_authentication().unwrap(),
            EspAuthentication {
                digest: DigestType::Sha256,
                icv_len: 16
            }
        );
        assert!(IntegrityAlgorithm::from(5u16).to_authentication().is_err());

        // transform 2 is HMAC-SHA1-96 in both, and must resolve identically
        assert_eq!(
            EspAuthAlgorithm::from(2u16).to_authentication().unwrap(),
            IntegrityAlgorithm::from(2u16).to_authentication().unwrap().unwrap()
        );

        assert_eq!(
            IntegrityAlgorithm::HmacSha256_128.to_authentication().unwrap(),
            Some(EspAuthentication {
                digest: DigestType::Sha256,
                icv_len: 16
            })
        );
        assert_eq!(IntegrityAlgorithm::None.to_authentication().unwrap(), None);
    }

    /// The same digest at two truncations is a different algorithm, so the ICV
    /// length has to be carried rather than derived from the digest.
    #[test]
    fn test_same_digest_at_two_truncations() {
        let short = IntegrityAlgorithm::HmacSha1_96.to_authentication().unwrap().unwrap();
        let long = IntegrityAlgorithm::HmacSha1_160.to_authentication().unwrap().unwrap();

        assert_eq!(short.digest, long.digest);
        assert_eq!((short.icv_len, long.icv_len), (12, 20));
    }

    #[test]
    fn test_transform_ids_map_to_crypto_types() {
        assert_eq!(
            EncryptionAlgorithm::AesCbc.to_cipher_type(32).unwrap(),
            CipherType::Aes256Cbc
        );
        assert_eq!(
            EncryptionAlgorithm::AesGcm16.to_cipher_type(32).unwrap(),
            CipherType::Aes256Gcm(crate::crypto::IcvLength::Sixteen)
        );
        assert!(EncryptionAlgorithm::AesGcm16.is_aead());
        assert!(!EncryptionAlgorithm::AesCbc.is_aead());

        assert_eq!(
            PseudoRandomFunction::HmacSha256.to_digest_type().unwrap(),
            DigestType::Sha256
        );
        assert!(PseudoRandomFunction::AesXCbc.to_digest_type().is_err());

        assert_eq!(
            IntegrityAlgorithm::HmacSha256_128.to_digest_type().unwrap(),
            DigestType::Sha256
        );
        assert_eq!(IntegrityAlgorithm::HmacSha256_128.checksum_len().unwrap(), 16);
        assert_eq!(IntegrityAlgorithm::HmacSha1_96.checksum_len().unwrap(), 12);
        assert_eq!(IntegrityAlgorithm::None.checksum_len().unwrap(), 0);

        assert_eq!(DhGroup::Ecp256.to_group_type().unwrap(), GroupType::EcP256);
        assert_eq!(DhGroup::from(GroupType::Oakley14), DhGroup::Modp2048);
        assert!(DhGroup::Modp768.to_group_type().is_err());
    }
}
