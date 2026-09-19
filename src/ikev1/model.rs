//! IKEv1 numeric registries per RFC 2407 (DOI), RFC 2408 (ISAKMP) and
//! RFC 2409 (IKE), plus the Check Point proprietary extensions this client
//! speaks.
//!
//! IKEv2 shares no payload numbering, exchange numbering or transform encoding
//! with these, so its own registries live in [`crate::ikev2::model`]. Both are
//! built with [`crate::model::registry`], so every value round-trips through
//! an `Other` (or `Reserved`) fallback unchanged.

use std::{fmt, time::Duration};

use bitflags::bitflags;
use bytes::Bytes;

pub use crate::model::VID_CHECKPOINT;
use crate::{
    crypto::DigestType,
    model::{EspAuthentication, registry},
};

pub const VID_FRAGMENTATION: &[u8] = b"\x40\x48\xb7\xd5\x6e\xbc\xe8\x85\x25\xe7\xde\x7f\x00\xd6\xc2\xd3";
pub const VID_NATT: &[u8] = b"\x4a\x13\x1c\x81\x07\x03\x58\x45\x5c\x57\x28\xf2\x0e\x95\x45\x2f";
pub const VID_EXT_WITH_FLAGS: &[u8] =
    b"\x3c\xf1\x87\xb2\x47\x40\x29\xea\x46\xac\x7f\xd0\xea\xf2\x89\xf5\x00\x00\x00\x03";
pub const VID_INITIAL_CONTACT: &[u8] = b"\x26\x24\x4d\x38\xed\xdb\x61\xb3\x17\x2a\x36\xe3\xd0\xcf\xb8\x19";
pub const VID_IPSEC_NAT_T: &[u8] = b"\x90\xcb\x80\x91\x3e\xbb\x69\x6e\x08\x63\x81\xb5\xec\x42\x7b\x1f";
pub const VID_MS_NT5: &[u8] = b"\x1e\x2b\x51\x69\x05\x99\x1c\x7d\x7c\x96\xfc\xbf\xb5\x87\xe4\x61\x00\x00\x00\x04";

bitflags! {
    /// Header flags, RFC 2408 §3.1. The bit positions have no relation to the
    /// IKEv2 flags in [`crate::ikev2::model::Flags`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct IsakmpFlags: u8 {
        const ENCRYPTION = 0b0000_0001;
        const COMMIT = 0b0000_0010;
        const AUTHENTICATION = 0b0000_0100;
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct SituationFlags: u32 {
        const IDENTITY_ONLY = 0b0000_0001;
        const SECRECY = 0b0000_0010;
        const INTEGRITY = 0b0000_0100;
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct SituationData {
    pub level: Bytes,
    pub category: Bytes,
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct Situation {
    pub labeled_domain_identifier: u32,
    pub secrecy: Option<SituationData>,
    pub integrity: Option<SituationData>,
}

registry! {
    #[derive(Default)]
    ProtocolId: u8 as Other {
        Reserved = 0,
        #[default]
        Isakmp = 1,
        IpsecAh = 2,
        IpsecEsp = 3,
        Ipcomp = 4,
    }
}

registry! {
    #[derive(Default)]
    TransformId: u8 as Other {
        Reserved = 0,
        #[default]
        KeyIke = 1,
        Esp3Des = 3,
        EspAesCbc = 12,
    }
}

registry! {
    #[derive(Default)]
    IkeEncryptionAlgorithm: u16 {
        #[default]
        AesCbc = 7,
        DesEde3Cbc = 5,
    }
}

registry! {
    #[derive(Default)]
    IkeGroupDescription: u16 {
        #[default]
        Oakley2 = 2,
        Oakley14 = 14,
    }
}

registry! {
    #[derive(Default)]
    IkeHashAlgorithm: u16 {
        Sha = 2,
        #[default]
        Sha256 = 4,
        Sha384 = 5,
        Sha512 = 6,
        Md5 = 1,
    }
}

registry! {
    #[derive(Default)]
    LifeType: u16 {
        #[default]
        Seconds = 1,
    }
}

registry! {
    #[derive(Default)]
    IkeAuthMethod: u16 {
        RsaSignature = 3,
        /// Check Point hybrid authentication: the gateway authenticates with a
        /// certificate, the client with XAuth afterwards.
        #[default]
        HybridInitRsa = 64221,
    }
}

registry! {
    /// ESP authentication algorithms, RFC 2407 §4.5. IKEv2 negotiates ESP
    /// integrity with its own transform registry
    /// ([`crate::ikev2::model::IntegrityAlgorithm`]), whose numbering only
    /// partly agrees with this one — resolve both into
    /// [`EspAuthentication`] rather than passing raw values around.
    #[derive(Default)]
    EspAuthAlgorithm: u16 {
        HmacSha96 = 2,
        HmacSha160 = 7,
        #[default]
        HmacSha256 = 5,
        HmacSha256v2 = 12,
    }
}

impl EspAuthAlgorithm {
    /// Resolve to the crypto-layer algorithm, for
    /// [`crate::model::EspCryptMaterial`].
    pub fn to_authentication(&self) -> anyhow::Result<EspAuthentication> {
        let digest = match self {
            EspAuthAlgorithm::HmacSha96 | EspAuthAlgorithm::HmacSha160 => DigestType::Sha1,
            EspAuthAlgorithm::HmacSha256 | EspAuthAlgorithm::HmacSha256v2 => DigestType::Sha256,
            EspAuthAlgorithm::Other(other) => {
                anyhow::bail!("Unsupported ESP authentication algorithm: {}", other)
            }
        };

        Ok(EspAuthentication {
            digest,
            icv_len: self.hash_len(),
        })
    }

    pub fn key_len(&self) -> usize {
        match self {
            EspAuthAlgorithm::HmacSha96 | EspAuthAlgorithm::HmacSha160 => 20,
            EspAuthAlgorithm::HmacSha256 | EspAuthAlgorithm::HmacSha256v2 => 32,
            EspAuthAlgorithm::Other(_) => 0,
        }
    }

    pub fn hash_len(&self) -> usize {
        match self {
            EspAuthAlgorithm::HmacSha96 => 12,
            EspAuthAlgorithm::HmacSha160 => 20,
            EspAuthAlgorithm::HmacSha256 | EspAuthAlgorithm::HmacSha256v2 => 16,
            EspAuthAlgorithm::Other(_) => 0,
        }
    }
}

registry! {
    #[derive(Default)]
    EspEncapMode: u16 {
        #[default]
        UdpTunnel = 3,
        CheckpointEspInUdp = 0xf003,
    }
}

registry! {
    #[derive(Default)]
    IdentityType: u8 {
        #[default]
        Ipv4Address = 1,
        Ipv4Subnet = 4,
        UserFqdn = 3,
        DerAsn1Dn = 9,
    }
}

registry! {
    #[derive(Default)]
    NotifyMessageType: u16 {
        #[default]
        InvalidPayloadType = 1,
        DoiNotSupported = 2,
        SituationNotSupported = 3,
        InvalidCookie = 4,
        InvalidMajorVersion = 5,
        InvalidMinorVersion = 6,
        InvalidExchangeType = 7,
        InvalidFlags = 8,
        InvalidMessageId = 9,
        InvalidProtocolId = 10,
        InvalidSpi = 11,
        InvalidTransformId = 12,
        AttributesNotSupported = 13,
        NoProposalChosen = 14,
        BadProposalSyntax = 15,
        PayloadMalformed = 16,
        InvalidKeyInformation = 17,
        InvalidIdInformation = 18,
        InvalidCertEncoding = 19,
        InvalidCertificate = 20,
        CertTypeUnsupported = 21,
        InvalidCertAuthority = 22,
        InvalidHashInformation = 23,
        AuthenticationFailed = 24,
        InvalidSignature = 25,
        AddressNotification = 26,
        NotifySaLifeTime = 27,
        CertificateUnavailable = 28,
        UnsupportedExchangeType = 29,
        UnequalPayloadLengths = 30,
        /// Check Point's CCC authentication blob. The IKEv2 path carries the
        /// same blob under a different number, see
        /// [`crate::ikev2::model::NotifyType::CccAuth`].
        CccAuth = 0x8004,
    }
}

registry! {
    #[derive(Default)]
    UserAuthType: u16 {
        #[default]
        Generic = 0,
    }
}

registry! {
    /// Payload types, RFC 2408 §3.1. IKEv2 reuses 33.. for entirely different
    /// payloads; see [`crate::ikev2::model::PayloadType`].
    PayloadType: u8 {
        None = 0,
        SecurityAssociation = 1,
        Proposal = 2,
        Transform = 3,
        KeyExchange = 4,
        Identification = 5,
        Certificate = 6,
        CertificateRequest = 7,
        Hash = 8,
        Signature = 9,
        Nonce = 10,
        Notification = 11,
        Delete = 12,
        VendorId = 13,
        Attributes = 14,
        Natd = 20,
        /// Check Point proprietary: PA_MCERT for hybrid auth.
        MachineCertificate = 0xf6,
        /// Check Point proprietary: PA_MSIG for hybrid auth.
        MachineSignature = 0xf9,
    }
}

registry! {
    /// Exchange types, RFC 2408 §3.1.
    ExchangeType: u8 {
        None = 0,
        Base = 1,
        IdentityProtection = 2,
        AuthenticationOnly = 3,
        Aggressive = 4,
        Informational = 5,
        Transaction = 6,
        Quick = 32,
    }
}

registry! {
    /// IKE SA attribute types, RFC 2409 Appendix A.
    IkeAttributeType: u16 {
        Unknown = 0,
        EncryptionAlgorithm = 1,
        HashAlgorithm = 2,
        AuthenticationMethod = 3,
        GroupDescription = 4,
        GroupType = 5,
        GroupPrime = 6,
        GroupGeneratorOne = 7,
        GroupGeneratorTwo = 8,
        GroupCurveA = 9,
        GroupCurveB = 10,
        LifeType = 11,
        LifeDuration = 12,
        Prf = 13,
        KeyLength = 14,
        FieldSize = 15,
        GroupOrder = 16,
    }
}

registry! {
    /// IPSEC SA attribute types, RFC 2407 §4.5.
    EspAttributeType: u16 {
        Unknown = 0,
        LifeType = 1,
        LifeDuration = 2,
        EncapsulationMode = 4,
        AuthenticationAlgorithm = 5,
        KeyLength = 6,
    }
}

registry! {
    /// ISAKMP-config (office mode) attribute types, RFC 2407 and the Check
    /// Point private range at 0x4000.
    ConfigAttributeType: u16 {
        Ipv4Address = 1,
        Ipv4Netmask = 2,
        Ipv4Dns = 3,
        AddressExpiry = 5,
        AuthType = 13,
        UserName = 14,
        UserPassword = 15,
        Passcode = 16,
        Message = 17,
        Challenge = 18,
        Domain = 19,
        Status = 20,
        NextPin = 21,
        Answer = 22,
        InternalDomainName = 0x4003,
        MacAddress = 0x4004,
        CccSessionId = 0x4045,
        CccVariableLeaseTime = 0x4046,
        CccOfficeModeAllowed = 0x4047,
        CccConnectAllowed = 0x404c,
    }
}

/// Attribute types whose value is a credential and must never reach a log; see
/// the `Debug` implementation of [`crate::ikev1::payload::AttributesPayload`].
pub(crate) fn is_sensitive_config_attribute(attribute_type: u16) -> bool {
    matches!(
        attribute_type.into(),
        ConfigAttributeType::UserPassword | ConfigAttributeType::Passcode
    )
}

registry! {
    #[derive(Default)]
    CertificateType: u8 as Reserved {
        #[default]
        None = 0,
        Pkcs7WrappedX509 = 1,
        Pgp = 2,
        DnsSignedKey = 3,
        X509ForSignature = 4,
        X509ForKeyExchange = 5,
        KerberosTokens = 6,
        Crl = 7,
        Arl = 8,
        Spki = 9,
        X509ForAttribute = 10,
    }
}

registry! {
    #[derive(Default)]
    AttributesPayloadType: u8 as Reserved {
        #[default]
        Request = 1,
        Reply = 2,
        Set = 3,
        Ack = 4,
    }
}

/// The transforms a responder selected out of our main-mode proposal, with the
/// SPIs of the IKE SA they key. The IKEv1 counterpart of
/// [`crate::ikev2::model::Ikev2SaProposal`].
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct SaProposal {
    pub initiator_spi: u64,
    pub responder_spi: u64,
    pub sa_bytes: Bytes,
    pub hash_alg: IkeHashAlgorithm,
    pub enc_alg: IkeEncryptionAlgorithm,
    pub key_len: usize,
    pub group: IkeGroupDescription,
    pub lifetime: Duration,
}

impl fmt::Display for SaProposal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SaProposal")
            .field("initiator_spi", &self.initiator_spi)
            .field("responder_spi", &self.responder_spi)
            .field("hash_alg", &self.hash_alg)
            .field("enc_alg", &self.enc_alg)
            .field("key_len", &self.key_len)
            .field("group", &self.group)
            .field("lifetime", &self.lifetime.as_secs())
            .finish()
    }
}

/// The child SA transforms a responder selected from our quick-mode proposal,
/// with both ESP SPIs and nonces.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct EspProposal {
    pub spi_i: u32,
    pub nonce_i: Bytes,
    pub spi_r: u32,
    pub nonce_r: Bytes,
    pub transform_id: TransformId,
    pub auth_alg: EspAuthAlgorithm,
    pub key_len: usize,
}

#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct IdentityRequest {
    pub auth_blob: String,
    pub internal_ca_fingerprints: Vec<String>,
    pub with_mfa: bool,
}
