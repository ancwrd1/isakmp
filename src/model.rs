use std::{io::Read, path::PathBuf};

use bitflags::bitflags;
use byteorder::{BigEndian, ReadBytesExt};
use bytes::{BufMut, Bytes, BytesMut};

pub const VID_CHECKPOINT: &[u8] = b"\xde\xfb\x99\xe6\x9a\x9f\x1f\x6e\x06\xf1\x50\x06\xb1\xf1\x66\xae";
pub const VID_FRAGMENTATION: &[u8] = b"\x40\x48\xb7\xd5\x6e\xbc\xe8\x85\x25\xe7\xde\x7f\x00\xd6\xc2\xd3";
pub const VID_NATT: &[u8] = b"\x4a\x13\x1c\x81\x07\x03\x58\x45\x5c\x57\x28\xf2\x0e\x95\x45\x2f";
pub const VID_EXT_WITH_FLAGS: &[u8] =
    b"\x3c\xf1\x87\xb2\x47\x40\x29\xea\x46\xac\x7f\xd0\xea\xf2\x89\xf5\x00\x00\x00\x03";
pub const VID_INITIAL_CONTACT: &[u8] = b"\x26\x24\x4d\x38\xed\xdb\x61\xb3\x17\x2a\x36\xe3\xd0\xcf\xb8\x19";
pub const VID_IPSEC_NAT_T: &[u8] = b"\x90\xcb\x80\x91\x3e\xbb\x69\x6e\x08\x63\x81\xb5\xec\x42\x7b\x1f";
pub const VID_MS_NT5: &[u8] = b"\x1e\x2b\x51\x69\x05\x99\x1c\x7d\x7c\x96\xfc\xbf\xb5\x87\xe4\x61\x00\x00\x00\x04";

bitflags! {
    /// Represents a set of flags.
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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProtocolId {
    Reserved,
    #[default]
    Isakmp,
    IpsecAh,
    IpsecEsp,
    Ipcomp,
    Other(u8),
}

impl From<u8> for ProtocolId {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Reserved,
            1 => Self::Isakmp,
            2 => Self::IpsecAh,
            3 => Self::IpsecEsp,
            4 => Self::Ipcomp,
            other => Self::Other(other),
        }
    }
}

impl From<ProtocolId> for u8 {
    fn from(value: ProtocolId) -> Self {
        match value {
            ProtocolId::Reserved => 0,
            ProtocolId::Isakmp => 1,
            ProtocolId::IpsecAh => 2,
            ProtocolId::IpsecEsp => 3,
            ProtocolId::Ipcomp => 4,
            ProtocolId::Other(u) => u,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TransformId {
    Reserved,
    #[default]
    KeyIke,
    Esp3Des,
    EspAesCbc,
    Other(u8),
}

impl From<u8> for TransformId {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Reserved,
            1 => Self::KeyIke,
            3 => Self::Esp3Des,
            12 => Self::EspAesCbc,
            other => Self::Other(other),
        }
    }
}

impl From<TransformId> for u8 {
    fn from(value: TransformId) -> Self {
        match value {
            TransformId::Reserved => 0,
            TransformId::KeyIke => 1,
            TransformId::Esp3Des => 3,
            TransformId::EspAesCbc => 12,
            TransformId::Other(u) => u,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IkeEncryptionAlgorithm {
    #[default]
    AesCbc,
    DesEde3Cbc,
    Other(u16),
}

impl From<u16> for IkeEncryptionAlgorithm {
    fn from(value: u16) -> Self {
        match value {
            7 => Self::AesCbc,
            5 => Self::DesEde3Cbc,
            other => Self::Other(other),
        }
    }
}

impl From<IkeEncryptionAlgorithm> for u16 {
    fn from(value: IkeEncryptionAlgorithm) -> Self {
        match value {
            IkeEncryptionAlgorithm::AesCbc => 7,
            IkeEncryptionAlgorithm::DesEde3Cbc => 5,
            IkeEncryptionAlgorithm::Other(u) => u,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IkeGroupDescription {
    #[default]
    Oakley2,
    Oakley14,
    Other(u16),
}

impl From<u16> for IkeGroupDescription {
    fn from(value: u16) -> Self {
        match value {
            2 => Self::Oakley2,
            14 => Self::Oakley14,
            other => Self::Other(other),
        }
    }
}

impl From<IkeGroupDescription> for u16 {
    fn from(value: IkeGroupDescription) -> Self {
        match value {
            IkeGroupDescription::Oakley2 => 2,
            IkeGroupDescription::Oakley14 => 14,
            IkeGroupDescription::Other(u) => u,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IkeHashAlgorithm {
    Sha,
    #[default]
    Sha256,
    Other(u16),
}

impl From<u16> for IkeHashAlgorithm {
    fn from(value: u16) -> Self {
        match value {
            2 => Self::Sha,
            4 => Self::Sha256,
            other => Self::Other(other),
        }
    }
}

impl From<IkeHashAlgorithm> for u16 {
    fn from(value: IkeHashAlgorithm) -> Self {
        match value {
            IkeHashAlgorithm::Sha => 2,
            IkeHashAlgorithm::Sha256 => 4,
            IkeHashAlgorithm::Other(u) => u,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LifeType {
    #[default]
    Seconds,
    Other(u16),
}

impl From<u16> for LifeType {
    fn from(value: u16) -> Self {
        match value {
            1 => Self::Seconds,
            other => Self::Other(other),
        }
    }
}

impl From<LifeType> for u16 {
    fn from(value: LifeType) -> Self {
        match value {
            LifeType::Seconds => 1,
            LifeType::Other(u) => u,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IkeAuthMethod {
    RsaSignature,
    #[default]
    HybridInitRsa,
    Other(u16),
}

impl From<u16> for IkeAuthMethod {
    fn from(value: u16) -> Self {
        match value {
            3 => Self::RsaSignature,
            64221 => Self::HybridInitRsa,
            other => Self::Other(other),
        }
    }
}

impl From<IkeAuthMethod> for u16 {
    fn from(value: IkeAuthMethod) -> Self {
        match value {
            IkeAuthMethod::RsaSignature => 3,
            IkeAuthMethod::HybridInitRsa => 64221,
            IkeAuthMethod::Other(u) => u,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EspAuthAlgorithm {
    HmacSha96,
    HmacSha160,
    #[default]
    HmacSha256,
    HmacSha256v2,
    Other(u16),
}

impl EspAuthAlgorithm {
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

impl From<u16> for EspAuthAlgorithm {
    fn from(value: u16) -> Self {
        match value {
            2 => Self::HmacSha96,
            5 => Self::HmacSha256,
            7 => Self::HmacSha160,
            12 => Self::HmacSha256v2,
            other => Self::Other(other),
        }
    }
}

impl From<EspAuthAlgorithm> for u16 {
    fn from(value: EspAuthAlgorithm) -> Self {
        match value {
            EspAuthAlgorithm::HmacSha96 => 2,
            EspAuthAlgorithm::HmacSha256 => 5,
            EspAuthAlgorithm::HmacSha160 => 7,
            EspAuthAlgorithm::HmacSha256v2 => 12,
            EspAuthAlgorithm::Other(u) => u,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EspEncapMode {
    #[default]
    UdpTunnel,
    CheckpointEspInUdp,
    Other(u16),
}

impl From<u16> for EspEncapMode {
    fn from(value: u16) -> Self {
        match value {
            3 => Self::UdpTunnel,
            0xf003 => Self::CheckpointEspInUdp,
            other => Self::Other(other),
        }
    }
}

impl From<EspEncapMode> for u16 {
    fn from(value: EspEncapMode) -> Self {
        match value {
            EspEncapMode::UdpTunnel => 3,
            EspEncapMode::CheckpointEspInUdp => 0xf003,
            EspEncapMode::Other(u) => u,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IdentityType {
    #[default]
    Ipv4Address,
    Ipv4Subnet,
    UserFqdn,
    DerAsn1Dn,
    Other(u8),
}

impl From<u8> for IdentityType {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::Ipv4Address,
            3 => Self::UserFqdn,
            4 => Self::Ipv4Subnet,
            9 => Self::DerAsn1Dn,
            other => Self::Other(other),
        }
    }
}

impl From<IdentityType> for u8 {
    fn from(value: IdentityType) -> Self {
        match value {
            IdentityType::Ipv4Address => 1,
            IdentityType::UserFqdn => 3,
            IdentityType::Ipv4Subnet => 4,
            IdentityType::DerAsn1Dn => 9,
            IdentityType::Other(u) => u,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NotifyMessageType {
    #[default]
    CccAuth,
    Other(u16),
}

impl From<u16> for NotifyMessageType {
    fn from(value: u16) -> Self {
        match value {
            0x8004 => Self::CccAuth,
            other => Self::Other(other),
        }
    }
}

impl From<NotifyMessageType> for u16 {
    fn from(value: NotifyMessageType) -> Self {
        match value {
            NotifyMessageType::CccAuth => 0x8004,
            NotifyMessageType::Other(u) => u,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UserAuthType {
    #[default]
    Generic,
    Other(u16),
}

impl From<u16> for UserAuthType {
    fn from(value: u16) -> Self {
        match value {
            0 => Self::Generic,
            other => Self::Other(other),
        }
    }
}

impl From<UserAuthType> for u16 {
    fn from(value: UserAuthType) -> Self {
        match value {
            UserAuthType::Generic => 0,
            UserAuthType::Other(u) => u,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PayloadType {
    None,
    SecurityAssociation,
    Proposal,
    Transform,
    KeyExchange,
    Identification,
    Certificate,
    CertificateRequest,
    Hash,
    Signature,
    Nonce,
    Notification,
    Delete,
    VendorId,
    Attributes,
    Natd,
    Other(u8),
}

impl From<PayloadType> for u8 {
    fn from(value: PayloadType) -> Self {
        match value {
            PayloadType::None => 0,
            PayloadType::SecurityAssociation => 1,
            PayloadType::Proposal => 2,
            PayloadType::Transform => 3,
            PayloadType::KeyExchange => 4,
            PayloadType::Identification => 5,
            PayloadType::Certificate => 6,
            PayloadType::CertificateRequest => 7,
            PayloadType::Hash => 8,
            PayloadType::Signature => 9,
            PayloadType::Nonce => 10,
            PayloadType::Notification => 11,
            PayloadType::Delete => 12,
            PayloadType::VendorId => 13,
            PayloadType::Attributes => 14,
            PayloadType::Natd => 20,
            PayloadType::Other(v) => v,
        }
    }
}

impl From<u8> for PayloadType {
    fn from(value: u8) -> Self {
        match value {
            0 => PayloadType::None,
            1 => PayloadType::SecurityAssociation,
            2 => PayloadType::Proposal,
            3 => PayloadType::Transform,
            4 => PayloadType::KeyExchange,
            5 => PayloadType::Identification,
            6 => PayloadType::Certificate,
            7 => PayloadType::CertificateRequest,
            8 => PayloadType::Hash,
            9 => PayloadType::Signature,
            10 => PayloadType::Nonce,
            11 => PayloadType::Notification,
            12 => PayloadType::Delete,
            13 => PayloadType::VendorId,
            14 => PayloadType::Attributes,
            20 => PayloadType::Natd,
            v => PayloadType::Other(v),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ExchangeType {
    None,
    Base,
    IdentityProtection,
    AuthenticationOnly,
    Aggressive,
    Informational,
    Transaction,
    Quick,
    Other(u8),
}

impl From<ExchangeType> for u8 {
    fn from(value: ExchangeType) -> Self {
        match value {
            ExchangeType::None => 0,
            ExchangeType::Base => 1,
            ExchangeType::IdentityProtection => 2,
            ExchangeType::AuthenticationOnly => 3,
            ExchangeType::Aggressive => 4,
            ExchangeType::Informational => 5,
            ExchangeType::Transaction => 6,
            ExchangeType::Quick => 32,
            ExchangeType::Other(v) => v,
        }
    }
}

impl From<u8> for ExchangeType {
    fn from(value: u8) -> Self {
        match value {
            0 => ExchangeType::None,
            1 => ExchangeType::Base,
            2 => ExchangeType::IdentityProtection,
            3 => ExchangeType::AuthenticationOnly,
            4 => ExchangeType::Aggressive,
            5 => ExchangeType::Informational,
            6 => ExchangeType::Transaction,
            32 => ExchangeType::Quick,
            other => ExchangeType::Other(other),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IkeAttributeType {
    Unknown,
    EncryptionAlgorithm,
    HashAlgorithm,
    AuthenticationMethod,
    GroupDescription,
    GroupType,
    GroupPrime,
    GroupGeneratorOne,
    GroupGeneratorTwo,
    GroupCurveA,
    GroupCurveB,
    LifeType,
    LifeDuration,
    Prf,
    KeyLength,
    FieldSize,
    GroupOrder,
    Other(u16),
}

impl From<IkeAttributeType> for u16 {
    fn from(value: IkeAttributeType) -> Self {
        match value {
            IkeAttributeType::Unknown => 0,
            IkeAttributeType::EncryptionAlgorithm => 1,
            IkeAttributeType::HashAlgorithm => 2,
            IkeAttributeType::AuthenticationMethod => 3,
            IkeAttributeType::GroupDescription => 4,
            IkeAttributeType::GroupType => 5,
            IkeAttributeType::GroupPrime => 6,
            IkeAttributeType::GroupGeneratorOne => 7,
            IkeAttributeType::GroupGeneratorTwo => 8,
            IkeAttributeType::GroupCurveA => 9,
            IkeAttributeType::GroupCurveB => 10,
            IkeAttributeType::LifeType => 11,
            IkeAttributeType::LifeDuration => 12,
            IkeAttributeType::Prf => 13,
            IkeAttributeType::KeyLength => 14,
            IkeAttributeType::FieldSize => 15,
            IkeAttributeType::GroupOrder => 16,
            IkeAttributeType::Other(v) => v,
        }
    }
}

impl From<u16> for IkeAttributeType {
    fn from(value: u16) -> Self {
        match value {
            0 => IkeAttributeType::Unknown,
            1 => IkeAttributeType::EncryptionAlgorithm,
            2 => IkeAttributeType::HashAlgorithm,
            3 => IkeAttributeType::AuthenticationMethod,
            4 => IkeAttributeType::GroupDescription,
            5 => IkeAttributeType::GroupType,
            6 => IkeAttributeType::GroupPrime,
            7 => IkeAttributeType::GroupGeneratorOne,
            8 => IkeAttributeType::GroupGeneratorTwo,
            9 => IkeAttributeType::GroupCurveA,
            10 => IkeAttributeType::GroupCurveB,
            11 => IkeAttributeType::LifeType,
            12 => IkeAttributeType::LifeDuration,
            13 => IkeAttributeType::Prf,
            14 => IkeAttributeType::KeyLength,
            15 => IkeAttributeType::FieldSize,
            16 => IkeAttributeType::GroupOrder,
            v => IkeAttributeType::Other(v),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EspAttributeType {
    Unknown,
    LifeType,
    LifeDuration,
    EncapsulationMode,
    AuthenticationAlgorithm,
    KeyLength,
    Other(u16),
}

impl From<EspAttributeType> for u16 {
    fn from(value: EspAttributeType) -> Self {
        match value {
            EspAttributeType::Unknown => 0,
            EspAttributeType::LifeType => 1,
            EspAttributeType::LifeDuration => 2,
            EspAttributeType::EncapsulationMode => 4,
            EspAttributeType::AuthenticationAlgorithm => 5,
            EspAttributeType::KeyLength => 6,
            EspAttributeType::Other(v) => v,
        }
    }
}

impl From<u16> for EspAttributeType {
    fn from(value: u16) -> Self {
        match value {
            0 => EspAttributeType::Unknown,
            1 => EspAttributeType::LifeType,
            2 => EspAttributeType::LifeDuration,
            4 => EspAttributeType::EncapsulationMode,
            5 => EspAttributeType::AuthenticationAlgorithm,
            6 => EspAttributeType::KeyLength,
            v => EspAttributeType::Other(v),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConfigAttributeType {
    Ipv4Address,
    Ipv4Netmask,
    Ipv4Dns,
    AddressExpiry,
    AuthType,
    UserName,
    UserPassword,
    Passcode,
    Message,
    Challenge,
    Domain,
    Status,
    NextPin,
    Answer,
    InternalDomainName,
    MacAddress,
    CccSessionId,
    Other(u16),
}

impl From<ConfigAttributeType> for u16 {
    fn from(value: ConfigAttributeType) -> Self {
        match value {
            ConfigAttributeType::Ipv4Address => 1,
            ConfigAttributeType::Ipv4Netmask => 2,
            ConfigAttributeType::Ipv4Dns => 3,
            ConfigAttributeType::AddressExpiry => 5,
            ConfigAttributeType::AuthType => 13,
            ConfigAttributeType::UserName => 14,
            ConfigAttributeType::UserPassword => 15,
            ConfigAttributeType::Passcode => 16,
            ConfigAttributeType::Message => 17,
            ConfigAttributeType::Challenge => 18,
            ConfigAttributeType::Domain => 19,
            ConfigAttributeType::Status => 20,
            ConfigAttributeType::NextPin => 21,
            ConfigAttributeType::Answer => 22,
            ConfigAttributeType::InternalDomainName => 0x4003,
            ConfigAttributeType::MacAddress => 0x4004,
            ConfigAttributeType::CccSessionId => 0x4045,

            ConfigAttributeType::Other(v) => v,
        }
    }
}

impl From<u16> for ConfigAttributeType {
    fn from(value: u16) -> Self {
        match value {
            1 => ConfigAttributeType::Ipv4Address,
            2 => ConfigAttributeType::Ipv4Netmask,
            3 => ConfigAttributeType::Ipv4Dns,
            5 => ConfigAttributeType::AddressExpiry,
            13 => ConfigAttributeType::AuthType,
            14 => ConfigAttributeType::UserName,
            15 => ConfigAttributeType::UserPassword,
            16 => ConfigAttributeType::Passcode,
            17 => ConfigAttributeType::Message,
            18 => ConfigAttributeType::Challenge,
            19 => ConfigAttributeType::Domain,
            20 => ConfigAttributeType::Status,
            21 => ConfigAttributeType::NextPin,
            22 => ConfigAttributeType::Answer,
            0x4003 => ConfigAttributeType::InternalDomainName,
            0x4004 => ConfigAttributeType::MacAddress,
            0x4045 => ConfigAttributeType::CccSessionId,
            v => ConfigAttributeType::Other(v),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum AttributeValue {
    Short(u16),
    Long(Bytes),
}

impl AttributeValue {
    pub fn len(&self) -> usize {
        match self {
            AttributeValue::Short(_) => 2,
            AttributeValue::Long(ref v) => v.len(),
        }
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DataAttribute {
    pub attribute_type: u16,
    pub value: AttributeValue,
}

impl DataAttribute {
    pub fn short(attribute_type: u16, value: u16) -> Self {
        Self {
            attribute_type,
            value: AttributeValue::Short(value),
        }
    }

    pub fn long(attribute_type: u16, value: Bytes) -> Self {
        Self {
            attribute_type,
            value: AttributeValue::Long(value),
        }
    }

    pub fn as_short(&self) -> Option<u16> {
        match self.value {
            AttributeValue::Short(v) => Some(v),
            AttributeValue::Long(_) => None,
        }
    }

    pub fn as_long(&self) -> Option<&Bytes> {
        match self.value {
            AttributeValue::Short(_) => None,
            AttributeValue::Long(ref v) => Some(v),
        }
    }

    pub fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(self.len());
        match self.value {
            AttributeValue::Short(v) => {
                buf.put_u16(self.attribute_type | 0x8000);
                buf.put_u16(v);
            }
            AttributeValue::Long(ref v) => {
                buf.put_u16(self.attribute_type);
                buf.put_u16(v.len() as u16);
                buf.put_slice(v);
            }
        }
        buf.freeze()
    }
    pub fn len(&self) -> usize {
        4 + if self.value.len() == 2 { 0 } else { self.value.len() }
    }

    pub fn is_empty(&self) -> bool {
        false
    }

    pub fn parse<R: Read>(reader: &mut R) -> anyhow::Result<Self> {
        let attribute_type = reader.read_u16::<BigEndian>()?;
        let length_or_value = reader.read_u16::<BigEndian>()?;
        if (attribute_type & 0x8000) != 0 {
            Ok(Self {
                attribute_type: attribute_type & 0x7fff,
                value: AttributeValue::Short(length_or_value),
            })
        } else {
            let mut data = vec![0u8; length_or_value as _];
            reader.read_exact(&mut data)?;
            Ok(Self {
                attribute_type,
                value: AttributeValue::Long(data.into()),
            })
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CertificateType {
    #[default]
    None,
    Pkcs7WrappedX509,
    Pgp,
    DnsSignedKey,
    X509ForSignature,
    X509ForKeyExchange,
    KerberosTokens,
    Crl,
    Arl,
    Spki,
    X509ForAttribute,
    Reserved(u8),
}

impl From<u8> for CertificateType {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::None,
            1 => Self::Pkcs7WrappedX509,
            2 => Self::Pgp,
            3 => Self::DnsSignedKey,
            4 => Self::X509ForSignature,
            5 => Self::X509ForKeyExchange,
            6 => Self::KerberosTokens,
            7 => Self::Crl,
            8 => Self::Arl,
            9 => Self::Spki,
            10 => Self::X509ForAttribute,
            other => Self::Reserved(other),
        }
    }
}

impl From<CertificateType> for u8 {
    fn from(value: CertificateType) -> Self {
        match value {
            CertificateType::None => 0,
            CertificateType::Pkcs7WrappedX509 => 1,
            CertificateType::Pgp => 2,
            CertificateType::DnsSignedKey => 3,
            CertificateType::X509ForSignature => 4,
            CertificateType::X509ForKeyExchange => 5,
            CertificateType::KerberosTokens => 6,
            CertificateType::Crl => 7,
            CertificateType::Arl => 8,
            CertificateType::Spki => 9,
            CertificateType::X509ForAttribute => 10,
            CertificateType::Reserved(v) => v,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AttributesPayloadType {
    #[default]
    Request,
    Reply,
    Set,
    Ack,
    Reserved(u8),
}

impl From<u8> for AttributesPayloadType {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::Request,
            2 => Self::Reply,
            3 => Self::Set,
            4 => Self::Ack,
            other => Self::Reserved(other),
        }
    }
}

impl From<AttributesPayloadType> for u8 {
    fn from(value: AttributesPayloadType) -> Self {
        match value {
            AttributesPayloadType::Request => 1,
            AttributesPayloadType::Reply => 2,
            AttributesPayloadType::Set => 3,
            AttributesPayloadType::Ack => 4,
            AttributesPayloadType::Reserved(v) => v,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub enum Identity {
    #[default]
    None,
    Pkcs12 {
        path: PathBuf,
        password: String,
    },
    Pkcs8 {
        path: PathBuf,
    },
    Pkcs11 {
        driver_path: PathBuf,
        pin: String,
        key_id: Option<Bytes>,
    },
}

#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct EspCryptMaterial {
    pub spi: u32,
    pub sk_e: Bytes,
    pub sk_a: Bytes,
    pub transform_id: TransformId,
    pub auth_algorithm: EspAuthAlgorithm,
}

#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct SaProposal {
    pub cookie_r: u64,
    pub sa_bytes: Bytes,
    pub hash_alg: IkeHashAlgorithm,
    pub enc_alg: IkeEncryptionAlgorithm,
    pub key_len: usize,
    pub group: IkeGroupDescription,
}

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
    pub auth_blob: Bytes,
    pub verify_certs: bool,
    pub ca_certs: Vec<PathBuf>,
    pub with_mfa: bool,
}
