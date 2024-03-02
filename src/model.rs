use std::io::Read;

use bitflags::bitflags;
use byteorder::{BigEndian, ReadBytesExt};
use bytes::{BufMut, Bytes, BytesMut};

pub const CHECKPOINT_VID: &[u8] = b"defb99e69a9f1f6e06f15006b1f166ae";
pub const NATT_VID: &[u8] = b"4a131c81070358455c5728f20e95452f";
pub const EXT_VID_WITH_FLAGS: &[u8] = b"3cf187b2474029ea46ac7fd0eaf289f500000001";

bitflags! {
    /// Represents a set of flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct IsakmpFlags: u8 {
        const ENCRYPTION = 0b00000001;
        const COMMIT = 0b00000010;
        const AUTHENTICATION = 0b00000100;
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct SituationFlags: u32 {
        const IDENTITY_ONLY = 0b00000001;
        const SECRECY = 0b00000010;
        const INTEGRITY = 0b00000100;
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
    EspAesCbc,
    Other(u8),
}

impl From<u8> for TransformId {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Reserved,
            1 => Self::KeyIke,
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
            TransformId::EspAesCbc => 12,
            TransformId::Other(u) => u,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IkeEncryptionAlgorithm {
    #[default]
    AesCbc,
    Other(u16),
}

impl From<u16> for IkeEncryptionAlgorithm {
    fn from(value: u16) -> Self {
        match value {
            7 => Self::AesCbc,
            other => Self::Other(other),
        }
    }
}

impl From<IkeEncryptionAlgorithm> for u16 {
    fn from(value: IkeEncryptionAlgorithm) -> Self {
        match value {
            IkeEncryptionAlgorithm::AesCbc => 7,
            IkeEncryptionAlgorithm::Other(u) => u,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IkeGroupDescription {
    #[default]
    Oakley2,
    Other(u16),
}

impl From<u16> for IkeGroupDescription {
    fn from(value: u16) -> Self {
        match value {
            2 => Self::Oakley2,
            other => Self::Other(other),
        }
    }
}

impl From<IkeGroupDescription> for u16 {
    fn from(value: IkeGroupDescription) -> Self {
        match value {
            IkeGroupDescription::Oakley2 => 2,
            IkeGroupDescription::Other(u) => u,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IkeHashAlgorithm {
    #[default]
    Sha256,
    Other(u16),
}

impl From<u16> for IkeHashAlgorithm {
    fn from(value: u16) -> Self {
        match value {
            4 => Self::Sha256,
            other => Self::Other(other),
        }
    }
}

impl From<IkeHashAlgorithm> for u16 {
    fn from(value: IkeHashAlgorithm) -> Self {
        match value {
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
    #[default]
    HybridInitRsa,
    Other(u16),
}

impl From<u16> for IkeAuthMethod {
    fn from(value: u16) -> Self {
        match value {
            64221 => Self::HybridInitRsa,
            other => Self::Other(other),
        }
    }
}

impl From<IkeAuthMethod> for u16 {
    fn from(value: IkeAuthMethod) -> Self {
        match value {
            IkeAuthMethod::HybridInitRsa => 64221,
            IkeAuthMethod::Other(u) => u,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EspAuthAlgorithm {
    #[default]
    HmacSha256,
    Other(u16),
}

impl From<u16> for EspAuthAlgorithm {
    fn from(value: u16) -> Self {
        match value {
            5 => Self::HmacSha256,
            other => Self::Other(other),
        }
    }
}

impl From<EspAuthAlgorithm> for u16 {
    fn from(value: EspAuthAlgorithm) -> Self {
        match value {
            EspAuthAlgorithm::HmacSha256 => 5,
            EspAuthAlgorithm::Other(u) => u,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EspEncapMode {
    #[default]
    UdpTunnel,
    Other(u16),
}

impl From<u16> for EspEncapMode {
    fn from(value: u16) -> Self {
        match value {
            3 => Self::UdpTunnel,
            other => Self::Other(other),
        }
    }
}

impl From<EspEncapMode> for u16 {
    fn from(value: EspEncapMode) -> Self {
        match value {
            EspEncapMode::UdpTunnel => 3,
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
    Other(u8),
}

impl From<u8> for IdentityType {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::Ipv4Address,
            3 => Self::UserFqdn,
            4 => Self::Ipv4Subnet,
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
        4 + if self.value.len() == 2 {
            0
        } else {
            self.value.len()
        }
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
