//! IKEv2 payload structures per RFC 7296 §3.
//!
//! Every payload is framed by the generic header in [`crate::payload`], so the
//! structures here model only the body: `len` and `to_bytes` exclude those four
//! bytes, matching [`crate::ikev1::payload`].

use std::io::{Cursor, Read};

use anyhow::Context;
use byteorder::{BigEndian, ReadBytesExt};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use tracing::trace;

use crate::{
    ikev2::model::{
        ATTRIBUTE_TYPE_KEY_LENGTH, AuthMethod, CertificateEncoding, ConfigurationAttributeType, ConfigurationType,
        DhGroup, EncryptionAlgorithm, ExtendedSequenceNumbers, IdentificationType, IntegrityAlgorithm, NotifyType,
        PayloadType, ProtocolId, PseudoRandomFunction, TrafficSelectorType, TransformType,
    },
    model::DataAttribute,
    payload::{BasicPayload, PayloadLike, read_bytes, read_next_payload, read_to_end, write_payload},
};

/// `Last Substruc` value for a proposal followed by another (RFC 7296 §3.3).
const LAST_SUBSTRUC_PROPOSAL: u8 = 2;
/// `Last Substruc` value for a transform followed by another.
const LAST_SUBSTRUC_TRANSFORM: u8 = 3;

/// One transform inside a proposal, RFC 7296 §3.3.2. The meaning of
/// `transform_id` depends on `transform_type`, so it is kept as the raw number
/// with typed accessors.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Transform {
    pub transform_type: TransformType,
    pub transform_id: u16,
    pub attributes: Vec<DataAttribute>,
}

impl Transform {
    pub fn new(transform_type: TransformType, transform_id: u16) -> Self {
        Self {
            transform_type,
            transform_id,
            attributes: Vec::new(),
        }
    }

    pub fn encryption(algorithm: EncryptionAlgorithm, key_len: Option<u16>) -> Self {
        let mut transform = Self::new(TransformType::EncryptionAlgorithm, algorithm.into());
        if let Some(key_len) = key_len {
            transform
                .attributes
                .push(DataAttribute::short(ATTRIBUTE_TYPE_KEY_LENGTH, key_len * 8));
        }
        transform
    }

    pub fn prf(algorithm: PseudoRandomFunction) -> Self {
        Self::new(TransformType::PseudoRandomFunction, algorithm.into())
    }

    pub fn integrity(algorithm: IntegrityAlgorithm) -> Self {
        Self::new(TransformType::IntegrityAlgorithm, algorithm.into())
    }

    pub fn dh_group(group: DhGroup) -> Self {
        Self::new(TransformType::DiffieHellmanGroup, group.into())
    }

    pub fn esn(esn: ExtendedSequenceNumbers) -> Self {
        Self::new(TransformType::ExtendedSequenceNumbers, esn.into())
    }

    pub fn as_encryption(&self) -> Option<EncryptionAlgorithm> {
        (self.transform_type == TransformType::EncryptionAlgorithm).then(|| self.transform_id.into())
    }

    pub fn as_prf(&self) -> Option<PseudoRandomFunction> {
        (self.transform_type == TransformType::PseudoRandomFunction).then(|| self.transform_id.into())
    }

    pub fn as_integrity(&self) -> Option<IntegrityAlgorithm> {
        (self.transform_type == TransformType::IntegrityAlgorithm).then(|| self.transform_id.into())
    }

    pub fn as_dh_group(&self) -> Option<DhGroup> {
        (self.transform_type == TransformType::DiffieHellmanGroup).then(|| self.transform_id.into())
    }

    pub fn as_esn(&self) -> Option<ExtendedSequenceNumbers> {
        (self.transform_type == TransformType::ExtendedSequenceNumbers).then(|| self.transform_id.into())
    }

    /// Negotiated key length in bytes, from the Key Length attribute.
    pub fn key_len(&self) -> Option<usize> {
        self.attributes
            .iter()
            .find(|a| a.attribute_type == ATTRIBUTE_TYPE_KEY_LENGTH)
            .and_then(|a| a.as_short())
            .map(|bits| bits as usize / 8)
    }

    fn to_bytes(&self, last: bool) -> Bytes {
        let mut buf = BytesMut::with_capacity(self.len());
        buf.put_u8(if last { 0 } else { LAST_SUBSTRUC_TRANSFORM });
        buf.put_u8(0);
        buf.put_u16(self.len() as u16);
        buf.put_u8(self.transform_type.into());
        buf.put_u8(0);
        buf.put_u16(self.transform_id);
        for attribute in &self.attributes {
            buf.put_slice(&attribute.to_bytes());
        }
        buf.freeze()
    }

    /// Full length including the 8-byte transform header.
    pub fn len(&self) -> usize {
        self.attributes.iter().fold(8, |len, a| len + a.len())
    }

    pub fn is_empty(&self) -> bool {
        false
    }

    /// Returns the transform and whether more follow.
    fn parse<R: Read>(reader: &mut R) -> anyhow::Result<(Self, bool)> {
        let last_substruc = reader.read_u8()?;
        reader.read_u8()?;
        let length = reader.read_u16::<BigEndian>()?;
        let length = length.checked_sub(8).context("Transform length below header size")?;

        let transform_type = reader.read_u8()?.into();
        reader.read_u8()?;
        let transform_id = reader.read_u16::<BigEndian>()?;

        let mut cursor = Cursor::new(read_bytes(reader, length as usize)?);
        let mut attributes = Vec::new();
        while cursor.has_remaining() {
            attributes.push(DataAttribute::parse(&mut cursor)?);
        }

        Ok((
            Self {
                transform_type,
                transform_id,
                attributes,
            },
            last_substruc != 0,
        ))
    }
}

/// Proposal substructure, RFC 7296 §3.3.1.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Proposal {
    pub proposal_num: u8,
    pub protocol_id: ProtocolId,
    /// Empty for the initial IKE proposal, 4 octets for an ESP/AH child SA.
    pub spi: Bytes,
    pub transforms: Vec<Transform>,
}

impl Proposal {
    pub fn find(&self, transform_type: TransformType) -> Option<&Transform> {
        self.transforms.iter().find(|t| t.transform_type == transform_type)
    }

    fn to_bytes(&self, last: bool) -> Bytes {
        let mut buf = BytesMut::with_capacity(self.len());
        buf.put_u8(if last { 0 } else { LAST_SUBSTRUC_PROPOSAL });
        buf.put_u8(0);
        buf.put_u16(self.len() as u16);
        buf.put_u8(self.proposal_num);
        buf.put_u8(self.protocol_id.into());
        buf.put_u8(self.spi.len() as u8);
        buf.put_u8(self.transforms.len() as u8);
        buf.put_slice(&self.spi);

        for (i, transform) in self.transforms.iter().enumerate() {
            buf.put_slice(&transform.to_bytes(i + 1 == self.transforms.len()));
        }
        buf.freeze()
    }

    /// Full length including the 8-byte proposal header.
    pub fn len(&self) -> usize {
        self.transforms.iter().fold(8 + self.spi.len(), |len, t| len + t.len())
    }

    pub fn is_empty(&self) -> bool {
        false
    }

    /// Returns the proposal and whether more follow.
    fn parse<R: Read>(reader: &mut R) -> anyhow::Result<(Self, bool)> {
        let last_substruc = reader.read_u8()?;
        reader.read_u8()?;
        let length = reader.read_u16::<BigEndian>()?;
        let length = length.checked_sub(8).context("Proposal length below header size")?;

        let proposal_num = reader.read_u8()?;
        let protocol_id = reader.read_u8()?.into();
        let spi_size = reader.read_u8()?;
        let num_transforms = reader.read_u8()?;

        let mut cursor = Cursor::new(read_bytes(reader, length as usize)?);
        let spi = read_bytes(&mut cursor, spi_size as usize)?;

        let mut transforms = Vec::with_capacity(num_transforms as usize);
        while cursor.has_remaining() {
            let (transform, more) = Transform::parse(&mut cursor)?;
            transforms.push(transform);
            if !more {
                break;
            }
        }

        if transforms.len() != num_transforms as usize {
            anyhow::bail!(
                "Proposal declares {} transforms but carries {}",
                num_transforms,
                transforms.len()
            );
        }

        Ok((
            Self {
                proposal_num,
                protocol_id,
                spi,
                transforms,
            },
            last_substruc != 0,
        ))
    }
}

/// SA payload, RFC 7296 §3.3. Unlike IKEv1 there is no DOI or situation, and
/// proposals are substructures rather than nested payloads.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct SecurityAssociationPayload {
    pub proposals: Vec<Proposal>,
}

impl PayloadLike for SecurityAssociationPayload {
    fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(self.len());
        for (i, proposal) in self.proposals.iter().enumerate() {
            buf.put_slice(&proposal.to_bytes(i + 1 == self.proposals.len()));
        }
        buf.freeze()
    }

    fn len(&self) -> usize {
        self.proposals.iter().map(|p| p.len()).sum()
    }

    fn parse<R: Read>(reader: &mut R) -> anyhow::Result<Self> {
        let mut cursor = Cursor::new(read_to_end(reader)?);
        let mut proposals = Vec::new();

        while cursor.has_remaining() {
            let (proposal, more) = Proposal::parse(&mut cursor)?;
            proposals.push(proposal);
            if !more {
                break;
            }
        }

        Ok(Self { proposals })
    }
}

/// KE payload, RFC 7296 §3.4.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct KeyExchangePayload {
    pub dh_group: DhGroup,
    pub data: Bytes,
}

impl PayloadLike for KeyExchangePayload {
    fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(self.len());
        buf.put_u16(self.dh_group.into());
        buf.put_u16(0);
        buf.put_slice(&self.data);
        buf.freeze()
    }

    fn len(&self) -> usize {
        4 + self.data.len()
    }

    fn parse<R: Read>(reader: &mut R) -> anyhow::Result<Self> {
        let dh_group = reader.read_u16::<BigEndian>()?.into();
        reader.read_u16::<BigEndian>()?;
        Ok(Self {
            dh_group,
            data: read_to_end(reader)?,
        })
    }
}

/// IDi / IDr payload, RFC 7296 §3.5. The IKEv1 protocol and port fields are
/// reserved in IKEv2.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct IdentificationPayload {
    pub id_type: IdentificationType,
    pub data: Bytes,
}

impl PayloadLike for IdentificationPayload {
    fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(self.len());
        buf.put_u8(self.id_type.into());
        buf.put_u8(0);
        buf.put_u16(0);
        buf.put_slice(&self.data);
        buf.freeze()
    }

    fn len(&self) -> usize {
        4 + self.data.len()
    }

    fn parse<R: Read>(reader: &mut R) -> anyhow::Result<Self> {
        let id_type = reader.read_u8()?.into();
        reader.read_u8()?;
        reader.read_u16::<BigEndian>()?;
        Ok(Self {
            id_type,
            data: read_to_end(reader)?,
        })
    }
}

/// CERT / CERTREQ payload, RFC 7296 §3.6 and §3.7.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CertificatePayload {
    pub encoding: CertificateEncoding,
    pub data: Bytes,
}

impl PayloadLike for CertificatePayload {
    fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(self.len());
        buf.put_u8(self.encoding.into());
        buf.put_slice(&self.data);
        buf.freeze()
    }

    fn len(&self) -> usize {
        1 + self.data.len()
    }

    fn parse<R: Read>(reader: &mut R) -> anyhow::Result<Self> {
        Ok(Self {
            encoding: reader.read_u8()?.into(),
            data: read_to_end(reader)?,
        })
    }
}

/// AUTH payload, RFC 7296 §3.8.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AuthenticationPayload {
    pub auth_method: AuthMethod,
    pub data: Bytes,
}

impl PayloadLike for AuthenticationPayload {
    fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(self.len());
        buf.put_u8(self.auth_method.into());
        buf.put_u8(0);
        buf.put_u16(0);
        buf.put_slice(&self.data);
        buf.freeze()
    }

    fn len(&self) -> usize {
        4 + self.data.len()
    }

    fn parse<R: Read>(reader: &mut R) -> anyhow::Result<Self> {
        let auth_method = reader.read_u8()?.into();
        reader.read_u8()?;
        reader.read_u16::<BigEndian>()?;
        Ok(Self {
            auth_method,
            data: read_to_end(reader)?,
        })
    }
}

/// N payload, RFC 7296 §3.10.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NotifyPayload {
    pub protocol_id: ProtocolId,
    pub spi: Bytes,
    pub notify_type: NotifyType,
    pub data: Bytes,
}

impl NotifyPayload {
    pub fn new(notify_type: NotifyType, data: Bytes) -> Self {
        Self {
            protocol_id: ProtocolId::None,
            spi: Bytes::new(),
            notify_type,
            data,
        }
    }
}

impl PayloadLike for NotifyPayload {
    fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(self.len());
        buf.put_u8(self.protocol_id.into());
        buf.put_u8(self.spi.len() as u8);
        buf.put_u16(self.notify_type.into());
        buf.put_slice(&self.spi);
        buf.put_slice(&self.data);
        buf.freeze()
    }

    fn len(&self) -> usize {
        4 + self.spi.len() + self.data.len()
    }

    fn parse<R: Read>(reader: &mut R) -> anyhow::Result<Self> {
        let protocol_id = reader.read_u8()?.into();
        let spi_size = reader.read_u8()?;
        let notify_type = reader.read_u16::<BigEndian>()?.into();

        Ok(Self {
            protocol_id,
            spi: read_bytes(reader, spi_size as usize)?,
            notify_type,
            data: read_to_end(reader)?,
        })
    }
}

/// D payload, RFC 7296 §3.11.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DeletePayload {
    pub protocol_id: ProtocolId,
    /// 0 when deleting the IKE SA itself, otherwise 4 for ESP/AH.
    pub spi_size: u8,
    pub spis: Vec<Bytes>,
}

impl PayloadLike for DeletePayload {
    fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(self.len());
        buf.put_u8(self.protocol_id.into());
        buf.put_u8(self.spi_size);
        buf.put_u16(self.spis.len() as u16);
        for spi in &self.spis {
            buf.put_slice(spi);
        }
        buf.freeze()
    }

    fn len(&self) -> usize {
        4 + self.spis.len() * self.spi_size as usize
    }

    fn parse<R: Read>(reader: &mut R) -> anyhow::Result<Self> {
        let protocol_id = reader.read_u8()?.into();
        let spi_size = reader.read_u8()?;
        let num_spis = reader.read_u16::<BigEndian>()?;

        let mut spis = Vec::with_capacity(num_spis as usize);
        for _ in 0..num_spis {
            spis.push(read_bytes(reader, spi_size as usize)?);
        }

        Ok(Self {
            protocol_id,
            spi_size,
            spis,
        })
    }
}

/// One traffic selector, RFC 7296 §3.13.1.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TrafficSelector {
    pub ts_type: TrafficSelectorType,
    pub ip_protocol_id: u8,
    pub start_port: u16,
    pub end_port: u16,
    pub start_address: Bytes,
    pub end_address: Bytes,
}

impl TrafficSelector {
    /// A selector matching every IPv4 address, port and protocol.
    pub fn any_ipv4() -> Self {
        Self {
            ts_type: TrafficSelectorType::Ipv4AddrRange,
            ip_protocol_id: 0,
            start_port: 0,
            end_port: u16::MAX,
            start_address: Bytes::from_static(&[0, 0, 0, 0]),
            end_address: Bytes::from_static(&[255, 255, 255, 255]),
        }
    }

    pub fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(self.len());
        buf.put_u8(self.ts_type.into());
        buf.put_u8(self.ip_protocol_id);
        buf.put_u16(self.len() as u16);
        buf.put_u16(self.start_port);
        buf.put_u16(self.end_port);
        buf.put_slice(&self.start_address);
        buf.put_slice(&self.end_address);
        buf.freeze()
    }

    pub fn len(&self) -> usize {
        8 + self.start_address.len() + self.end_address.len()
    }

    pub fn is_empty(&self) -> bool {
        false
    }

    pub fn parse<R: Read>(reader: &mut R) -> anyhow::Result<Self> {
        let ts_type = reader.read_u8()?.into();
        let ip_protocol_id = reader.read_u8()?;
        let length = reader.read_u16::<BigEndian>()?;
        let start_port = reader.read_u16::<BigEndian>()?;
        let end_port = reader.read_u16::<BigEndian>()?;

        let address_len = length.checked_sub(8).context("Traffic selector too short")? / 2;

        Ok(Self {
            ts_type,
            ip_protocol_id,
            start_port,
            end_port,
            start_address: read_bytes(reader, address_len as usize)?,
            end_address: read_bytes(reader, address_len as usize)?,
        })
    }
}

/// TSi / TSr payload, RFC 7296 §3.13.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct TrafficSelectorPayload {
    pub selectors: Vec<TrafficSelector>,
}

impl PayloadLike for TrafficSelectorPayload {
    fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(self.len());
        buf.put_u8(self.selectors.len() as u8);
        buf.put_u8(0);
        buf.put_u16(0);
        for selector in &self.selectors {
            buf.put_slice(&selector.to_bytes());
        }
        buf.freeze()
    }

    fn len(&self) -> usize {
        self.selectors.iter().fold(4, |len, s| len + s.len())
    }

    fn parse<R: Read>(reader: &mut R) -> anyhow::Result<Self> {
        let num_selectors = reader.read_u8()?;
        reader.read_u8()?;
        reader.read_u16::<BigEndian>()?;

        let mut selectors = Vec::with_capacity(num_selectors as usize);
        for _ in 0..num_selectors {
            selectors.push(TrafficSelector::parse(reader)?);
        }

        Ok(Self { selectors })
    }
}

/// Configuration attribute, RFC 7296 §3.15.1. Note this is *not* the IKEv1
/// attribute TLV: there is no inline short form, only a reserved bit and an
/// explicit length.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ConfigurationAttribute {
    pub attribute_type: ConfigurationAttributeType,
    pub data: Bytes,
}

impl ConfigurationAttribute {
    /// An empty attribute, as sent in a CFG_REQUEST to ask for a value.
    pub fn request(attribute_type: ConfigurationAttributeType) -> Self {
        Self {
            attribute_type,
            data: Bytes::new(),
        }
    }

    pub fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(self.len());
        buf.put_u16(u16::from(self.attribute_type) & 0x7fff);
        buf.put_u16(self.data.len() as u16);
        buf.put_slice(&self.data);
        buf.freeze()
    }

    pub fn len(&self) -> usize {
        4 + self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        false
    }

    pub fn parse<R: Read>(reader: &mut R) -> anyhow::Result<Self> {
        let attribute_type = (reader.read_u16::<BigEndian>()? & 0x7fff).into();
        let length = reader.read_u16::<BigEndian>()?;

        Ok(Self {
            attribute_type,
            data: read_bytes(reader, length as usize)?,
        })
    }
}

/// CP payload, RFC 7296 §3.15: the IKEv2 replacement for the IKEv1 office-mode
/// transaction exchange.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ConfigurationPayload {
    pub cfg_type: ConfigurationType,
    pub attributes: Vec<ConfigurationAttribute>,
}

impl PayloadLike for ConfigurationPayload {
    fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(self.len());
        buf.put_u8(self.cfg_type.into());
        buf.put_u8(0);
        buf.put_u16(0);
        for attribute in &self.attributes {
            buf.put_slice(&attribute.to_bytes());
        }
        buf.freeze()
    }

    fn len(&self) -> usize {
        self.attributes.iter().fold(4, |len, a| len + a.len())
    }

    fn parse<R: Read>(reader: &mut R) -> anyhow::Result<Self> {
        let cfg_type = reader.read_u8()?.into();
        reader.read_u8()?;
        reader.read_u16::<BigEndian>()?;

        let mut cursor = Cursor::new(read_to_end(reader)?);
        let mut attributes = Vec::new();
        while cursor.has_remaining() {
            attributes.push(ConfigurationAttribute::parse(&mut cursor)?);
        }

        Ok(Self { cfg_type, attributes })
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Payload {
    SecurityAssociation(SecurityAssociationPayload),
    KeyExchange(KeyExchangePayload),
    IdentificationInitiator(IdentificationPayload),
    IdentificationResponder(IdentificationPayload),
    Certificate(CertificatePayload),
    CertificateRequest(CertificatePayload),
    Authentication(AuthenticationPayload),
    Nonce(BasicPayload),
    Notify(NotifyPayload),
    Delete(DeletePayload),
    VendorId(BasicPayload),
    TrafficSelectorInitiator(TrafficSelectorPayload),
    TrafficSelectorResponder(TrafficSelectorPayload),
    /// SK: the raw `IV | ciphertext | ICV` blob. The codec unwraps it.
    Encrypted(BasicPayload),
    Configuration(ConfigurationPayload),
    Eap(BasicPayload),
    Other(PayloadType, BasicPayload),
}

impl Payload {
    pub fn to_bytes(&self) -> Bytes {
        match self {
            Payload::SecurityAssociation(p) => p.to_bytes(),
            Payload::KeyExchange(p) => p.to_bytes(),
            Payload::IdentificationInitiator(p) | Payload::IdentificationResponder(p) => p.to_bytes(),
            Payload::Certificate(p) | Payload::CertificateRequest(p) => p.to_bytes(),
            Payload::Authentication(p) => p.to_bytes(),
            Payload::Notify(p) => p.to_bytes(),
            Payload::Delete(p) => p.to_bytes(),
            Payload::TrafficSelectorInitiator(p) | Payload::TrafficSelectorResponder(p) => p.to_bytes(),
            Payload::Configuration(p) => p.to_bytes(),
            Payload::Nonce(p) | Payload::VendorId(p) | Payload::Encrypted(p) | Payload::Eap(p) => p.to_bytes(),
            Payload::Other(_, p) => p.to_bytes(),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Payload::SecurityAssociation(p) => p.len(),
            Payload::KeyExchange(p) => p.len(),
            Payload::IdentificationInitiator(p) | Payload::IdentificationResponder(p) => p.len(),
            Payload::Certificate(p) | Payload::CertificateRequest(p) => p.len(),
            Payload::Authentication(p) => p.len(),
            Payload::Notify(p) => p.len(),
            Payload::Delete(p) => p.len(),
            Payload::TrafficSelectorInitiator(p) | Payload::TrafficSelectorResponder(p) => p.len(),
            Payload::Configuration(p) => p.len(),
            Payload::Nonce(p) | Payload::VendorId(p) | Payload::Encrypted(p) | Payload::Eap(p) => p.len(),
            Payload::Other(_, p) => p.len(),
        }
    }

    // never empty: every payload carries at least its own fixed fields
    pub fn is_empty(&self) -> bool {
        false
    }

    pub fn as_payload_type(&self) -> PayloadType {
        match self {
            Payload::SecurityAssociation(_) => PayloadType::SecurityAssociation,
            Payload::KeyExchange(_) => PayloadType::KeyExchange,
            Payload::IdentificationInitiator(_) => PayloadType::IdentificationInitiator,
            Payload::IdentificationResponder(_) => PayloadType::IdentificationResponder,
            Payload::Certificate(_) => PayloadType::Certificate,
            Payload::CertificateRequest(_) => PayloadType::CertificateRequest,
            Payload::Authentication(_) => PayloadType::Authentication,
            Payload::Nonce(_) => PayloadType::Nonce,
            Payload::Notify(_) => PayloadType::Notify,
            Payload::Delete(_) => PayloadType::Delete,
            Payload::VendorId(_) => PayloadType::VendorId,
            Payload::TrafficSelectorInitiator(_) => PayloadType::TrafficSelectorInitiator,
            Payload::TrafficSelectorResponder(_) => PayloadType::TrafficSelectorResponder,
            Payload::Encrypted(_) => PayloadType::Encrypted,
            Payload::Configuration(_) => PayloadType::Configuration,
            Payload::Eap(_) => PayloadType::ExtensibleAuthentication,
            Payload::Other(t, _) => *t,
        }
    }

    fn parse<R: Read>(payload_type: PayloadType, critical: bool, reader: &mut R) -> anyhow::Result<Self> {
        Ok(match payload_type {
            PayloadType::SecurityAssociation => {
                Payload::SecurityAssociation(SecurityAssociationPayload::parse(reader)?)
            }
            PayloadType::KeyExchange => Payload::KeyExchange(KeyExchangePayload::parse(reader)?),
            PayloadType::IdentificationInitiator => {
                Payload::IdentificationInitiator(IdentificationPayload::parse(reader)?)
            }
            PayloadType::IdentificationResponder => {
                Payload::IdentificationResponder(IdentificationPayload::parse(reader)?)
            }
            PayloadType::Certificate => Payload::Certificate(CertificatePayload::parse(reader)?),
            PayloadType::CertificateRequest => Payload::CertificateRequest(CertificatePayload::parse(reader)?),
            PayloadType::Authentication => Payload::Authentication(AuthenticationPayload::parse(reader)?),
            PayloadType::Nonce => Payload::Nonce(BasicPayload::parse(reader)?),
            PayloadType::Notify => Payload::Notify(NotifyPayload::parse(reader)?),
            PayloadType::Delete => Payload::Delete(DeletePayload::parse(reader)?),
            PayloadType::VendorId => Payload::VendorId(BasicPayload::parse(reader)?),
            PayloadType::TrafficSelectorInitiator => {
                Payload::TrafficSelectorInitiator(TrafficSelectorPayload::parse(reader)?)
            }
            PayloadType::TrafficSelectorResponder => {
                Payload::TrafficSelectorResponder(TrafficSelectorPayload::parse(reader)?)
            }
            PayloadType::Encrypted => Payload::Encrypted(BasicPayload::parse(reader)?),
            PayloadType::Configuration => Payload::Configuration(ConfigurationPayload::parse(reader)?),
            PayloadType::ExtensibleAuthentication => Payload::Eap(BasicPayload::parse(reader)?),
            other => {
                // RFC 7296 §2.5: an unrecognised payload flagged critical must
                // abort the exchange with UNSUPPORTED_CRITICAL_PAYLOAD.
                if critical {
                    anyhow::bail!("Unsupported critical payload: {:?}", other);
                }
                Payload::Other(other, BasicPayload::parse(reader)?)
            }
        })
    }

    pub fn parse_all<R: Read>(next_payload: PayloadType, reader: &mut R) -> anyhow::Result<Vec<Payload>> {
        let mut result = Vec::new();
        let mut payload_type = next_payload;

        while payload_type != PayloadType::None {
            let (next, critical, data) = read_next_payload(reader)?;
            trace!(
                "Parsing IKEv2 payload: type={:?}, size={}, next={:?}",
                payload_type,
                data.len(),
                next
            );
            result.push(Self::parse(payload_type, critical, &mut Cursor::new(data))?);
            payload_type = next;
        }

        Ok(result)
    }

    /// Serialise a payload chain, each payload preceded by its generic header.
    /// The chain always terminates with a Next Payload of `None`, both at the
    /// top level and inside an SK payload (RFC 7296 §3.14).
    pub fn write_all(payloads: &[Payload]) -> Bytes {
        let mut buf = BytesMut::new();

        for (i, payload) in payloads.iter().enumerate() {
            let next = payloads.get(i + 1).map_or(PayloadType::None, |p| p.as_payload_type());
            write_payload(&mut buf, next.into(), &payload.to_bytes());
        }

        buf.freeze()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload::CRITICAL_BIT;

    fn round_trip(payloads: Vec<Payload>) -> Vec<Payload> {
        let first = payloads[0].as_payload_type();
        let encoded = Payload::write_all(&payloads);
        let decoded = Payload::parse_all(first, &mut Cursor::new(encoded.clone())).unwrap();

        assert_eq!(decoded, payloads);
        assert_eq!(Payload::write_all(&decoded), encoded, "re-encoding changed the bytes");
        decoded
    }

    fn ike_proposal() -> Proposal {
        Proposal {
            proposal_num: 1,
            protocol_id: ProtocolId::Ike,
            spi: Bytes::new(),
            transforms: vec![
                Transform::encryption(EncryptionAlgorithm::AesCbc, Some(32)),
                Transform::prf(PseudoRandomFunction::HmacSha256),
                Transform::integrity(IntegrityAlgorithm::HmacSha256_128),
                Transform::dh_group(DhGroup::Ecp256),
            ],
        }
    }

    fn esp_proposal() -> Proposal {
        Proposal {
            proposal_num: 2,
            protocol_id: ProtocolId::Esp,
            spi: Bytes::from_static(&[0xaa, 0xbb, 0xcc, 0xdd]),
            transforms: vec![
                Transform::encryption(EncryptionAlgorithm::AesGcm16, Some(32)),
                Transform::esn(ExtendedSequenceNumbers::None),
            ],
        }
    }

    #[test]
    fn test_security_association_round_trip() {
        let sa = SecurityAssociationPayload {
            proposals: vec![ike_proposal(), esp_proposal()],
        };

        let decoded = round_trip(vec![Payload::SecurityAssociation(sa)]);
        let Payload::SecurityAssociation(sa) = &decoded[0] else {
            panic!("wrong payload type")
        };

        assert_eq!(sa.proposals.len(), 2);
        assert_eq!(sa.proposals[1].spi, Bytes::from_static(&[0xaa, 0xbb, 0xcc, 0xdd]));

        let encr = sa.proposals[0].find(TransformType::EncryptionAlgorithm).unwrap();
        assert_eq!(encr.as_encryption(), Some(EncryptionAlgorithm::AesCbc));
        assert_eq!(encr.key_len(), Some(32));
        assert_eq!(encr.as_prf(), None, "accessors are typed by transform type");

        assert_eq!(
            sa.proposals[0]
                .find(TransformType::DiffieHellmanGroup)
                .unwrap()
                .as_dh_group(),
            Some(DhGroup::Ecp256)
        );
        assert_eq!(
            sa.proposals[1]
                .find(TransformType::ExtendedSequenceNumbers)
                .unwrap()
                .as_esn(),
            Some(ExtendedSequenceNumbers::None)
        );
        assert_eq!(sa.proposals[1].find(TransformType::PseudoRandomFunction), None);
    }

    /// The Key Length attribute is expressed in bits on the wire.
    #[test]
    fn test_key_length_attribute_is_in_bits() {
        let transform = Transform::encryption(EncryptionAlgorithm::AesCbc, Some(32));

        assert_eq!(transform.attributes[0].as_short(), Some(256));
        assert_eq!(transform.key_len(), Some(32));
        assert_eq!(&transform.attributes[0].to_bytes()[..], &[0x80, 0x0e, 0x01, 0x00]);

        assert_eq!(
            Transform::encryption(EncryptionAlgorithm::DesEde3Cbc, None).key_len(),
            None
        );
    }

    #[test]
    fn test_last_substruc_marks_the_final_entry() {
        let sa = SecurityAssociationPayload {
            proposals: vec![ike_proposal(), esp_proposal()],
        };
        let bytes = sa.to_bytes();

        // first proposal is followed by another, second is last
        assert_eq!(bytes[0], 2);
        let second = ike_proposal().len();
        assert_eq!(bytes[second], 0);

        // within a proposal, transforms chain with 3 and end with 0
        assert_eq!(bytes[8], 3);
        let last_transform = ike_proposal().len() - ike_proposal().transforms.last().unwrap().len();
        assert_eq!(bytes[last_transform], 0);
    }

    #[test]
    fn test_basic_payloads_round_trip() {
        round_trip(vec![
            Payload::Nonce(BasicPayload::new(Bytes::from_static(&[0x11; 32]))),
            Payload::VendorId(BasicPayload::new(Bytes::from_static(b"vendor"))),
            Payload::Eap(BasicPayload::new(Bytes::from_static(&[1, 2, 3]))),
            Payload::Encrypted(BasicPayload::new(Bytes::from_static(&[9; 40]))),
        ]);
    }

    #[test]
    fn test_key_exchange_and_identification_round_trip() {
        round_trip(vec![
            Payload::KeyExchange(KeyExchangePayload {
                dh_group: DhGroup::Ecp256,
                data: Bytes::from(vec![0x42; 64]),
            }),
            Payload::IdentificationInitiator(IdentificationPayload {
                id_type: IdentificationType::Rfc822Address,
                data: Bytes::from_static(b"user@example.com"),
            }),
            Payload::IdentificationResponder(IdentificationPayload {
                id_type: IdentificationType::Ipv4Address,
                data: Bytes::from_static(&[10, 0, 0, 1]),
            }),
        ]);
    }

    #[test]
    fn test_certificate_and_auth_round_trip() {
        round_trip(vec![
            Payload::Certificate(CertificatePayload {
                encoding: CertificateEncoding::X509CertificateSignature,
                data: Bytes::from(vec![0x30; 100]),
            }),
            Payload::CertificateRequest(CertificatePayload {
                encoding: CertificateEncoding::X509CertificateSignature,
                data: Bytes::from(vec![0x77; 20]),
            }),
            Payload::Authentication(AuthenticationPayload {
                auth_method: AuthMethod::DigitalSignature,
                data: Bytes::from(vec![0x5a; 256]),
            }),
        ]);
    }

    #[test]
    fn test_notify_round_trip_with_and_without_spi() {
        let decoded = round_trip(vec![
            Payload::Notify(NotifyPayload::new(
                NotifyType::NatDetectionSourceIp,
                Bytes::from(vec![0x11; 20]),
            )),
            Payload::Notify(NotifyPayload {
                protocol_id: ProtocolId::Esp,
                spi: Bytes::from_static(&[1, 2, 3, 4]),
                notify_type: NotifyType::RekeySa,
                data: Bytes::new(),
            }),
            Payload::Notify(NotifyPayload::new(NotifyType::Cookie, Bytes::from(vec![0xc0; 64]))),
        ]);

        let Payload::Notify(notify) = &decoded[1] else {
            panic!("wrong payload type")
        };
        assert_eq!(notify.spi, Bytes::from_static(&[1, 2, 3, 4]));
        assert_eq!(notify.protocol_id, ProtocolId::Esp);
    }

    #[test]
    fn test_delete_round_trip() {
        round_trip(vec![
            // deleting the IKE SA carries no SPIs
            Payload::Delete(DeletePayload {
                protocol_id: ProtocolId::Ike,
                spi_size: 0,
                spis: Vec::new(),
            }),
            Payload::Delete(DeletePayload {
                protocol_id: ProtocolId::Esp,
                spi_size: 4,
                spis: vec![Bytes::from_static(&[1, 2, 3, 4]), Bytes::from_static(&[5, 6, 7, 8])],
            }),
        ]);
    }

    #[test]
    fn test_traffic_selector_round_trip() {
        let decoded = round_trip(vec![
            Payload::TrafficSelectorInitiator(TrafficSelectorPayload {
                selectors: vec![TrafficSelector::any_ipv4()],
            }),
            Payload::TrafficSelectorResponder(TrafficSelectorPayload {
                selectors: vec![
                    TrafficSelector {
                        ts_type: TrafficSelectorType::Ipv4AddrRange,
                        ip_protocol_id: 6,
                        start_port: 443,
                        end_port: 443,
                        start_address: Bytes::from_static(&[10, 0, 0, 1]),
                        end_address: Bytes::from_static(&[10, 0, 0, 255]),
                    },
                    TrafficSelector {
                        ts_type: TrafficSelectorType::Ipv6AddrRange,
                        ip_protocol_id: 0,
                        start_port: 0,
                        end_port: u16::MAX,
                        start_address: Bytes::from(vec![0u8; 16]),
                        end_address: Bytes::from(vec![0xffu8; 16]),
                    },
                ],
            }),
        ]);

        let Payload::TrafficSelectorResponder(ts) = &decoded[1] else {
            panic!("wrong payload type")
        };
        // the address width is derived from the selector length, per selector
        assert_eq!(ts.selectors[0].start_address.len(), 4);
        assert_eq!(ts.selectors[1].start_address.len(), 16);
    }

    #[test]
    fn test_configuration_round_trip() {
        let decoded = round_trip(vec![
            Payload::Configuration(ConfigurationPayload {
                cfg_type: ConfigurationType::Request,
                attributes: vec![
                    ConfigurationAttribute::request(ConfigurationAttributeType::InternalIp4Address),
                    ConfigurationAttribute::request(ConfigurationAttributeType::InternalIp4Netmask),
                    ConfigurationAttribute::request(ConfigurationAttributeType::InternalIp4Dns),
                ],
            }),
            Payload::Configuration(ConfigurationPayload {
                cfg_type: ConfigurationType::Reply,
                attributes: vec![ConfigurationAttribute {
                    attribute_type: ConfigurationAttributeType::InternalIp4Address,
                    data: Bytes::from_static(&[10, 1, 2, 3]),
                }],
            }),
        ]);

        let Payload::Configuration(cfg) = &decoded[0] else {
            panic!("wrong payload type")
        };
        // a CFG_REQUEST asks with zero-length attributes
        assert!(cfg.attributes.iter().all(|a| a.data.is_empty()));
        assert_eq!(&cfg.attributes[0].to_bytes()[..], &[0x00, 0x01, 0x00, 0x00]);
    }

    /// Unlike the IKEv1 attribute TLV there is no inline short form: the
    /// reserved top bit stays clear and the length is always explicit.
    #[test]
    fn test_configuration_attribute_is_not_an_ikev1_tlv() {
        let attribute = ConfigurationAttribute {
            attribute_type: ConfigurationAttributeType::InternalIp4Netmask,
            data: Bytes::from_static(&[255, 255, 255, 0]),
        };

        assert_eq!(&attribute.to_bytes()[..], &[0x00, 0x02, 0x00, 0x04, 255, 255, 255, 0]);
    }

    #[test]
    fn test_unknown_payload_is_preserved() {
        let decoded = round_trip(vec![
            Payload::Nonce(BasicPayload::new(Bytes::from_static(&[7; 16]))),
            Payload::Other(
                PayloadType::Other(200),
                BasicPayload::new(Bytes::from_static(b"opaque")),
            ),
        ]);

        assert_eq!(decoded[1].as_payload_type(), PayloadType::Other(200));
    }

    /// RFC 7296 §2.5: an unrecognised payload with the critical bit set must
    /// abort the exchange rather than being skipped.
    #[test]
    fn test_unknown_critical_payload_is_rejected() {
        let mut encoded = Payload::write_all(&[Payload::Other(
            PayloadType::Other(200),
            BasicPayload::new(Bytes::from_static(b"opaque")),
        )])
        .to_vec();

        assert!(Payload::parse_all(PayloadType::Other(200), &mut Cursor::new(encoded.clone())).is_ok());

        encoded[1] = CRITICAL_BIT;
        let err = Payload::parse_all(PayloadType::Other(200), &mut Cursor::new(encoded)).unwrap_err();
        assert!(err.to_string().contains("critical"), "{err}");
    }

    /// A recognised payload is parsed whether or not it is flagged critical.
    #[test]
    fn test_known_critical_payload_is_accepted() {
        let mut encoded =
            Payload::write_all(&[Payload::Nonce(BasicPayload::new(Bytes::from_static(&[7; 16])))]).to_vec();
        encoded[1] = CRITICAL_BIT;

        let decoded = Payload::parse_all(PayloadType::Nonce, &mut Cursor::new(encoded)).unwrap();
        assert_eq!(decoded.len(), 1);
    }

    #[test]
    fn test_malformed_lengths_are_rejected() {
        // payload length below the 4-byte generic header
        assert!(Payload::parse_all(PayloadType::Nonce, &mut Cursor::new(vec![0, 0, 0, 3])).is_err());

        // length past the end of the buffer
        assert!(Payload::parse_all(PayloadType::Nonce, &mut Cursor::new(vec![0, 0, 0xff, 0])).is_err());

        // proposal claiming more transforms than it carries
        let mut sa = SecurityAssociationPayload {
            proposals: vec![ike_proposal()],
        }
        .to_bytes()
        .to_vec();
        sa[7] = 9;
        assert!(SecurityAssociationPayload::parse(&mut Cursor::new(sa)).is_err());
    }
}
