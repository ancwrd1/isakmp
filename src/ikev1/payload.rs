//! IKEv1 payload structures per RFC 2408 (ISAKMP) and RFC 2409 (IKE).
//!
//! Every payload is framed by the generic header in [`crate::payload`], so the
//! structures here model only the body: `len` and `to_bytes` exclude those four
//! bytes, matching [`crate::ikev2::payload`].

use std::{
    fmt,
    io::{Cursor, Read},
};

use anyhow::anyhow;
use byteorder::{BigEndian, ReadBytesExt};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use tracing::trace;

use crate::{
    ikev1::model::{
        AttributesPayloadType, CertificateType, NotifyMessageType, PayloadType, ProtocolId, Situation, SituationData,
        SituationFlags, TransformId, is_sensitive_config_attribute,
    },
    model::DataAttribute,
    payload::{BasicPayload, PAYLOAD_HEADER_LEN, PayloadLike, read_next_payload, read_to_end, write_payload},
};

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct SecurityAssociationPayload {
    pub doi: u32,
    pub situation: Option<Situation>,
    pub payloads: Vec<Payload>,
}

impl PayloadLike for SecurityAssociationPayload {
    fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(self.len());
        buf.put_u32(self.doi);
        if let Some(ref situation) = self.situation {
            let mut flags: SituationFlags = SituationFlags::from_bits_retain(0);
            if situation.secrecy.is_some() {
                flags |= SituationFlags::SECRECY;
            }
            if situation.integrity.is_some() {
                flags |= SituationFlags::INTEGRITY;
            }
            buf.put_u32(flags.bits());
            buf.put_u32(situation.labeled_domain_identifier);
            if let Some(ref secrecy) = situation.secrecy {
                buf.put_u16(secrecy.level.len() as _);
                buf.put_u16(0);
                buf.put_slice(&secrecy.level);
                buf.put_u16(secrecy.category.len() as _);
                buf.put_u16(0);
                buf.put_slice(&secrecy.category);
            }
            if let Some(ref integrity) = situation.integrity {
                buf.put_u16(integrity.level.len() as _);
                buf.put_u16(0);
                buf.put_slice(&integrity.level);
                buf.put_u16(integrity.category.len() as _);
                buf.put_u16(0);
                buf.put_slice(&integrity.category);
            }
        } else {
            buf.put_u32(SituationFlags::IDENTITY_ONLY.bits());
        }

        buf.put_slice(&Payload::write_all(&self.payloads));
        buf.freeze()
    }

    fn len(&self) -> usize {
        let sit_len = 8 + self
            .situation
            .as_ref()
            .map(|s| {
                let secrecy_len = s.secrecy.as_ref().map_or(0, |s| 8 + s.level.len() + s.category.len());
                let integrity_len = s.integrity.as_ref().map_or(0, |s| 8 + s.level.len() + s.category.len());
                secrecy_len + integrity_len
            })
            .unwrap_or(0);
        self.payloads
            .iter()
            .fold(sit_len, |len, p| len + PAYLOAD_HEADER_LEN + p.len())
    }

    fn parse<R: Read>(reader: &mut R) -> anyhow::Result<Self> {
        let doi = reader.read_u32::<BigEndian>()?;
        let situation_flags = SituationFlags::from_bits_retain(reader.read_u32::<BigEndian>()?);

        let situation = if situation_flags.contains(SituationFlags::SECRECY | SituationFlags::INTEGRITY) {
            let mut situation = Situation {
                labeled_domain_identifier: reader.read_u32::<BigEndian>()?,
                secrecy: None,
                integrity: None,
            };
            if situation_flags.contains(SituationFlags::SECRECY) {
                situation.secrecy = Some(SituationData::parse(reader)?);
            }

            if situation_flags.contains(SituationFlags::INTEGRITY) {
                situation.integrity = Some(SituationData::parse(reader)?);
            }

            Some(situation)
        } else {
            None
        };
        let payloads = Payload::parse_all(PayloadType::Proposal, reader)?;
        Ok(Self {
            doi,
            situation,
            payloads,
        })
    }
}

impl SituationData {
    fn parse<R: Read>(reader: &mut R) -> anyhow::Result<Self> {
        let level_length = reader.read_u16::<BigEndian>()?;
        reader.read_u16::<BigEndian>()?;
        let mut level = vec![0u8; level_length as usize];
        reader.read_exact(&mut level)?;

        let category_length = reader.read_u16::<BigEndian>()?;
        reader.read_u16::<BigEndian>()?;
        let mut category = vec![0u8; category_length as usize];
        reader.read_exact(&mut category)?;

        Ok(Self {
            level: level.into(),
            category: category.into(),
        })
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct ProposalPayload {
    pub proposal_num: u8,
    pub protocol_id: ProtocolId,
    pub spi: Bytes,
    pub transforms: Vec<TransformPayload>,
}

impl PayloadLike for ProposalPayload {
    fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(self.len());
        buf.put_u8(self.proposal_num);
        buf.put_u8(self.protocol_id.into());
        buf.put_u8(self.spi.len() as u8);
        buf.put_u8(self.transforms.len() as u8);
        buf.put_slice(&self.spi);
        for (i, transform) in self.transforms.iter().enumerate() {
            let next = self
                .transforms
                .get(i + 1)
                .map_or(PayloadType::None, |_| PayloadType::Transform);
            write_payload(&mut buf, next.into(), &transform.to_bytes());
        }

        buf.freeze()
    }

    fn len(&self) -> usize {
        self.transforms
            .iter()
            .fold(4 + (self.spi.len() & 255), |len, p| len + PAYLOAD_HEADER_LEN + p.len())
    }

    fn parse<R: Read>(reader: &mut R) -> anyhow::Result<Self> {
        let proposal_num = reader.read_u8()?;
        let protocol_id: ProtocolId = reader.read_u8()?.into();
        let spi_len = reader.read_u8()? as usize;
        let num_transforms = reader.read_u8()? as usize;
        let mut spi_data = vec![0u8; spi_len];
        reader.read_exact(&mut spi_data)?;
        let transforms = Payload::parse_all(PayloadType::Transform, reader)?
            .into_iter()
            .filter_map(|p| match p {
                Payload::Transform(payload) => Some(payload),
                _ => None,
            })
            .collect::<Vec<_>>();

        if transforms.len() == num_transforms {
            Ok(Self {
                proposal_num,
                protocol_id,
                spi: spi_data.into(),
                transforms,
            })
        } else {
            Err(anyhow!(
                "Transform count mismatch: expected {}, got {}",
                num_transforms,
                transforms.len()
            ))
        }
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct NotificationPayload {
    pub doi: u32,
    pub protocol_id: ProtocolId,
    pub message_type: NotifyMessageType,
    pub spi: Bytes,
    pub data: Bytes,
}

impl PayloadLike for NotificationPayload {
    fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(self.len());

        buf.put_u32(self.doi);
        buf.put_u8(self.protocol_id.into());
        buf.put_u8(self.spi.len() as u8);
        buf.put_u16(self.message_type.into());
        buf.put_slice(&self.spi);
        buf.put_slice(&self.data);

        buf.freeze()
    }

    fn len(&self) -> usize {
        8 + (self.spi.len() & 255) + self.data.len()
    }

    fn parse<R: Read>(reader: &mut R) -> anyhow::Result<Self> {
        let doi = reader.read_u32::<BigEndian>()?;
        let protocol_id: ProtocolId = reader.read_u8()?.into();
        let spi_len = reader.read_u8()? as usize;
        let message_type = reader.read_u16::<BigEndian>()?;
        let mut spi_data = vec![0u8; spi_len];
        reader.read_exact(&mut spi_data)?;
        Ok(Self {
            doi,
            protocol_id,
            message_type: message_type.into(),
            spi: spi_data.into(),
            data: read_to_end(reader)?,
        })
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct DeletePayload {
    pub doi: u32,
    pub protocol_id: ProtocolId,
    pub spi_size: u8,
    pub spi: Vec<Bytes>,
}

impl PayloadLike for DeletePayload {
    fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(self.len());
        buf.put_u32(self.doi);
        buf.put_u8(self.protocol_id.into());
        buf.put_u8(self.spi_size);
        buf.put_u16(self.spi.len() as _);
        for spi in &self.spi {
            buf.put_slice(spi);
        }

        buf.freeze()
    }

    fn len(&self) -> usize {
        self.spi.iter().fold(8, |len, s| len + s.len())
    }

    fn parse<R: Read>(reader: &mut R) -> anyhow::Result<Self> {
        let doi = reader.read_u32::<BigEndian>()?;
        let protocol_id: ProtocolId = reader.read_u8()?.into();
        let spi_len = reader.read_u8()?;
        let mut spi_data = vec![0u8; spi_len as _];
        reader.read_exact(&mut spi_data)?;
        Ok(Self {
            doi,
            protocol_id,
            spi_size: spi_len,
            spi: spi_data.chunks(spi_len as _).map(Bytes::copy_from_slice).collect(),
        })
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct TransformPayload {
    pub transform_num: u8,
    pub transform_id: TransformId,
    pub attributes: Vec<DataAttribute>,
}

impl PayloadLike for TransformPayload {
    fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(self.len());
        buf.put_u8(self.transform_num);
        buf.put_u8(self.transform_id.into());
        buf.put_u16(0);

        for attr in &self.attributes {
            buf.put_slice(&attr.to_bytes());
        }

        buf.freeze()
    }

    fn len(&self) -> usize {
        self.attributes.iter().fold(4, |len, a| len + a.len())
    }

    fn parse<R: Read>(reader: &mut R) -> anyhow::Result<Self> {
        let transform_num = reader.read_u8()?;
        let transform_id = reader.read_u8()?.into();
        reader.read_u16::<BigEndian>()?;

        Ok(Self {
            transform_num,
            transform_id,
            attributes: parse_attributes(reader)?,
        })
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct IdentificationPayload {
    pub id_type: u8,
    pub protocol_id: u8,
    pub port: u16,
    pub data: Bytes,
}

impl PayloadLike for IdentificationPayload {
    fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(self.len());

        buf.put_u8(self.id_type);
        buf.put_u8(self.protocol_id);
        buf.put_u16(0);
        buf.put_slice(&self.data);

        buf.freeze()
    }

    fn len(&self) -> usize {
        4 + self.data.len()
    }

    fn parse<R: Read>(reader: &mut R) -> anyhow::Result<Self> {
        let id_type = reader.read_u8()?;
        let protocol_id = reader.read_u8()?;
        let port = reader.read_u16::<BigEndian>()?;
        Ok(Self {
            id_type,
            protocol_id,
            port,
            data: read_to_end(reader)?,
        })
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct CertificatePayload {
    pub certificate_type: CertificateType,
    pub data: Bytes,
}

impl PayloadLike for CertificatePayload {
    fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(self.len());
        buf.put_u8(self.certificate_type.into());
        buf.put_slice(&self.data);
        buf.freeze()
    }

    fn len(&self) -> usize {
        1 + self.data.len()
    }

    fn parse<R: Read>(reader: &mut R) -> anyhow::Result<Self> {
        let certificate_type: CertificateType = reader.read_u8()?.into();
        Ok(Self {
            certificate_type,
            data: read_to_end(reader)?,
        })
    }
}

/// ISAKMP-config (office mode) payload, RFC 2407. The IKEv1 counterpart of the
/// IKEv2 configuration payload.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct AttributesPayload {
    pub attributes_payload_type: AttributesPayloadType,
    pub identifier: u16,
    pub attributes: Vec<DataAttribute>,
}

impl PayloadLike for AttributesPayload {
    fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(self.len());
        buf.put_u8(self.attributes_payload_type.into());
        buf.put_u8(0);
        buf.put_u16(self.identifier);
        for attr in &self.attributes {
            buf.put_slice(&attr.to_bytes());
        }

        buf.freeze()
    }

    fn len(&self) -> usize {
        self.attributes.iter().fold(4, |len, attr| len + attr.len())
    }

    fn parse<R: Read>(reader: &mut R) -> anyhow::Result<Self> {
        let attributes_payload_type: AttributesPayloadType = reader.read_u8()?.into();
        reader.read_u8()?;
        let identifier = reader.read_u16::<BigEndian>()?;
        Ok(Self {
            attributes_payload_type,
            identifier,
            attributes: parse_attributes(reader)?,
        })
    }
}

/// This is the one payload whose attributes carry credentials — the user
/// password and the passcode of an office-mode exchange — so it redacts them
/// rather than deriving `Debug`.
impl fmt::Debug for AttributesPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        static REDACTED: DataAttribute = DataAttribute {
            attribute_type: 0,
            value: crate::model::AttributeValue::Long(Bytes::from_static(&[])),
        };

        let attributes = self.attributes.iter().map(|attr| {
            if is_sensitive_config_attribute(attr.attribute_type) {
                &REDACTED
            } else {
                attr
            }
        });

        f.debug_struct("AttributesPayload")
            .field("attributes_payload_type", &self.attributes_payload_type)
            .field("identifier", &self.identifier)
            .field("attributes", &attributes.collect::<Vec<_>>())
            .finish()
    }
}

/// Reads data attributes until the reader is exhausted, as a transform and an
/// attributes payload both do.
fn parse_attributes<R: Read>(reader: &mut R) -> anyhow::Result<Vec<DataAttribute>> {
    let mut cursor = Cursor::new(read_to_end(reader)?);
    let mut attributes = Vec::new();
    while cursor.has_remaining() {
        attributes.push(DataAttribute::parse(&mut cursor)?);
    }
    Ok(attributes)
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Payload {
    SecurityAssociation(SecurityAssociationPayload),
    Proposal(ProposalPayload),
    Notification(NotificationPayload),
    Delete(DeletePayload),
    Transform(TransformPayload),
    VendorId(BasicPayload),
    KeyExchange(BasicPayload),
    Nonce(BasicPayload),
    Identification(IdentificationPayload),
    Hash(BasicPayload),
    Certificate(CertificatePayload),
    CertificateRequest(CertificatePayload),
    Signature(BasicPayload),
    Attributes(AttributesPayload),
    Natd(BasicPayload),
    MachineCertificate(CertificatePayload),
    MachineSignature(BasicPayload),
    Other(PayloadType, BasicPayload),
}

impl Payload {
    pub fn to_bytes(&self) -> Bytes {
        match self {
            Payload::SecurityAssociation(p) => p.to_bytes(),
            Payload::Proposal(p) => p.to_bytes(),
            Payload::Notification(p) => p.to_bytes(),
            Payload::Delete(p) => p.to_bytes(),
            Payload::Transform(p) => p.to_bytes(),
            Payload::VendorId(p)
            | Payload::KeyExchange(p)
            | Payload::Nonce(p)
            | Payload::Hash(p)
            | Payload::Natd(p)
            | Payload::Signature(p)
            | Payload::MachineSignature(p) => p.to_bytes(),
            Payload::Identification(p) => p.to_bytes(),
            Payload::Certificate(p) | Payload::MachineCertificate(p) | Payload::CertificateRequest(p) => p.to_bytes(),
            Payload::Attributes(p) => p.to_bytes(),
            Payload::Other(_, p) => p.to_bytes(),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Payload::SecurityAssociation(p) => p.len(),
            Payload::Proposal(p) => p.len(),
            Payload::Notification(p) => p.len(),
            Payload::Delete(p) => p.len(),
            Payload::Transform(p) => p.len(),
            Payload::VendorId(p)
            | Payload::KeyExchange(p)
            | Payload::Nonce(p)
            | Payload::Hash(p)
            | Payload::Natd(p)
            | Payload::Signature(p)
            | Payload::MachineSignature(p) => p.len(),
            Payload::Identification(p) => p.len(),
            Payload::Certificate(p) | Payload::MachineCertificate(p) | Payload::CertificateRequest(p) => p.len(),
            Payload::Attributes(p) => p.len(),
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
            Payload::Proposal(_) => PayloadType::Proposal,
            Payload::Notification(_) => PayloadType::Notification,
            Payload::Delete(_) => PayloadType::Delete,
            Payload::Transform(_) => PayloadType::Transform,
            Payload::VendorId(_) => PayloadType::VendorId,
            Payload::KeyExchange(_) => PayloadType::KeyExchange,
            Payload::Nonce(_) => PayloadType::Nonce,
            Payload::Identification(_) => PayloadType::Identification,
            Payload::Hash(_) => PayloadType::Hash,
            Payload::Certificate(_) => PayloadType::Certificate,
            Payload::MachineCertificate(_) => PayloadType::MachineCertificate,
            Payload::CertificateRequest(_) => PayloadType::CertificateRequest,
            Payload::Signature(_) => PayloadType::Signature,
            Payload::MachineSignature(_) => PayloadType::MachineSignature,
            Payload::Attributes(_) => PayloadType::Attributes,
            Payload::Natd(_) => PayloadType::Natd,
            Payload::Other(t, _) => *t,
        }
    }

    fn parse<R: Read>(payload_type: PayloadType, reader: &mut R) -> anyhow::Result<Self> {
        Ok(match payload_type {
            PayloadType::SecurityAssociation => {
                Payload::SecurityAssociation(SecurityAssociationPayload::parse(reader)?)
            }
            PayloadType::Proposal => Payload::Proposal(ProposalPayload::parse(reader)?),
            PayloadType::Transform => Payload::Transform(TransformPayload::parse(reader)?),
            PayloadType::Notification => Payload::Notification(NotificationPayload::parse(reader)?),
            PayloadType::Delete => Payload::Delete(DeletePayload::parse(reader)?),
            PayloadType::VendorId => Payload::VendorId(BasicPayload::parse(reader)?),
            PayloadType::KeyExchange => Payload::KeyExchange(BasicPayload::parse(reader)?),
            PayloadType::Nonce => Payload::Nonce(BasicPayload::parse(reader)?),
            PayloadType::Identification => Payload::Identification(IdentificationPayload::parse(reader)?),
            PayloadType::Hash => Payload::Hash(BasicPayload::parse(reader)?),
            PayloadType::Natd => Payload::Natd(BasicPayload::parse(reader)?),
            PayloadType::Signature => Payload::Signature(BasicPayload::parse(reader)?),
            PayloadType::MachineSignature => Payload::MachineSignature(BasicPayload::parse(reader)?),
            PayloadType::Certificate => Payload::Certificate(CertificatePayload::parse(reader)?),
            PayloadType::MachineCertificate => Payload::MachineCertificate(CertificatePayload::parse(reader)?),
            PayloadType::CertificateRequest => Payload::CertificateRequest(CertificatePayload::parse(reader)?),
            PayloadType::Attributes => Payload::Attributes(AttributesPayload::parse(reader)?),
            other => Payload::Other(other, BasicPayload::parse(reader)?),
        })
    }

    pub fn parse_all<R: Read>(next_payload: PayloadType, reader: &mut R) -> anyhow::Result<Vec<Payload>> {
        let mut result = Vec::new();
        let mut payload_type = next_payload;

        while payload_type != PayloadType::None {
            // IKEv1 has no critical bit; the flags octet is reserved.
            let (next, _, data) = read_next_payload(reader)?;
            trace!(
                "Parsing IKEv1 payload: type={:?}, size={}, next={:?}",
                payload_type,
                data.len(),
                next
            );
            result.push(Self::parse(payload_type, &mut Cursor::new(data))?);
            payload_type = next;
        }

        Ok(result)
    }

    /// Serialise a payload chain, each payload preceded by its generic header.
    /// The chain always terminates with a Next Payload of `None`.
    pub fn write_all(payloads: &[Payload]) -> Bytes {
        let mut buf = BytesMut::new();

        for (i, payload) in payloads.iter().enumerate() {
            let next = payloads.get(i + 1).map_or(PayloadType::None, |p| p.as_payload_type());
            write_payload(&mut buf, next.into(), &payload.to_bytes());
        }

        buf.freeze()
    }
}
