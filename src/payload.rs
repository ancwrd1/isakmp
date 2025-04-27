use std::io::{Cursor, Read};

use anyhow::anyhow;
use byteorder::{BigEndian, ReadBytesExt};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use tracing::trace;

use crate::model::{
    AttributesPayloadType, CertificateType, DataAttribute, NotifyMessageType, PayloadType, ProtocolId, Situation,
    SituationData, SituationFlags, TransformId,
};

pub trait PayloadLike: Sized {
    fn to_bytes(&self) -> Bytes;
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn parse<R: Read>(reader: &mut R) -> anyhow::Result<Self>;
}

fn read_next_payload<R: Read>(reader: &mut R) -> anyhow::Result<(PayloadType, Bytes)> {
    let next_payload = reader.read_u8()?.into();
    reader.read_u8()?;
    let length = reader.read_u16::<BigEndian>()?;
    let mut data = vec![0u8; length as usize - 4];
    reader.read_exact(&mut data)?;

    Ok((next_payload, data.into()))
}

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

        for (i, payload) in self.payloads.iter().enumerate() {
            buf.put_u8(
                self.payloads
                    .get(i + 1)
                    .map_or(PayloadType::None, |p| p.as_payload_type())
                    .into(),
            );
            buf.put_u8(0);
            buf.put_u16(4 + payload.len() as u16);
            buf.put_slice(&payload.to_bytes());
        }
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
        self.payloads.iter().fold(sit_len, |len, p| 4 + len + p.len())
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
                let level_length = reader.read_u16::<BigEndian>()?;
                reader.read_u16::<BigEndian>()?;
                let mut level_data = vec![0u8; level_length as usize];
                reader.read_exact(&mut level_data)?;

                let category_length = reader.read_u16::<BigEndian>()?;
                reader.read_u16::<BigEndian>()?;
                let mut category_data = vec![0u8; category_length as usize];
                reader.read_exact(&mut category_data)?;

                situation.secrecy = Some(SituationData {
                    level: level_data.into(),
                    category: category_data.into(),
                });
            }

            if situation_flags.contains(SituationFlags::INTEGRITY) {
                let level_length = reader.read_u16::<BigEndian>()?;
                reader.read_u16::<BigEndian>()?;
                let mut level_data = vec![0u8; level_length as usize];
                reader.read_exact(&mut level_data)?;

                let category_length = reader.read_u16::<BigEndian>()?;
                reader.read_u16::<BigEndian>()?;
                let mut category_data = vec![0u8; category_length as usize];
                reader.read_exact(&mut category_data)?;

                situation.integrity = Some(SituationData {
                    level: level_data.into(),
                    category: category_data.into(),
                });
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
        for (i, trans) in self.transforms.iter().enumerate() {
            buf.put_u8(
                self.transforms
                    .get(i + 1)
                    .map_or(PayloadType::None, |_| PayloadType::Transform)
                    .into(),
            );
            buf.put_u8(0);
            buf.put_u16(4 + trans.len() as u16);
            buf.put_slice(&trans.to_bytes());
        }

        buf.freeze()
    }

    fn len(&self) -> usize {
        self.transforms
            .iter()
            .fold(4 + (self.spi.len() & 255), |len, p| len + p.len() + 4)
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
            Err(anyhow!("Invalid transforms payload"))
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
        let mut data = Vec::new();
        reader.read_to_end(&mut data)?;
        Ok(Self {
            doi,
            protocol_id,
            message_type: message_type.into(),
            spi: spi_data.into(),
            data: data.into(),
        })
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct BasicPayload {
    pub data: Bytes,
}

impl BasicPayload {
    pub fn new(data: Bytes) -> Self {
        Self { data }
    }
}

impl<T: AsRef<[u8]>> From<T> for BasicPayload {
    fn from(value: T) -> Self {
        Self::new(Bytes::copy_from_slice(value.as_ref()))
    }
}

impl PayloadLike for BasicPayload {
    fn to_bytes(&self) -> Bytes {
        self.data.clone()
    }

    fn len(&self) -> usize {
        self.data.len()
    }

    fn parse<R: Read>(reader: &mut R) -> anyhow::Result<Self> {
        let mut data = Vec::new();
        reader.read_to_end(&mut data)?;
        Ok(Self { data: data.into() })
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

        let mut data = Vec::new();
        reader.read_to_end(&mut data)?;

        let mut attributes = Vec::new();
        let mut cursor = Cursor::new(data);
        while cursor.has_remaining() {
            attributes.push(DataAttribute::parse(&mut cursor)?);
        }

        Ok(Self {
            transform_num,
            transform_id,
            attributes,
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
        let mut data = Vec::new();
        reader.read_to_end(&mut data)?;
        Ok(Self {
            id_type,
            protocol_id,
            port,
            data: data.into(),
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
        let mut data = Vec::new();
        reader.read_to_end(&mut data)?;
        Ok(Self {
            certificate_type,
            data: data.into(),
        })
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
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
        let mut data = Vec::new();
        reader.read_to_end(&mut data)?;
        let mut cursor = Cursor::new(data);
        let mut attributes = Vec::new();
        while cursor.has_remaining() {
            attributes.push(DataAttribute::parse(&mut cursor)?);
        }
        Ok(Self {
            attributes_payload_type,
            identifier,
            attributes,
        })
    }
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
            | Payload::Signature(p) => p.to_bytes(),
            Payload::Identification(p) => p.to_bytes(),
            Payload::Certificate(p) | Payload::CertificateRequest(p) => p.to_bytes(),
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
            | Payload::Signature(p) => p.len(),
            Payload::Identification(p) => p.len(),
            Payload::Certificate(p) | Payload::CertificateRequest(p) => p.len(),
            Payload::Attributes(p) => p.len(),
            Payload::Other(_, p) => p.len(),
        }
    }

    // never empty
    pub fn is_empty(&self) -> bool {
        false
    }

    fn parse<R: Read>(next_payload: PayloadType, reader: &mut R) -> anyhow::Result<Self> {
        match next_payload {
            PayloadType::SecurityAssociation => {
                Ok(Payload::SecurityAssociation(SecurityAssociationPayload::parse(reader)?))
            }
            PayloadType::Proposal => Ok(Payload::Proposal(ProposalPayload::parse(reader)?)),
            PayloadType::Transform => Ok(Payload::Transform(TransformPayload::parse(reader)?)),
            PayloadType::Notification => Ok(Payload::Notification(NotificationPayload::parse(reader)?)),
            PayloadType::Delete => Ok(Payload::Delete(DeletePayload::parse(reader)?)),
            PayloadType::VendorId => Ok(Payload::VendorId(BasicPayload::parse(reader)?)),
            PayloadType::KeyExchange => Ok(Payload::KeyExchange(BasicPayload::parse(reader)?)),
            PayloadType::Nonce => Ok(Payload::Nonce(BasicPayload::parse(reader)?)),
            PayloadType::Identification => Ok(Payload::Identification(IdentificationPayload::parse(reader)?)),
            PayloadType::Hash => Ok(Payload::Hash(BasicPayload::parse(reader)?)),
            PayloadType::Natd => Ok(Payload::Natd(BasicPayload::parse(reader)?)),
            PayloadType::Signature => Ok(Payload::Signature(BasicPayload::parse(reader)?)),
            PayloadType::Certificate => Ok(Payload::Certificate(CertificatePayload::parse(reader)?)),
            PayloadType::CertificateRequest => Ok(Payload::CertificateRequest(CertificatePayload::parse(reader)?)),
            PayloadType::Attributes => Ok(Payload::Attributes(AttributesPayload::parse(reader)?)),
            _ => Ok(Payload::Other(next_payload, BasicPayload::parse(reader)?)),
        }
    }

    pub fn as_payload_type(&self) -> PayloadType {
        match self {
            Self::SecurityAssociation(_) => PayloadType::SecurityAssociation,
            Self::Proposal(_) => PayloadType::Proposal,
            Self::Notification(_) => PayloadType::Notification,
            Self::Delete(_) => PayloadType::Delete,
            Self::Transform(_) => PayloadType::Transform,
            Self::VendorId(_) => PayloadType::VendorId,
            Self::KeyExchange(_) => PayloadType::KeyExchange,
            Self::Nonce(_) => PayloadType::Nonce,
            Self::Identification(_) => PayloadType::Identification,
            Self::Hash(_) => PayloadType::Hash,
            Self::Certificate(_) => PayloadType::Certificate,
            Self::CertificateRequest(_) => PayloadType::CertificateRequest,
            Self::Signature(_) => PayloadType::Signature,
            Self::Attributes(_) => PayloadType::Attributes,
            Self::Natd(_) => PayloadType::Natd,
            Self::Other(t, _) => *t,
        }
    }

    pub fn parse_all<R: Read>(next_payload: PayloadType, reader: &mut R) -> anyhow::Result<Vec<Payload>> {
        let mut result = Vec::new();
        let mut next_payload = next_payload;
        while next_payload != PayloadType::None {
            let (n, data) = read_next_payload(reader)?;
            trace!(
                "Parsing payload: type={:?}, size={}, next={:?}",
                next_payload,
                data.len(),
                n
            );
            let mut cursor = Cursor::new(data);
            let payload = Self::parse(next_payload, &mut cursor)?;
            result.push(payload);
            next_payload = n;
        }
        Ok(result)
    }
}
