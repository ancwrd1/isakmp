use std::{net::Ipv4Addr, sync::Arc, time::Duration};

use anyhow::anyhow;
use byteorder::{BigEndian, ReadBytesExt};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use parking_lot::RwLock;
use rand::random;
use tracing::{debug, trace};

use crate::{
    message::IsakmpMessage, model::*, payload::*, session::Ikev1Session, transport::IsakmpTransport,
};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

pub struct Ikev1<T> {
    socket_timeout: Duration,
    transport: T,
    session: Arc<RwLock<Ikev1Session>>,
}

impl<T: IsakmpTransport + Send> Ikev1<T> {
    pub fn new(transport: T, session: Arc<RwLock<Ikev1Session>>) -> anyhow::Result<Self> {
        Ok(Self {
            socket_timeout: DEFAULT_TIMEOUT,
            transport,
            session,
        })
    }

    fn build_ike_sa(&self) -> anyhow::Result<IsakmpMessage> {
        let attributes = vec![
            DataAttribute::short(
                IkeAttributeType::EncryptionAlgorithm.into(),
                IkeEncryptionAlgorithm::AesCbc.into(),
            ),
            DataAttribute::short(
                IkeAttributeType::HashAlgorithm.into(),
                IkeHashAlgorithm::Sha256.into(),
            ),
            DataAttribute::short(
                IkeAttributeType::GroupDescription.into(),
                IkeGroupDescription::Oakley2.into(),
            ),
            DataAttribute::short(
                IkeAttributeType::AuthenticationMethod.into(),
                IkeAuthMethod::HybridInitRsa.into(),
            ),
            DataAttribute::short(IkeAttributeType::LifeType.into(), LifeType::Seconds.into()),
            DataAttribute::short(IkeAttributeType::LifeDuration.into(), 28800),
            DataAttribute::short(IkeAttributeType::KeyLength.into(), 256),
        ];

        let transforms = vec![TransformPayload {
            transform_num: 1,
            transform_id: TransformId::KeyIke,
            attributes,
        }];
        let proposal = Payload::Proposal(ProposalPayload {
            proposal_num: 1,
            protocol_id: ProtocolId::Isakmp,
            spi: Default::default(),
            transforms,
        });

        let sa = Payload::SecurityAssociation(SecurityAssociationPayload {
            doi: 1,
            situation: None,
            payloads: vec![proposal],
        });

        let vid1 = Payload::VendorId(hex::decode(CHECKPOINT_VID)?.into());
        let vid2 = Payload::VendorId(hex::decode(NATT_VID)?.into());
        let vid3 = Payload::VendorId(hex::decode(EXT_VID_WITH_FLAGS)?.into());

        Ok(IsakmpMessage {
            cookie_i: self.session.read().cookie_i,
            cookie_r: 0,
            version: 0x10,
            exchange_type: ExchangeType::IdentityProtection,
            flags: IsakmpFlags::empty(),
            message_id: 0,
            payloads: vec![sa, vid1, vid2, vid3],
        })
    }

    fn build_esp_sa(&self, spi: u32, nonce: &[u8]) -> anyhow::Result<IsakmpMessage> {
        let attributes = vec![
            DataAttribute::short(EspAttributeType::LifeType.into(), LifeType::Seconds.into()),
            DataAttribute::short(EspAttributeType::LifeDuration.into(), 3600),
            DataAttribute::short(
                EspAttributeType::AuthenticationAlgorithm.into(),
                EspAuthAlgorithm::HmacSha256.into(),
            ),
            DataAttribute::short(
                EspAttributeType::EncapsulationMode.into(),
                EspEncapMode::UdpTunnel.into(),
            ),
            DataAttribute::short(EspAttributeType::KeyLength.into(), 256),
        ];

        let transforms = vec![TransformPayload {
            transform_num: 1,
            transform_id: TransformId::EspAesCbc,
            attributes,
        }];

        let proposal = Payload::Proposal(ProposalPayload {
            proposal_num: 1,
            protocol_id: ProtocolId::IpsecEsp,
            spi: Bytes::copy_from_slice(&spi.to_be_bytes()),
            transforms,
        });

        let sa_payload = Payload::SecurityAssociation(SecurityAssociationPayload {
            doi: 1,
            situation: None,
            payloads: vec![proposal],
        });

        let nonce_payload = Payload::Nonce(nonce.into());

        let message_id: u32 = random();

        let session = self.session.read();

        let hash_payload =
            self.make_hash_from_payloads(&session, message_id, &[&sa_payload, &nonce_payload])?;

        let message = IsakmpMessage {
            cookie_i: session.cookie_i,
            cookie_r: session.cookie_r,
            version: 0x10,
            exchange_type: ExchangeType::Quick,
            flags: IsakmpFlags::ENCRYPTION,
            message_id,
            payloads: vec![hash_payload, sa_payload, nonce_payload],
        };

        Ok(message)
    }

    fn build_ke(&self, local_ip: Ipv4Addr, gateway_ip: Ipv4Addr) -> anyhow::Result<IsakmpMessage> {
        let session = self.session.read();

        let ke = Payload::KeyExchange(session.public_key_i.as_ref().into());
        let nonce = Payload::Nonce(session.nonce_i.as_ref().into());

        let remote_ip: u32 = gateway_ip.into();

        let hash_r = session.crypto.hash([
            session.cookie_i.to_be_bytes().as_slice(),
            session.cookie_r.to_be_bytes().as_slice(),
            remote_ip.to_be_bytes().as_slice(),
            4500u16.to_be_bytes().as_slice(),
        ])?;

        let natd_r_payload = Payload::Natd(BasicPayload::new(hash_r));

        let local_ip: u32 = local_ip.into();

        let hash_i = session.crypto.hash([
            session.cookie_i.to_be_bytes().as_slice(),
            session.cookie_r.to_be_bytes().as_slice(),
            local_ip.to_be_bytes().as_slice(),
            &[0, 0],
        ])?;

        let natd_i_payload = Payload::Natd(BasicPayload::new(hash_i));

        Ok(IsakmpMessage {
            cookie_i: session.cookie_i,
            cookie_r: session.cookie_r,
            version: 0x10,
            exchange_type: ExchangeType::IdentityProtection,
            flags: IsakmpFlags::empty(),
            message_id: 0,
            payloads: vec![ke, nonce, natd_r_payload, natd_i_payload],
        })
    }

    fn build_id(&self, notify_data: Bytes) -> anyhow::Result<IsakmpMessage> {
        let id_payload = Payload::Identification(IdentificationPayload {
            id_type: IdentityType::UserFqdn.into(),
            protocol_id: 0,
            port: 0,
            data: Bytes::new(),
        });

        let session = self.session.read();

        let notify_payload = Payload::Notification(NotificationPayload {
            doi: 0,
            protocol_id: ProtocolId::Isakmp,
            message_type: NotifyMessageType::CccAuth.into(),
            spi: session
                .cookie_i
                .to_be_bytes()
                .into_iter()
                .chain(session.cookie_r.to_be_bytes())
                .collect(),
            data: notify_data,
        });

        let hash_i = session.hash_i(id_payload.to_bytes().as_ref())?;

        let hash_payload = Payload::Hash(BasicPayload::new(hash_i));

        Ok(IsakmpMessage {
            cookie_i: session.cookie_i,
            cookie_r: session.cookie_r,
            version: 0x10,
            exchange_type: ExchangeType::IdentityProtection,
            flags: IsakmpFlags::ENCRYPTION,
            message_id: 0,
            payloads: vec![hash_payload, id_payload, notify_payload],
        })
    }

    fn build_auth_attr(
        &self,
        identifier: u16,
        message_id: u32,
        attribute_type: ConfigAttributeType,
        data: Bytes,
    ) -> anyhow::Result<IsakmpMessage> {
        let attrs_payload = Payload::Attributes(AttributesPayload {
            attributes_payload_type: AttributesPayloadType::Reply,
            identifier,
            attributes: vec![
                DataAttribute::short(
                    ConfigAttributeType::AuthType.into(),
                    UserAuthType::Generic.into(),
                ),
                DataAttribute::long(attribute_type.into(), data),
            ],
        });

        let session = self.session.read();

        let hash_payload = self.make_hash_from_payloads(&session, message_id, &[&attrs_payload])?;

        Ok(IsakmpMessage {
            cookie_i: session.cookie_i,
            cookie_r: session.cookie_r,
            version: 0x10,
            exchange_type: ExchangeType::Transaction,
            flags: IsakmpFlags::ENCRYPTION,
            message_id,
            payloads: vec![hash_payload, attrs_payload],
        })
    }

    fn build_ack_cfg(&self, identifier: u16, message_id: u32) -> anyhow::Result<IsakmpMessage> {
        let attrs_payload = Payload::Attributes(AttributesPayload {
            attributes_payload_type: AttributesPayloadType::Ack,
            identifier,
            attributes: vec![DataAttribute::short(ConfigAttributeType::Status.into(), 1)],
        });

        let session = self.session.read();

        let hash_payload = self.make_hash_from_payloads(&session, message_id, &[&attrs_payload])?;

        Ok(IsakmpMessage {
            cookie_i: session.cookie_i,
            cookie_r: session.cookie_r,
            version: 0x10,
            exchange_type: ExchangeType::Transaction,
            flags: IsakmpFlags::ENCRYPTION,
            message_id,
            payloads: vec![hash_payload, attrs_payload],
        })
    }

    fn build_om_cfg(&self) -> anyhow::Result<IsakmpMessage> {
        let empty_attrs = [
            ConfigAttributeType::Ipv4Address,
            ConfigAttributeType::Ipv4Netmask,
            ConfigAttributeType::Ipv4Dns,
            ConfigAttributeType::AddressExpiry,
            ConfigAttributeType::InternalDomainName,
            ConfigAttributeType::CccSessionId,
        ];

        let attributes = empty_attrs
            .into_iter()
            .map(|a| DataAttribute::long(a.into(), Bytes::copy_from_slice(&[0, 0, 0, 0])))
            .chain(Some(DataAttribute::long(
                ConfigAttributeType::MacAddress.into(),
                Bytes::copy_from_slice(&random::<[u8; 6]>()),
            )))
            .collect();

        let attrs_payload = Payload::Attributes(AttributesPayload {
            attributes_payload_type: AttributesPayloadType::Request,
            identifier: random(),
            attributes,
        });

        let message_id: u32 = random();

        let session = self.session.read();

        let hash_payload = self.make_hash_from_payloads(&session, message_id, &[&attrs_payload])?;

        Ok(IsakmpMessage {
            cookie_i: session.cookie_i,
            cookie_r: session.cookie_r,
            version: 0x10,
            exchange_type: ExchangeType::Transaction,
            flags: IsakmpFlags::ENCRYPTION,
            message_id,
            payloads: vec![hash_payload, attrs_payload],
        })
    }

    fn make_hash_from_payloads(
        &self,
        session: &Ikev1Session,
        message_id: u32,
        payloads: &[&Payload],
    ) -> anyhow::Result<Payload> {
        let mut buf = BytesMut::new();
        for (i, payload) in payloads.iter().enumerate() {
            let data = payload.to_bytes();
            let next_payload = payloads
                .get(i + 1)
                .map(|p| p.as_payload_type())
                .unwrap_or(PayloadType::None);
            buf.put_u8(next_payload.into());
            buf.put_u8(0);
            buf.put_u16(4 + data.len() as u16);
            buf.put_slice(&data);
        }
        let data = buf.freeze();

        let hash = session.crypto.prf(
            &session.s_key_id_a,
            [message_id.to_be_bytes().as_slice(), &data],
        )?;

        Ok(Payload::Hash(BasicPayload::new(hash)))
    }

    pub async fn do_sa_proposal(&mut self) -> anyhow::Result<()> {
        debug!("Begin SA proposal");

        let request = self.build_ike_sa()?;
        let sa_bytes = request.payloads[0].to_bytes();

        let response = self
            .transport
            .send_receive(&request, self.socket_timeout)
            .await?;

        self.session
            .write()
            .init_from_sa(response.cookie_r, sa_bytes);

        debug!("End SA proposal");

        Ok(())
    }

    pub async fn do_key_exchange(
        &mut self,
        local_ip: Ipv4Addr,
        gateway_ip: Ipv4Addr,
    ) -> anyhow::Result<()> {
        debug!("Begin key exchange");

        let request = self.build_ke(local_ip, gateway_ip)?;

        let response = self
            .transport
            .send_receive(&request, self.socket_timeout)
            .await?;

        let public_key_r = response
            .payloads
            .iter()
            .find_map(|p| match p {
                Payload::KeyExchange(ke) => Some(ke.data.clone()),
                _ => None,
            })
            .ok_or_else(|| anyhow!("No KE in response!"))?;

        trace!("Responder's public key length: {}", public_key_r.len());

        let nonce_r = response
            .payloads
            .iter()
            .find_map(|p| match p {
                Payload::Nonce(ke) => Some(ke.data.clone()),
                _ => None,
            })
            .ok_or_else(|| anyhow!("No nonce in response!"))?;

        trace!("Responder's nonce length: {}", nonce_r.len());

        self.session.write().init_from_ke(public_key_r, nonce_r)?;

        trace!("COOKIE_i: {:08x}", self.session.read().cookie_i);
        trace!("SKEYID_e: {}", hex::encode(&self.session.read().s_key_id_e));

        debug!("End key exchange");

        Ok(())
    }

    fn get_attributes_payload(
        &mut self,
        response: IsakmpMessage,
    ) -> anyhow::Result<AttributesPayload> {
        response
            .payloads
            .into_iter()
            .find_map(|p| match p {
                Payload::Attributes(p) => Some(p),
                _ => None,
            })
            .ok_or_else(|| anyhow!("No config payload in response!"))
    }

    pub async fn do_identity_protection(
        &mut self,
        notify_data: Bytes,
    ) -> anyhow::Result<(AttributesPayload, u32)> {
        debug!("Begin identity protection");

        let request = self.build_id(notify_data)?;

        self.transport
            .send_receive(&request, self.socket_timeout)
            .await?;

        let response = self.transport.receive(self.socket_timeout).await?;
        let message_id = response.message_id;

        debug!("Response message ID: {:04x}", message_id);

        let config = self.get_attributes_payload(response)?;

        debug!("End identity protection");

        Ok((config, message_id))
    }

    pub async fn send_auth_attribute(
        &mut self,
        identifier: u16,
        message_id: u32,
        attribute_type: ConfigAttributeType,
        data: Bytes,
        timeout: Option<Duration>,
    ) -> anyhow::Result<(AttributesPayload, u32)> {
        debug!(
            "Sending auth attribute: {:?}, timeout: {:?} seconds",
            attribute_type,
            timeout.map(|t| t.as_secs())
        );

        let request = self.build_auth_attr(identifier, message_id, attribute_type, data)?;
        let response = self
            .transport
            .send_receive(&request, timeout.unwrap_or(self.socket_timeout))
            .await?;
        let message_id = response.message_id;
        debug!("Message ID: {:04x}", message_id);

        let config = self.get_attributes_payload(response)?;

        debug!("Response message ID: {:04x}", message_id);

        Ok((config, message_id))
    }

    pub async fn send_ack_response(
        &mut self,
        identifier: u16,
        message_id: u32,
    ) -> anyhow::Result<()> {
        debug!("Sending ACK response");
        let request = self.build_ack_cfg(identifier, message_id)?;
        self.transport.send(&request).await?;

        Ok(())
    }

    pub async fn send_om_request(&mut self) -> anyhow::Result<AttributesPayload> {
        debug!("Begin sending OM request");

        let request = self.build_om_cfg()?;
        let response = self
            .transport
            .send_receive(&request, self.socket_timeout)
            .await?;

        debug!("End sending OM request");

        self.get_attributes_payload(response)
    }

    pub async fn do_esp_proposal(&mut self) -> anyhow::Result<()> {
        let spi_i: u32 = random();
        let nonce_i = Bytes::copy_from_slice(&random::<[u8; 32]>());

        debug!("Begin ESP SA proposal");

        let request = self.build_esp_sa(spi_i, &nonce_i)?;

        let response = self
            .transport
            .send_receive(&request, self.socket_timeout)
            .await?;

        let nonce_r = response
            .payloads
            .iter()
            .find_map(|p| match p {
                Payload::Nonce(payload) => Some(payload.data.clone()),
                _ => None,
            })
            .ok_or_else(|| anyhow!("No nonce payload in response!"))?;

        let spi_r = response
            .payloads
            .into_iter()
            .find_map(|p| match p {
                Payload::SecurityAssociation(payload) => {
                    payload.payloads.into_iter().find_map(|p| match p {
                        Payload::Proposal(proposal) => {
                            proposal.spi.reader().read_u32::<BigEndian>().ok()
                        }
                        _ => None,
                    })
                }
                _ => None,
            })
            .ok_or_else(|| anyhow!("No proposal payload in response!"))?;

        let session = self.session.read();

        let prf = session.crypto.prf(
            session.s_key_id_a.as_ref(),
            [
                &[0],
                response.message_id.to_be_bytes().as_slice(),
                &nonce_i,
                &nonce_r,
            ],
        )?;

        let hash_msg = IsakmpMessage {
            cookie_i: session.cookie_i,
            cookie_r: session.cookie_r,
            version: 0x10,
            exchange_type: ExchangeType::Quick,
            flags: IsakmpFlags::ENCRYPTION,
            message_id: response.message_id,
            payloads: vec![Payload::Hash(BasicPayload::new(prf))],
        };

        drop(session);

        self.transport.send(&hash_msg).await?;

        self.session
            .write()
            .init_from_qm(spi_i, nonce_i, spi_r, nonce_r)?;

        let session = self.session.read();

        trace!("IN  SPI : {:04x}", session.esp_in.spi);
        trace!("IN  ENC : {}", hex::encode(&session.esp_in.sk_e));
        trace!("IN  AUTH: {}", hex::encode(&session.esp_in.sk_a));
        trace!("OUT SPI : {:04x}", session.esp_out.spi);
        trace!("OUT ENC : {}", hex::encode(&session.esp_out.sk_e));
        trace!("OUT AUTH: {}", hex::encode(&session.esp_out.sk_a));

        debug!("End ESP SA proposal");

        Ok(())
    }
}
