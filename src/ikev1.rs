use std::{net::Ipv4Addr, time::Duration};

use anyhow::anyhow;
use byteorder::{BigEndian, ReadBytesExt};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use rand::random;
use tracing::{debug, trace};

use session::Ikev1Session;

use crate::session::IsakmpSession;
use crate::{
    ikev1::session::Ikev1SessionRef, message::IsakmpMessage, model::*, payload::*,
    transport::IsakmpTransport,
};

pub mod codec;
pub mod session;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

pub struct Ikev1Service<T> {
    socket_timeout: Duration,
    transport: T,
    session: Ikev1SessionRef,
}

impl<T: IsakmpTransport + Send> Ikev1Service<T> {
    pub fn new(transport: T, session: Ikev1SessionRef) -> anyhow::Result<Self> {
        Ok(Self {
            socket_timeout: DEFAULT_TIMEOUT,
            transport,
            session,
        })
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    fn build_ike_sa(&self, lifetime: Duration) -> anyhow::Result<IsakmpMessage> {
        let mut transforms = Vec::new();

        for auth in [IkeHashAlgorithm::Sha256, IkeHashAlgorithm::Sha] {
            for key_len in [256, 128] {
                let attributes = vec![
                    DataAttribute::short(
                        IkeAttributeType::EncryptionAlgorithm.into(),
                        IkeEncryptionAlgorithm::AesCbc.into(),
                    ),
                    DataAttribute::short(IkeAttributeType::HashAlgorithm.into(), auth.into()),
                    DataAttribute::short(
                        IkeAttributeType::GroupDescription.into(),
                        IkeGroupDescription::Oakley2.into(),
                    ),
                    DataAttribute::short(
                        IkeAttributeType::AuthenticationMethod.into(),
                        if self.session.read().cert_data().is_some() {
                            IkeAuthMethod::RsaSignature.into()
                        } else {
                            IkeAuthMethod::HybridInitRsa.into()
                        },
                    ),
                    DataAttribute::short(
                        IkeAttributeType::LifeType.into(),
                        LifeType::Seconds.into(),
                    ),
                    DataAttribute::long(
                        IkeAttributeType::LifeDuration.into(),
                        Bytes::copy_from_slice(&(lifetime.as_secs() as u32).to_be_bytes()),
                    ),
                    DataAttribute::short(IkeAttributeType::KeyLength.into(), key_len),
                ];

                transforms.push(TransformPayload {
                    transform_num: (transforms.len() + 1) as _,
                    transform_id: TransformId::KeyIke,
                    attributes,
                });
            }
        }

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

        let mut payloads = vec![sa, vid1, vid2, vid3];

        if let Some(cert_data) = self.session.read().cert_data() {
            payloads.push(Payload::CertificateRequest(CertificatePayload {
                certificate_type: CertificateType::X509ForSignature,
                data: cert_data.issuer(),
            }));
            payloads.push(Payload::CertificateRequest(CertificatePayload {
                certificate_type: CertificateType::X509ForSignature,
                data: Default::default(),
            }));
        }

        Ok(IsakmpMessage {
            cookie_i: self.session.read().cookie_i,
            cookie_r: 0,
            version: 0x10,
            exchange_type: ExchangeType::IdentityProtection,
            flags: IsakmpFlags::empty(),
            message_id: 0,
            payloads,
        })
    }

    #[allow(clippy::single_element_loop)]
    fn build_esp_sa(
        &self,
        spi: u32,
        nonce: &[u8],
        ipaddr: Ipv4Addr,
        lifetime: Duration,
    ) -> anyhow::Result<IsakmpMessage> {
        let mut transforms = Vec::new();

        for auth in [EspAuthAlgorithm::HmacSha256] {
            for key_len in [256] {
                let attributes = vec![
                    DataAttribute::short(
                        EspAttributeType::LifeType.into(),
                        LifeType::Seconds.into(),
                    ),
                    DataAttribute::long(
                        EspAttributeType::LifeDuration.into(),
                        Bytes::copy_from_slice(&(lifetime.as_secs() as u32).to_be_bytes()),
                    ),
                    DataAttribute::short(
                        EspAttributeType::AuthenticationAlgorithm.into(),
                        auth.into(),
                    ),
                    DataAttribute::short(
                        EspAttributeType::EncapsulationMode.into(),
                        EspEncapMode::UdpTunnel.into(),
                    ),
                    DataAttribute::short(EspAttributeType::KeyLength.into(), key_len),
                ];
                transforms.push(TransformPayload {
                    transform_num: (transforms.len() + 1) as _,
                    transform_id: TransformId::EspAesCbc,
                    attributes,
                });
            }
        }

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

        let ip_payload = Payload::Identification(IdentificationPayload {
            id_type: IdentityType::Ipv4Address.into(),
            protocol_id: 0,
            port: 0,
            data: Bytes::copy_from_slice(&u32::from(ipaddr).to_be_bytes()),
        });

        let netmask_payload = Payload::Identification(IdentificationPayload {
            id_type: IdentityType::Ipv4Subnet.into(),
            protocol_id: 0,
            port: 0,
            data: Bytes::copy_from_slice(&0u64.to_be_bytes()),
        });

        let message_id: u32 = random();

        let session = self.session.read();

        let hash_payload = self.make_hash_from_payloads(
            &session,
            message_id,
            &[&sa_payload, &nonce_payload, &ip_payload, &netmask_payload],
        )?;

        let message = IsakmpMessage {
            cookie_i: session.cookie_i,
            cookie_r: session.cookie_r,
            version: 0x10,
            exchange_type: ExchangeType::Quick,
            flags: IsakmpFlags::ENCRYPTION,
            message_id,
            payloads: vec![
                hash_payload,
                sa_payload,
                nonce_payload,
                ip_payload,
                netmask_payload,
            ],
        };

        Ok(message)
    }

    fn build_delete_sa(&mut self) -> anyhow::Result<IsakmpMessage> {
        let session = self.session.read();

        let message_id = random();

        let delete_payload = Payload::Delete(DeletePayload {
            doi: 0,
            protocol_id: ProtocolId::Isakmp,
            spi_size: 16,
            spi: vec![
                Bytes::copy_from_slice(session.cookie_i.to_be_bytes().as_slice()),
                Bytes::copy_from_slice(session.cookie_r.to_be_bytes().as_slice()),
            ],
        });

        let hash_payload =
            self.make_hash_from_payloads(&session, message_id, &[&delete_payload])?;

        Ok(IsakmpMessage {
            cookie_i: session.cookie_i,
            cookie_r: session.cookie_r,
            version: 0x10,
            exchange_type: ExchangeType::Informational,
            flags: IsakmpFlags::empty(),
            message_id,
            payloads: vec![delete_payload, hash_payload],
        })
    }

    fn build_ke(&self, local_ip: Ipv4Addr, gateway_ip: Ipv4Addr) -> anyhow::Result<IsakmpMessage> {
        let session = self.session.read();

        let ke = Payload::KeyExchange(session.public_key_i.as_ref().into());
        let nonce = Payload::Nonce(session.nonce_i.as_ref().into());

        let remote_ip: u32 = gateway_ip.into();

        let hash_r = session.hash([
            session.cookie_i.to_be_bytes().as_slice(),
            session.cookie_r.to_be_bytes().as_slice(),
            remote_ip.to_be_bytes().as_slice(),
            4500u16.to_be_bytes().as_slice(),
        ])?;

        let natd_r_payload = Payload::Natd(BasicPayload::new(hash_r));

        let local_ip: u32 = local_ip.into();

        let hash_i = session.hash([
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

    fn build_id_protection(&self, notify_data: Bytes) -> anyhow::Result<IsakmpMessage> {
        let session = self.session.read();

        let id_payload = if let Some(cert_data) = session.cert_data() {
            Payload::Identification(IdentificationPayload {
                id_type: IdentityType::DerAsn1Dn.into(),
                data: cert_data.subject(),
                ..Default::default()
            })
        } else {
            Payload::Identification(IdentificationPayload {
                id_type: IdentityType::UserFqdn.into(),
                ..Default::default()
            })
        };

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

        let payloads = if let Some(cert_data) = session.cert_data() {
            let mut payloads = vec![id_payload];

            payloads.extend(cert_data.certs().into_iter().map(|cert| {
                Payload::Certificate(CertificatePayload {
                    certificate_type: CertificateType::X509ForSignature,
                    data: cert,
                })
            }));

            let sig_payload = Payload::Signature(BasicPayload::new(cert_data.sign(&hash_i)?));

            payloads.push(sig_payload);
            payloads.push(notify_payload);

            payloads
        } else {
            let hash_payload = Payload::Hash(BasicPayload::new(hash_i));
            vec![hash_payload, id_payload, notify_payload]
        };

        Ok(IsakmpMessage {
            cookie_i: session.cookie_i,
            cookie_r: session.cookie_r,
            version: 0x10,
            exchange_type: ExchangeType::IdentityProtection,
            flags: IsakmpFlags::ENCRYPTION,
            message_id: 0,
            payloads,
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

    pub async fn do_sa_proposal(
        &mut self,
        lifetime: Duration,
    ) -> anyhow::Result<Vec<DataAttribute>> {
        debug!("Begin SA proposal");

        let request = self.build_ike_sa(lifetime)?;
        let sa_bytes = request.payloads[0].to_bytes();

        let response = self
            .transport
            .send_receive(&request, self.socket_timeout)
            .await?;

        let attributes = response
            .payloads
            .into_iter()
            .find_map(|p| match p {
                Payload::SecurityAssociation(payload) => {
                    payload.payloads.into_iter().find_map(|p| match p {
                        Payload::Proposal(proposal) => {
                            proposal.transforms.into_iter().next().map(|t| t.attributes)
                        }
                        _ => None,
                    })
                }
                _ => None,
            })
            .ok_or_else(|| anyhow!("No attributes in response!"))?;

        let hash_alg: IkeHashAlgorithm = attributes
            .iter()
            .find_map(|a| {
                if a.attribute_type == IkeAttributeType::HashAlgorithm.into() {
                    a.as_short().map(Into::into)
                } else {
                    None
                }
            })
            .ok_or_else(|| anyhow!("No hash algorithm in response!"))?;

        debug!("Negotiated SA hash algorithm: {:?}", hash_alg);

        let key_len = attributes
            .iter()
            .find_map(|a| {
                if a.attribute_type == IkeAttributeType::KeyLength.into() {
                    a.as_short().map(|k| k as usize / 8)
                } else {
                    None
                }
            })
            .ok_or_else(|| anyhow!("No hash algorithm in response!"))?;

        debug!("Negotiated SA key length: {}", key_len);

        self.session
            .write()
            .init_from_sa(response.cookie_r, sa_bytes, hash_alg, key_len)?;

        debug!("End SA proposal");

        Ok(attributes)
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

    pub async fn get_auth_attributes(&mut self) -> anyhow::Result<(AttributesPayload, u32)> {
        debug!("Waiting for attributes payload");

        let attr_response = self.transport.receive(self.socket_timeout).await?;

        let message_id = attr_response.message_id;

        debug!("Attributes message ID: {:04x}", message_id);

        Ok((self.get_attributes_payload(attr_response)?, message_id))
    }

    pub async fn do_identity_protection(
        &mut self,
        notify_data: Bytes,
    ) -> anyhow::Result<IdentificationPayload> {
        debug!("Begin identity protection");

        let request = self.build_id_protection(notify_data)?;

        let response = self
            .transport
            .send_receive(&request, self.socket_timeout)
            .await?;

        Ok(response
            .payloads
            .into_iter()
            .find_map(|payload| match payload {
                Payload::Identification(id) => Some(id),
                _ => None,
            })
            .ok_or_else(|| anyhow!("No identification payload in response!"))?)
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

    pub async fn do_esp_proposal(
        &mut self,
        ipaddr: Ipv4Addr,
        lifetime: Duration,
    ) -> anyhow::Result<Vec<DataAttribute>> {
        let spi_i: u32 = random();
        let nonce_i = Bytes::copy_from_slice(&random::<[u8; 32]>());

        debug!("Begin ESP SA proposal");

        let request = self.build_esp_sa(spi_i, &nonce_i, ipaddr, lifetime)?;

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
            .iter()
            .find_map(|p| match p {
                Payload::SecurityAssociation(payload) => {
                    payload.payloads.iter().find_map(|p| match p {
                        Payload::Proposal(proposal) => {
                            proposal.spi.clone().reader().read_u32::<BigEndian>().ok()
                        }
                        _ => None,
                    })
                }
                _ => None,
            })
            .ok_or_else(|| anyhow!("No proposal payload in response!"))?;

        let attributes = response
            .payloads
            .into_iter()
            .find_map(|p| match p {
                Payload::SecurityAssociation(payload) => {
                    payload.payloads.into_iter().find_map(|p| match p {
                        Payload::Proposal(proposal) => {
                            proposal.transforms.into_iter().next().map(|t| t.attributes)
                        }
                        _ => None,
                    })
                }
                _ => None,
            })
            .ok_or_else(|| anyhow!("No attributes in response!"))?;

        let prf = self.session.read().crypto.prf(
            self.session.read().s_key_id_a.as_ref(),
            [
                &[0],
                response.message_id.to_be_bytes().as_slice(),
                &nonce_i,
                &nonce_r,
            ],
        )?;

        let auth_alg: EspAuthAlgorithm = attributes
            .iter()
            .find_map(|a| {
                if a.attribute_type == EspAttributeType::AuthenticationAlgorithm.into() {
                    a.as_short().map(Into::into)
                } else {
                    None
                }
            })
            .ok_or_else(|| anyhow!("No auth algorithm in response!"))?;

        debug!("Negotiated ESP auth algorithm: {:?}", auth_alg);

        let key_len = attributes
            .iter()
            .find_map(|a| {
                if a.attribute_type == EspAttributeType::KeyLength.into() {
                    a.as_short().map(|k| k as usize)
                } else {
                    None
                }
            })
            .unwrap_or(128)
            / 8;

        debug!("Negotiated ESP key length: {}", key_len);

        let hash_msg = IsakmpMessage {
            cookie_i: self.session.read().cookie_i,
            cookie_r: self.session.read().cookie_r,
            version: 0x10,
            exchange_type: ExchangeType::Quick,
            flags: IsakmpFlags::ENCRYPTION,
            message_id: response.message_id,
            payloads: vec![Payload::Hash(BasicPayload::new(prf))],
        };

        self.transport.send(&hash_msg).await?;

        self.session
            .write()
            .init_from_qm(spi_i, nonce_i, spi_r, nonce_r, auth_alg, key_len)?;

        let session = self.session.read();

        trace!("IN  SPI : {:04x}", session.esp_in.spi);
        trace!("IN  ENC : {}", hex::encode(&session.esp_in.sk_e));
        trace!("IN  AUTH: {}", hex::encode(&session.esp_in.sk_a));
        trace!("IN  ALG : {:?}", session.esp_in.auth_algorithm);
        trace!("OUT SPI : {:04x}", session.esp_out.spi);
        trace!("OUT ENC : {}", hex::encode(&session.esp_out.sk_e));
        trace!("OUT AUTH: {}", hex::encode(&session.esp_out.sk_a));
        trace!("OUT ALG : {:?}", session.esp_out.auth_algorithm);

        debug!("End ESP SA proposal");

        Ok(attributes)
    }

    pub async fn delete_sa(&mut self) -> anyhow::Result<()> {
        let request = self.build_delete_sa()?;

        self.transport.send(&request).await?;

        Ok(())
    }
}
