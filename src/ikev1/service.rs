use std::{net::Ipv4Addr, time::Duration};

use anyhow::Context;
use byteorder::{BigEndian, ReadBytesExt};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use ipnet::Ipv4Net;
use itertools::{Itertools, iproduct};
use rand::random;
use tracing::{debug, trace};

use crate::{
    certs::CertList, message::IsakmpMessage, model::*, payload::*, rfc1751::key_to_english, session::IsakmpSession,
    transport::IsakmpTransport,
};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

fn get_attributes_payload(response: IsakmpMessage) -> anyhow::Result<AttributesPayload> {
    response
        .payloads
        .into_iter()
        .find_map(|p| match p {
            Payload::Attributes(p) => Some(p),
            _ => None,
        })
        .context("No config payload in response!")
}

pub struct Ikev1Service {
    socket_timeout: Duration,
    transport: Box<dyn IsakmpTransport + Send + Sync>,
    session: Box<dyn IsakmpSession + Send + Sync>,
}

impl Ikev1Service {
    pub fn new(
        transport: Box<dyn IsakmpTransport + Send + Sync>,
        session: Box<dyn IsakmpSession + Send + Sync>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            socket_timeout: DEFAULT_TIMEOUT,
            transport,
            session,
        })
    }

    pub fn session(&mut self) -> &mut dyn IsakmpSession {
        &mut *self.session
    }

    fn build_ike_sa(&self, lifetime: Duration) -> anyhow::Result<IsakmpMessage> {
        let mut transforms = Vec::new();

        for (alg, key_lengths) in [
            (IkeEncryptionAlgorithm::AesCbc, vec![256, 192, 128]),
            (IkeEncryptionAlgorithm::DesEde3Cbc, vec![0]),
        ] {
            let proposals = iproduct!(
                [
                    IkeHashAlgorithm::Sha512,
                    IkeHashAlgorithm::Sha384,
                    IkeHashAlgorithm::Sha256,
                    IkeHashAlgorithm::Sha,
                    IkeHashAlgorithm::Md5
                ],
                key_lengths,
                [IkeGroupDescription::Oakley14, IkeGroupDescription::Oakley2]
            );

            for (auth, key_len, group) in proposals {
                trace!(
                    "Adding SA transform: auth={:?} key_len={} group={:?}",
                    auth, key_len, group
                );

                let mut attributes = vec![
                    DataAttribute::short(IkeAttributeType::EncryptionAlgorithm.into(), alg.into()),
                    DataAttribute::short(IkeAttributeType::HashAlgorithm.into(), auth.into()),
                    DataAttribute::short(IkeAttributeType::GroupDescription.into(), group.into()),
                    DataAttribute::short(
                        IkeAttributeType::AuthenticationMethod.into(),
                        if self.session.client_certificate().is_some() {
                            IkeAuthMethod::RsaSignature.into()
                        } else {
                            IkeAuthMethod::HybridInitRsa.into()
                        },
                    ),
                    DataAttribute::short(IkeAttributeType::LifeType.into(), LifeType::Seconds.into()),
                    DataAttribute::long(
                        IkeAttributeType::LifeDuration.into(),
                        Bytes::copy_from_slice(&(lifetime.as_secs() as u32).to_be_bytes()),
                    ),
                ];

                if key_len != 0 {
                    attributes.push(DataAttribute::short(IkeAttributeType::KeyLength.into(), key_len));
                }

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
            spi: Bytes::default(),
            transforms,
        });

        let sa = Payload::SecurityAssociation(SecurityAssociationPayload {
            doi: 1,
            situation: None,
            payloads: vec![proposal],
        });

        let payloads = vec![
            sa,
            Payload::VendorId(VID_CHECKPOINT.into()),
            Payload::VendorId(VID_NATT.into()),
            Payload::VendorId(VID_EXT_WITH_FLAGS.into()),
            //Payload::VendorId(VID_INITIAL_CONTACT.into()),
            //Payload::VendorId(VID_IPSEC_NAT_T.into()),
            //Payload::VendorId(VID_MS_NT5.into()),
            //Payload::VendorId(VID_FRAGMENTATION.into()),
        ];

        Ok(IsakmpMessage {
            cookie_i: self.session.cookie_i(),
            cookie_r: 0,
            version: 0x10,
            exchange_type: ExchangeType::IdentityProtection,
            flags: IsakmpFlags::empty(),
            message_id: 0,
            payloads,
        })
    }

    fn build_esp_sa(
        &self,
        spi: u32,
        nonce: &[u8],
        ipaddr: Ipv4Addr,
        lifetime: Duration,
    ) -> anyhow::Result<IsakmpMessage> {
        let mut transforms = Vec::new();

        for (transform_id, key_lengths) in [
            (TransformId::EspAesCbc, vec![256, 192, 128]),
            (TransformId::Esp3Des, vec![0]),
        ] {
            let proposals = iproduct!(
                [
                    EspAuthAlgorithm::HmacSha256v2,
                    EspAuthAlgorithm::HmacSha256,
                    EspAuthAlgorithm::HmacSha160,
                    EspAuthAlgorithm::HmacSha96,
                ],
                [EspEncapMode::UdpTunnel, EspEncapMode::CheckpointEspInUdp],
                key_lengths,
            );
            for (auth, encap, key_len) in proposals {
                trace!(
                    "Adding ESP transform: id={:?} auth={:?} encap={:?} key_len={}",
                    transform_id, auth, encap, key_len
                );

                let mut attributes = vec![
                    DataAttribute::short(EspAttributeType::LifeType.into(), LifeType::Seconds.into()),
                    DataAttribute::long(
                        EspAttributeType::LifeDuration.into(),
                        Bytes::copy_from_slice(&(lifetime.as_secs() as u32).to_be_bytes()),
                    ),
                    DataAttribute::short(EspAttributeType::AuthenticationAlgorithm.into(), auth.into()),
                    DataAttribute::short(EspAttributeType::EncapsulationMode.into(), encap.into()),
                ];
                if key_len != 0 {
                    attributes.push(DataAttribute::short(EspAttributeType::KeyLength.into(), key_len));
                }
                transforms.push(TransformPayload {
                    transform_num: (transforms.len() + 1) as _,
                    transform_id,
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
            doi: 0,
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

        let hash_payload = self.make_hash_from_payloads(
            message_id,
            &[&sa_payload, &nonce_payload, &ip_payload, &netmask_payload],
        )?;

        let message = IsakmpMessage {
            cookie_i: self.session.cookie_i(),
            cookie_r: self.session.cookie_r(),
            version: 0x10,
            exchange_type: ExchangeType::Quick,
            flags: IsakmpFlags::ENCRYPTION,
            message_id,
            payloads: vec![hash_payload, sa_payload, nonce_payload, ip_payload, netmask_payload],
        };

        Ok(message)
    }

    fn build_delete_sa(&mut self) -> anyhow::Result<IsakmpMessage> {
        let message_id = random();

        let delete_payload = Payload::Delete(DeletePayload {
            doi: 0,
            protocol_id: ProtocolId::Isakmp,
            spi_size: 16,
            spi: vec![
                Bytes::copy_from_slice(self.session.cookie_i().to_be_bytes().as_slice()),
                Bytes::copy_from_slice(self.session.cookie_r().to_be_bytes().as_slice()),
            ],
        });

        let hash_payload = self.make_hash_from_payloads(message_id, &[&delete_payload])?;

        Ok(IsakmpMessage {
            cookie_i: self.session.cookie_i(),
            cookie_r: self.session.cookie_r(),
            version: 0x10,
            exchange_type: ExchangeType::Informational,
            flags: IsakmpFlags::empty(),
            message_id,
            payloads: vec![delete_payload, hash_payload],
        })
    }

    fn build_ke(&self, local_ip: Ipv4Addr, gateway_ip: Ipv4Addr) -> anyhow::Result<IsakmpMessage> {
        let ke = Payload::KeyExchange(self.session.initiator().public_key.as_ref().into());
        let nonce = Payload::Nonce(self.session.initiator().nonce.as_ref().into());

        let remote_ip: u32 = gateway_ip.into();

        let hash_r = self.session.hash(&[
            self.session.cookie_i().to_be_bytes().as_slice(),
            self.session.cookie_r().to_be_bytes().as_slice(),
            remote_ip.to_be_bytes().as_slice(),
            4500u16.to_be_bytes().as_slice(),
        ])?;

        let natd_r_payload = Payload::Natd(BasicPayload::new(hash_r));

        let local_ip: u32 = local_ip.into();

        let hash_i = self.session.hash(&[
            self.session.cookie_i().to_be_bytes().as_slice(),
            self.session.cookie_r().to_be_bytes().as_slice(),
            local_ip.to_be_bytes().as_slice(),
            &[0, 0],
        ])?;

        let natd_i_payload = Payload::Natd(BasicPayload::new(hash_i));

        let mut payloads = vec![ke, nonce, natd_r_payload, natd_i_payload];

        if let Some(client_cert) = self.session.client_certificate() {
            trace!(
                "Adding client certificate request, issuer: {}",
                client_cert.issuer_name()
            );
            payloads.push(Payload::CertificateRequest(CertificatePayload {
                certificate_type: CertificateType::X509ForSignature,
                data: client_cert.issuer(),
            }));
            payloads.push(Payload::CertificateRequest(CertificatePayload {
                certificate_type: CertificateType::X509ForSignature,
                data: Bytes::default(),
            }));
        }

        Ok(IsakmpMessage {
            cookie_i: self.session.cookie_i(),
            cookie_r: self.session.cookie_r(),
            version: 0x10,
            exchange_type: ExchangeType::IdentityProtection,
            flags: IsakmpFlags::empty(),
            message_id: 0,
            payloads,
        })
    }

    fn build_id_protection(&self, notify_data: Bytes) -> anyhow::Result<IsakmpMessage> {
        let id_payload = if let Some(client_cert) = self.session.client_certificate() {
            Payload::Identification(IdentificationPayload {
                id_type: IdentityType::DerAsn1Dn.into(),
                data: client_cert.subject(),
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
            message_type: NotifyMessageType::CccAuth,
            spi: self
                .session
                .cookie_i()
                .to_be_bytes()
                .into_iter()
                .chain(self.session.responder().cookie.to_be_bytes())
                .collect(),
            data: notify_data,
        });

        let hash_i = self.session.hash_id_i(id_payload.to_bytes().as_ref())?;

        let payloads = if let Some(client_cert) = self.session.client_certificate() {
            let mut payloads = vec![id_payload];

            payloads.extend(client_cert.certs().into_iter().map(|cert| {
                trace!("Adding certificate payload");
                Payload::Certificate(CertificatePayload {
                    certificate_type: CertificateType::X509ForSignature,
                    data: cert,
                })
            }));

            let sig_payload = Payload::Signature(BasicPayload::new(client_cert.sign(&hash_i)?));

            payloads.push(sig_payload);
            payloads.push(notify_payload);

            payloads
        } else {
            let hash_payload = Payload::Hash(BasicPayload::new(hash_i));
            vec![hash_payload, id_payload, notify_payload]
        };

        Ok(IsakmpMessage {
            cookie_i: self.session.cookie_i(),
            cookie_r: self.session.cookie_r(),
            version: 0x10,
            exchange_type: ExchangeType::IdentityProtection,
            flags: IsakmpFlags::ENCRYPTION,
            message_id: 0,
            payloads,
        })
    }

    fn build_attribute_request(
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
                DataAttribute::short(ConfigAttributeType::AuthType.into(), UserAuthType::Generic.into()),
                DataAttribute::long(attribute_type.into(), data),
            ],
        });

        let hash_payload = self.make_hash_from_payloads(message_id, &[&attrs_payload])?;

        Ok(IsakmpMessage {
            cookie_i: self.session.cookie_i(),
            cookie_r: self.session.cookie_r(),
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

        let hash_payload = self.make_hash_from_payloads(message_id, &[&attrs_payload])?;

        Ok(IsakmpMessage {
            cookie_i: self.session.cookie_i(),
            cookie_r: self.session.cookie_r(),
            version: 0x10,
            exchange_type: ExchangeType::Transaction,
            flags: IsakmpFlags::ENCRYPTION,
            message_id,
            payloads: vec![hash_payload, attrs_payload],
        })
    }

    fn build_om_cfg(&self, address: Option<Ipv4Net>, mac: Option<Bytes>) -> anyhow::Result<IsakmpMessage> {
        let empty_attrs = [
            ConfigAttributeType::Ipv4Dns,
            ConfigAttributeType::AddressExpiry,
            ConfigAttributeType::InternalDomainName,
            ConfigAttributeType::CccSessionId,
            ConfigAttributeType::CccVariableLeaseTime,
            ConfigAttributeType::CccOfficeModeAllowed,
            ConfigAttributeType::CccConnectAllowed,
        ];

        let (address, netmask) = if let Some(address) = address {
            (address.addr(), address.netmask())
        } else {
            (Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED)
        };

        let attributes = empty_attrs
            .into_iter()
            .map(|a| DataAttribute::long(a.into(), Bytes::copy_from_slice(&[0, 0, 0, 0])))
            .chain(Some(DataAttribute::long(
                ConfigAttributeType::MacAddress.into(),
                mac.unwrap_or_else(|| Bytes::copy_from_slice(&random::<[u8; 6]>())),
            )))
            .chain(Some(DataAttribute::long(
                ConfigAttributeType::Ipv4Address.into(),
                Bytes::copy_from_slice(&address.octets()),
            )))
            .chain(Some(DataAttribute::long(
                ConfigAttributeType::Ipv4Netmask.into(),
                Bytes::copy_from_slice(&netmask.octets()),
            )))
            .collect();

        let attrs_payload = Payload::Attributes(AttributesPayload {
            attributes_payload_type: AttributesPayloadType::Request,
            identifier: random(),
            attributes,
        });

        let message_id: u32 = random();

        let hash_payload = self.make_hash_from_payloads(message_id, &[&attrs_payload])?;

        Ok(IsakmpMessage {
            cookie_i: self.session.cookie_i(),
            cookie_r: self.session.cookie_r(),
            version: 0x10,
            exchange_type: ExchangeType::Transaction,
            flags: IsakmpFlags::ENCRYPTION,
            message_id,
            payloads: vec![hash_payload, attrs_payload],
        })
    }

    pub fn make_hash_from_payloads(&self, message_id: u32, payloads: &[&Payload]) -> anyhow::Result<Payload> {
        let mut buf = BytesMut::new();
        for (i, payload) in payloads.iter().enumerate() {
            let data = payload.to_bytes();
            let next_payload = payloads.get(i + 1).map_or(PayloadType::None, |p| p.as_payload_type());
            buf.put_u8(next_payload.into());
            buf.put_u8(0);
            buf.put_u16(4 + data.len() as u16);
            buf.put_slice(&data);
        }
        let data = buf.freeze();

        let hash = self.session.prf(
            &self.session.session_keys().skeyid_a,
            &[message_id.to_be_bytes().as_slice(), &data],
        )?;

        Ok(Payload::Hash(BasicPayload::new(hash)))
    }

    pub async fn do_sa_proposal(&mut self, lifetime: Duration) -> anyhow::Result<SaProposal> {
        debug!("Begin SA proposal");

        let request = self.build_ike_sa(lifetime)?;
        let (proposal, _) = self.send_sa_proposal(request).await?;

        self.session.init_from_sa(proposal.clone())?;

        debug!("End SA proposal");

        Ok(proposal)
    }

    pub async fn send_sa_proposal(&mut self, message: IsakmpMessage) -> anyhow::Result<(SaProposal, IsakmpMessage)> {
        let sa_bytes = message.payloads[0].to_bytes();

        let response = self.transport.send_receive(&message, self.socket_timeout).await?;

        let attributes = response
            .payloads
            .iter()
            .find_map(|p| match p {
                Payload::SecurityAssociation(payload) => payload.payloads.iter().find_map(|p| match p {
                    Payload::Proposal(proposal) => proposal.transforms.first().map(|t| t.attributes.clone()),
                    _ => None,
                }),
                _ => None,
            })
            .context("No attributes in response!")?;

        let hash_alg: IkeHashAlgorithm = attributes
            .iter()
            .find_map(|a| {
                if a.attribute_type == IkeAttributeType::HashAlgorithm.into() {
                    a.as_short().map(Into::into)
                } else {
                    None
                }
            })
            .context("No hash algorithm in response!")?;

        debug!("Negotiated SA hash algorithm: {:?}", hash_alg);

        let enc_alg: IkeEncryptionAlgorithm = attributes
            .iter()
            .find_map(|a| {
                if a.attribute_type == IkeAttributeType::EncryptionAlgorithm.into() {
                    a.as_short().map(Into::into)
                } else {
                    None
                }
            })
            .context("No hash algorithm in response!")?;

        debug!("Negotiated SA encryption algorithm: {:?}", enc_alg);

        let key_len = if enc_alg == IkeEncryptionAlgorithm::DesEde3Cbc {
            24
        } else {
            attributes
                .iter()
                .find_map(|a| {
                    if a.attribute_type == IkeAttributeType::KeyLength.into() {
                        a.as_short().map(|k| k as usize / 8)
                    } else {
                        None
                    }
                })
                .context("No key length in response!")?
        };

        debug!("Negotiated SA key length: {}", key_len);

        let group: IkeGroupDescription = attributes
            .iter()
            .find_map(|a| {
                if a.attribute_type == IkeAttributeType::GroupDescription.into() {
                    a.as_short().map(Into::into)
                } else {
                    None
                }
            })
            .context("No DH group in response!")?;

        debug!("Negotiated SA group: {:?}", group);

        let lifetime = attributes
            .iter()
            .find_map(|a| match IkeAttributeType::from(a.attribute_type) {
                IkeAttributeType::LifeDuration => a.as_long().and_then(|v| {
                    let data: Option<[u8; 4]> = v.as_ref().try_into().ok();
                    data.map(u32::from_be_bytes)
                }),
                _ => None,
            })
            .context("No lifetime in reply!")?;

        debug!("Negotiated SA lifetime: {}", lifetime);

        let proposal = SaProposal {
            cookie_i: response.cookie_i,
            cookie_r: response.cookie_r,
            sa_bytes,
            hash_alg,
            enc_alg,
            key_len,
            group,
            lifetime: Duration::from_secs(lifetime as u64),
        };

        Ok((proposal, response))
    }

    pub async fn do_key_exchange(&mut self, local_ip: Ipv4Addr, gateway_ip: Ipv4Addr) -> anyhow::Result<()> {
        debug!("Begin key exchange");

        let request = self.build_ke(local_ip, gateway_ip)?;

        let response = self.transport.send_receive(&request, self.socket_timeout).await?;

        let public_key_r = response
            .payloads
            .iter()
            .find_map(|p| match p {
                Payload::KeyExchange(ke) => Some(ke.data.clone()),
                _ => None,
            })
            .context("No KE in response!")?;

        trace!("Responder's public key length: {}", public_key_r.len());

        let nonce_r = response
            .payloads
            .iter()
            .find_map(|p| match p {
                Payload::Nonce(ke) => Some(ke.data.clone()),
                _ => None,
            })
            .context("No nonce in response!")?;

        trace!("Responder's nonce length: {}", nonce_r.len());

        self.session.init_from_ke(public_key_r, nonce_r)?;

        trace!("COOKIE_i: {:08x}", self.session.cookie_i());
        trace!("SKEYID_e: {}", hex::encode(&self.session.session_keys().skeyid_e));

        debug!("End key exchange");

        Ok(())
    }

    async fn get_auth_attributes(&mut self) -> anyhow::Result<(AttributesPayload, u32)> {
        let attr_response = self.transport.receive(self.socket_timeout).await?;

        let message_id = attr_response.message_id;

        debug!("Attributes message ID: {:04x}", message_id);

        Ok((get_attributes_payload(attr_response)?, message_id))
    }

    pub async fn do_identity_protection(
        &mut self,
        identity_request: IdentityRequest,
    ) -> anyhow::Result<(Option<AttributesPayload>, u32)> {
        debug!("Begin identity protection");

        let request = self.build_id_protection(Bytes::copy_from_slice(identity_request.auth_blob.as_bytes()))?;

        let response = self.transport.send_receive(&request, self.socket_timeout).await?;

        let signature = response.payloads.iter().find_map(|payload| match payload {
            Payload::Signature(data) => Some(data.data.clone()),
            _ => None,
        });

        let id = response.payloads.iter().find_map(|payload| match payload {
            Payload::Identification(data) => Some(data),
            _ => None,
        });

        let certs = response
            .payloads
            .iter()
            .filter_map(|payload| match payload {
                Payload::Certificate(cert) => Some(cert.data.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();

        let (Some(signature), Some(id), [cert, ..]) = (signature, id, &certs[..]) else {
            anyhow::bail!("Incomplete ID payload received!");
        };

        for fp in &identity_request.internal_ca_fingerprints {
            debug!("Trusted server fingerprint: {}", fp);
        }

        if identity_request.internal_ca_fingerprints.is_empty() {
            debug!("No internal CA fingerprints specified, skipping validation");
        } else {
            let mut validation_result = false;

            for cert in &certs {
                let cert_list = CertList::from_ipsec(&[cert])?;
                let fingerprint = key_to_english(&cert_list.fingerprint()[0..16])?.join(" ");

                debug!("Fingerprint for: {}: {}", cert_list.subject_name(), fingerprint);

                if identity_request.internal_ca_fingerprints.iter().contains(&fingerprint) {
                    validation_result = true;
                    break;
                }
            }

            if validation_result {
                debug!("Internal IPSec certificate validation succeeded");
            } else {
                anyhow::bail!("Internal IPSec certificate validation failed!");
            }
        }

        let id_type = IdentityType::from(id.id_type);
        if id_type == IdentityType::Ipv4Address {
            let id_addr: Ipv4Addr = id.data.clone().reader().read_u32::<BigEndian>()?.into();
            debug!("IP address from ID payload: {}", id_addr);
        }

        let data = id.to_bytes();
        let hash = self.session.hash_id_r(&data)?;
        self.session().verify_signature(&hash, &signature, cert)?;

        debug!("ID payload signature verification succeeded!");

        let result = if identity_request.with_mfa {
            debug!("Awaiting authentication factors");
            let (attrs, id) = self.get_auth_attributes().await?;
            Ok((Some(attrs), id))
        } else {
            Ok((None, response.message_id))
        };

        debug!("End identity protection");

        result
    }

    pub async fn send_attribute(
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

        let request = self.build_attribute_request(identifier, message_id, attribute_type, data)?;

        self.send_attribute_message(request, timeout).await
    }

    pub async fn send_attribute_message(
        &mut self,
        message: IsakmpMessage,
        timeout: Option<Duration>,
    ) -> anyhow::Result<(AttributesPayload, u32)> {
        let response = self
            .transport
            .send_receive(&message, timeout.unwrap_or(self.socket_timeout))
            .await?;
        let message_id = response.message_id;
        debug!("Message ID: {:04x}", message_id);

        let config = get_attributes_payload(response)?;

        debug!("Response message ID: {:04x}", message_id);

        Ok((config, message_id))
    }

    pub async fn send_ack_response(&mut self, identifier: u16, message_id: u32) -> anyhow::Result<()> {
        debug!("Sending ACK response");
        self.send_ack_message(self.build_ack_cfg(identifier, message_id)?).await
    }

    pub async fn send_ack_message(&mut self, msg: IsakmpMessage) -> anyhow::Result<()> {
        self.transport.send(&msg).await
    }

    pub async fn send_om_request(
        &mut self,
        address: Option<Ipv4Net>,
        mac: Option<Bytes>,
    ) -> anyhow::Result<AttributesPayload> {
        debug!("Begin sending OM request");

        let request = self.build_om_cfg(address, mac)?;
        let response = self.transport.send_receive(&request, self.socket_timeout).await?;

        debug!("End sending OM request");

        get_attributes_payload(response)
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

        let response = self.transport.send_receive(&request, self.socket_timeout).await?;

        let nonce_r = response
            .payloads
            .iter()
            .find_map(|p| match p {
                Payload::Nonce(payload) => Some(payload.data.clone()),
                _ => None,
            })
            .context("No nonce payload in response!")?;

        let spi_r = response
            .payloads
            .iter()
            .find_map(|p| match p {
                Payload::SecurityAssociation(payload) => payload.payloads.iter().find_map(|p| match p {
                    Payload::Proposal(proposal) => proposal.spi.clone().reader().read_u32::<BigEndian>().ok(),
                    _ => None,
                }),
                _ => None,
            })
            .context("No proposal payload in response!")?;

        let (transform_id, attributes) = response
            .payloads
            .into_iter()
            .find_map(|p| match p {
                Payload::SecurityAssociation(payload) => payload.payloads.into_iter().find_map(|p| match p {
                    Payload::Proposal(proposal) => proposal
                        .transforms
                        .into_iter()
                        .next()
                        .map(|t| (t.transform_id, t.attributes)),
                    _ => None,
                }),
                _ => None,
            })
            .context("No attributes in response!")?;

        debug!("Negotiated transform id: {:?}", transform_id);

        let prf = self.session.prf(
            self.session.session_keys().skeyid_a.as_ref(),
            &[&[0], response.message_id.to_be_bytes().as_slice(), &nonce_i, &nonce_r],
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
            .context("No auth algorithm in response!")?;

        debug!("Negotiated ESP auth algorithm: {:?}", auth_alg);

        let key_len = if transform_id == TransformId::EspAesCbc {
            attributes
                .iter()
                .find_map(|a| {
                    if a.attribute_type == EspAttributeType::KeyLength.into() {
                        a.as_short().map(|k| k as usize)
                    } else {
                        None
                    }
                })
                .unwrap_or(128)
                / 8
        } else {
            // 3DES key length
            24
        };

        debug!("Negotiated ESP key length: {}", key_len);

        let hash_msg = IsakmpMessage {
            cookie_i: self.session.cookie_i(),
            cookie_r: self.session.cookie_r(),
            version: 0x10,
            exchange_type: ExchangeType::Quick,
            flags: IsakmpFlags::ENCRYPTION,
            message_id: response.message_id,
            payloads: vec![Payload::Hash(BasicPayload::new(prf))],
        };

        self.transport.send(&hash_msg).await?;
        self.transport.disconnect();

        let proposal = EspProposal {
            spi_i,
            nonce_i,
            spi_r,
            nonce_r,
            transform_id,
            auth_alg,
            key_len,
        };

        self.session.init_from_qm(proposal)?;

        let esp_in = self.session.esp_in();
        let esp_out = self.session.esp_out();

        trace!("IN  SPI : {:04x}", esp_in.spi);
        trace!("IN  ENC : {}", hex::encode(&esp_in.sk_e));
        trace!("IN  AUTH: {}", hex::encode(&esp_in.sk_a));
        trace!("IN  KEYL: {}", esp_in.sk_e.len());
        trace!("IN  EALG: {:?}", esp_in.transform_id);
        trace!("IN  AALG: {:?}", esp_in.auth_algorithm);
        trace!("OUT SPI : {:04x}", esp_out.spi);
        trace!("OUT ENC : {}", hex::encode(&esp_out.sk_e));
        trace!("OUT AUTH: {}", hex::encode(&esp_out.sk_a));
        trace!("OUT KEYL: {}", esp_out.sk_e.len());
        trace!("OUT EALG: {:?}", esp_out.transform_id);
        trace!("OUT AALG: {:?}", esp_out.auth_algorithm);

        debug!("End ESP SA proposal");

        Ok(attributes)
    }

    pub async fn delete_sa(&mut self) -> anyhow::Result<()> {
        let request = self.build_delete_sa()?;

        self.transport.send(&request).await?;
        self.transport.disconnect();

        Ok(())
    }
}
