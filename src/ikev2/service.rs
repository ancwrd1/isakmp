//! IKEv2 exchange state machine.
//!
//! IKEv1 spends two round trips on what IKEv2 does in one: IKE_SA_INIT carries
//! the SA proposal, the D-H public value and the nonce together, so
//! `do_sa_proposal` and `do_key_exchange` collapse into [`Ikev2Service::do_sa_init`].

use std::{
    net::{Ipv4Addr, SocketAddrV4},
    sync::Arc,
    time::Duration,
};

use anyhow::Context;
use bytes::{BufMut, Bytes, BytesMut};
use openssl::sha::sha1;
use rand::random;
use tracing::{debug, trace, warn};

use crate::{
    certs::ClientCertificate,
    crypto::GroupType,
    ikev2::{
        eap::EapMessage,
        message::Ikev2Message,
        model::{
            CertificateEncoding, ConfigurationAttributeType, ConfigurationType, DhGroup, EapCode, EapType,
            EncryptionAlgorithm, ExchangeType, ExtendedSequenceNumbers, Flags, IdentificationType, Ikev2EspProposal,
            Ikev2SaProposal, IntegrityAlgorithm, NotifyType, ProtocolId, PseudoRandomFunction, TransformType,
        },
        payload::{
            CertificatePayload, ConfigurationAttribute, ConfigurationPayload, DeletePayload, IdentificationPayload,
            KeyExchangePayload, NotifyPayload, Payload, Proposal, SecurityAssociationPayload, TrafficSelector,
            TrafficSelectorPayload, Transform,
        },
        session::Ikev2Session,
    },
    message::IKEV2_VERSION,
    model::VID_CHECKPOINT,
    payload::{BasicPayload, PayloadLike},
    session::{IsakmpSession, OfficeMode},
    transport::IsakmpTransport,
};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
const AUTH_TIMEOUT: Duration = Duration::from_secs(120);

const MAX_SA_INIT_ATTEMPTS: usize = 3;

/// RFC 7296 §2.10 wants at least 16 octets, and no less than half the PRF's
/// key size.
const CHILD_SA_NONCE_SIZE: usize = 32;

const OFFERED_ENCRYPTION: [(EncryptionAlgorithm, Option<u16>); 3] = [
    (EncryptionAlgorithm::AesCbc, Some(32)),
    (EncryptionAlgorithm::AesCbc, Some(16)),
    (EncryptionAlgorithm::DesEde3Cbc, None),
];

const OFFERED_PRF: [PseudoRandomFunction; 4] = [
    PseudoRandomFunction::HmacSha512,
    PseudoRandomFunction::HmacSha384,
    PseudoRandomFunction::HmacSha256,
    PseudoRandomFunction::HmacSha1,
];

const OFFERED_INTEGRITY: [IntegrityAlgorithm; 4] = [
    IntegrityAlgorithm::HmacSha512_256,
    IntegrityAlgorithm::HmacSha384_192,
    IntegrityAlgorithm::HmacSha256_128,
    IntegrityAlgorithm::HmacSha1_96,
];

const OFFERED_GROUPS: [DhGroup; 5] = [
    DhGroup::Ecp521,
    DhGroup::Ecp384,
    DhGroup::Ecp256,
    DhGroup::Modp2048,
    DhGroup::Modp1024,
];

/// RFC 7296 §2.23: `SHA1(SPIi | SPIr | IP | port)`, with SHA-1 fixed by the
/// specification rather than negotiated.
///
/// The port is the socket's own, not a fixed one: the responder hashes the
/// address *and port* it saw the packet come from, so a guessed port makes
/// every comparison fail and reports a NAT that is not there.
fn nat_detection_hash(initiator_spi: u64, responder_spi: u64, endpoint: SocketAddrV4) -> Bytes {
    let mut buf = BytesMut::with_capacity(22);
    buf.put_u64(initiator_spi);
    buf.put_u64(responder_spi);
    buf.put_slice(&endpoint.ip().octets());
    buf.put_u16(endpoint.port());

    Bytes::copy_from_slice(&sha1(&buf))
}

/// What IKE_SA_INIT settled, beyond the key schedule the session now holds.
#[derive(Debug, Clone, Default)]
pub struct SaInitResult {
    pub local_nat: bool,
    pub remote_nat: bool,
    pub notifies: Vec<NotifyPayload>,
}

pub struct Ikev2Service {
    socket_timeout: Duration,
    transport: Box<dyn IsakmpTransport<Ikev2Message> + Send + Sync>,
    session: Ikev2Session,
    message_id: u32,
    auth: Option<AuthContext>,
    machine_auth_notify: Option<NotifyType>,
    ccc_auth_notify: Vec<NotifyType>,
}

impl Ikev2Service {
    pub fn new(
        transport: Box<dyn IsakmpTransport<Ikev2Message> + Send + Sync>,
        session: Ikev2Session,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            socket_timeout: DEFAULT_TIMEOUT,
            transport,
            session,
            message_id: 0,
            auth: None,
            machine_auth_notify: Some(NotifyType::CpRaUsingMachineAuth),
            ccc_auth_notify: vec![NotifyType::CccAuth],
        })
    }

    pub fn session(&mut self) -> &mut Ikev2Session {
        &mut self.session
    }

    pub fn set_machine_auth_notify(&mut self, notify_type: Option<NotifyType>) {
        self.machine_auth_notify = notify_type;
    }

    pub fn set_ccc_auth_notify(&mut self, types: impl IntoIterator<Item = NotifyType>) {
        self.ccc_auth_notify = types.into_iter().collect();
    }

    fn client_auth(&self) -> ClientAuth {
        match (self.session.client_certificate(), self.session.hybrid_auth()) {
            (Some(certificate), true) => ClientAuth::Machine(certificate),
            (Some(certificate), false) => ClientAuth::User(certificate),
            (None, _) => ClientAuth::Password,
        }
    }

    pub fn message_id(&self) -> u32 {
        self.message_id
    }

    fn build_sa_init(&self, local: SocketAddrV4, gateway: SocketAddrV4, cookie: Option<&Bytes>) -> Ikev2Message {
        let initiator = self.session.initiator();
        let initiator_spi = self.session.initiator_spi();

        let mut transforms = OFFERED_ENCRYPTION
            .into_iter()
            .map(|(algorithm, key_len)| Transform::encryption(algorithm, key_len))
            .chain(OFFERED_PRF.into_iter().map(Transform::prf))
            .chain(OFFERED_INTEGRITY.into_iter().map(Transform::integrity))
            .collect::<Vec<_>>();

        // our KE payload is for the session's group, so it leads the list
        let our_group = DhGroup::from(self.session.dh_group());
        transforms.push(Transform::dh_group(our_group));
        transforms.extend(
            OFFERED_GROUPS
                .into_iter()
                .filter(|group| *group != our_group)
                .map(Transform::dh_group),
        );

        let sa = Payload::SecurityAssociation(SecurityAssociationPayload {
            proposals: vec![Proposal {
                proposal_num: 1,
                protocol_id: ProtocolId::Ike,
                // RFC 7296 §3.3.1: the IKE SA's SPIs are in the header already
                spi: Bytes::default(),
                transforms,
            }],
        });

        let mut payloads = Vec::new();

        // RFC 7296 §2.6: the COOKIE notify must be the first payload of the retried request.
        if let Some(cookie) = cookie {
            payloads.push(Payload::Notify(NotifyPayload::new(NotifyType::Cookie, cookie.clone())));
        }

        payloads.extend([
            sa,
            Payload::KeyExchange(KeyExchangePayload {
                dh_group: our_group,
                data: initiator.public_key.clone(),
            }),
            Payload::Nonce(BasicPayload::new(initiator.nonce.clone())),
            Payload::Notify(NotifyPayload::new(
                NotifyType::NatDetectionSourceIp,
                nat_detection_hash(initiator_spi, 0, local),
            )),
            Payload::Notify(NotifyPayload::new(
                NotifyType::NatDetectionDestinationIp,
                nat_detection_hash(initiator_spi, 0, gateway),
            )),
            Payload::VendorId(BasicPayload::new(Bytes::from_static(VID_CHECKPOINT))),
        ]);

        if let Some(notify_type) = self.machine_auth_notify {
            payloads.push(Payload::Notify(NotifyPayload::new(notify_type, Bytes::default())));
        }

        Ikev2Message {
            initiator_spi,
            responder_spi: 0,
            version: IKEV2_VERSION,
            exchange_type: ExchangeType::IkeSaInit,
            flags: Flags::INITIATOR,
            message_id: 0,
            payloads,
        }
    }

    pub async fn do_sa_init(&mut self, local: SocketAddrV4, gateway: SocketAddrV4) -> anyhow::Result<SaInitResult> {
        debug!("Begin IKE_SA_INIT");

        let mut cookie: Option<Bytes> = None;
        let mut group_retried = false;
        let mut attempt = 0;

        let response = loop {
            attempt += 1;
            anyhow::ensure!(
                attempt <= MAX_SA_INIT_ATTEMPTS,
                "IKE_SA_INIT did not settle in {MAX_SA_INIT_ATTEMPTS} attempts"
            );

            let request = self.build_sa_init(local, gateway, cookie.as_ref());
            let response = self.transport.send_receive(&request, self.socket_timeout).await?;

            // A responder under load answers with a cookie instead of an SA and expects the same request back with the cookie attached.
            if cookie.is_none()
                && let Some(notify) = response.find_notify(NotifyType::Cookie)
            {
                debug!("Responder demanded a cookie, retrying IKE_SA_INIT");
                cookie = Some(notify.data.clone());
                continue;
            }

            match response.error_notify() {
                Some(NotifyType::InvalidKePayload) if !group_retried => {
                    let group = response
                        .notifies()
                        .find(|n| n.notify_type == NotifyType::InvalidKePayload)
                        .filter(|n| n.data.len() >= 2)
                        .map(|n| u16::from_be_bytes([n.data[0], n.data[1]]))
                        .context("INVALID_KE_PAYLOAD without a group")?;

                    debug!("Responder wants D-H group {group}, retrying IKE_SA_INIT");
                    group_retried = true;
                    self.session.set_dh_group(GroupType::from_group_id(group)?)?;
                    continue;
                }
                Some(notify) => anyhow::bail!("IKE_SA_INIT rejected: {:?}", notify),
                None => break response,
            }
        };

        let (proposal, public_key, nonce) = self.parse_sa_init(&response)?;

        self.session.init_from_sa(proposal)?;
        self.session.init_from_ke(public_key, nonce)?;

        self.message_id = 1;

        trace!(
            "SPI_i: {:016x}, SPI_r: {:016x}",
            self.session.initiator_spi(),
            self.session.responder_spi()
        );

        let notifies = response.notifies().cloned().collect::<Vec<_>>();
        let result = SaInitResult {
            local_nat: self.nat_detected(&response, NotifyType::NatDetectionDestinationIp, local),
            remote_nat: self.nat_detected(&response, NotifyType::NatDetectionSourceIp, gateway),
            notifies,
        };

        debug!(
            "End IKE_SA_INIT, local NAT: {}, remote NAT: {}",
            result.local_nat, result.remote_nat
        );

        Ok(result)
    }

    fn parse_sa_init(&self, response: &Ikev2Message) -> anyhow::Result<(Ikev2SaProposal, Bytes, Bytes)> {
        let proposal = response
            .payloads
            .iter()
            .find_map(|p| match p {
                Payload::SecurityAssociation(sa) => sa.proposals.first(),
                _ => None,
            })
            .context("No SA payload in the IKE_SA_INIT response")?;

        let encryption_transform = self
            .choose(proposal, TransformType::EncryptionAlgorithm, &|transform| {
                OFFERED_ENCRYPTION.iter().any(|(algorithm, key_len)| {
                    u16::from(*algorithm) == transform.transform_id && key_len.map(usize::from) == transform.key_len()
                })
            })
            .context("Responder returned no encryption transform we offered")?;

        let encryption = encryption_transform
            .as_encryption()
            .context("No encryption transform in the chosen proposal")?;

        // 3DES has a fixed key length and so carries no attribute for it.
        let key_len = encryption_transform.key_len().unwrap_or(match encryption {
            EncryptionAlgorithm::DesEde3Cbc => 24,
            _ => 0,
        });

        let prf = self
            .choose(proposal, TransformType::PseudoRandomFunction, &|transform| {
                OFFERED_PRF
                    .iter()
                    .any(|algorithm| u16::from(*algorithm) == transform.transform_id)
            })
            .and_then(Transform::as_prf)
            .context("Responder returned no PRF transform we offered")?;

        let integrity = self
            .choose(proposal, TransformType::IntegrityAlgorithm, &|transform| {
                OFFERED_INTEGRITY
                    .iter()
                    .any(|algorithm| u16::from(*algorithm) == transform.transform_id)
            })
            .and_then(Transform::as_integrity)
            .unwrap_or(IntegrityAlgorithm::None);

        let key_exchange = response
            .payloads
            .iter()
            .find_map(|p| match p {
                Payload::KeyExchange(ke) => Some(ke),
                _ => None,
            })
            .context("No KE payload in the IKE_SA_INIT response")?;

        match proposal
            .find(TransformType::DiffieHellmanGroup)
            .and_then(Transform::as_dh_group)
        {
            Some(chosen) if chosen != key_exchange.dh_group => warn!(
                "Responder's proposal chose {:?} but its KE payload is for {:?}; keying from the KE payload",
                chosen, key_exchange.dh_group
            ),
            None => debug!("Responder's proposal carries no D-H transform; taking the group from the KE payload"),
            _ => {}
        }

        let sa_proposal = Ikev2SaProposal {
            initiator_spi: response.initiator_spi,
            responder_spi: response.responder_spi,
            encryption,
            key_len,
            prf,
            integrity,
            dh_group: key_exchange.dh_group,
        };

        let nonce = response
            .payloads
            .iter()
            .find_map(|p| match p {
                Payload::Nonce(nonce) => Some(nonce.data.clone()),
                _ => None,
            })
            .context("No nonce payload in the IKE_SA_INIT response")?;

        Ok((sa_proposal, key_exchange.data.clone(), nonce))
    }

    fn choose<'a>(
        &self,
        proposal: &'a Proposal,
        transform_type: TransformType,
        offered: &dyn Fn(&Transform) -> bool,
    ) -> Option<&'a Transform> {
        let candidates = proposal
            .transforms
            .iter()
            .filter(|transform| transform.transform_type == transform_type && offered(transform))
            .collect::<Vec<_>>();

        if candidates.len() > 1 {
            warn!(
                "Responder returned {} {:?} transforms we offered ({:?}) instead of one; taking the first",
                candidates.len(),
                transform_type,
                candidates.iter().map(|t| t.transform_id).collect::<Vec<_>>()
            );
        }

        candidates.first().copied()
    }

    fn nat_detected(&self, response: &Ikev2Message, notify_type: NotifyType, endpoint: SocketAddrV4) -> bool {
        let expected = nat_detection_hash(response.initiator_spi, response.responder_spi, endpoint);

        let mut received = response.notifies().filter(|n| n.notify_type == notify_type).peekable();

        if received.peek().is_none() {
            // nothing to compare against: the responder does not support NAT
            // detection, so assume no NAT rather than claim one
            warn!("No {:?} notify in the IKE_SA_INIT response", notify_type);
            return false;
        }

        !received.any(|n| n.data == expected)
    }
}

#[derive(Debug, Clone, Default)]
pub struct Ikev2AuthRequest {
    pub username: String,
    pub auth_blob: String,
    pub address: Option<Ipv4Addr>,
    pub machine_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AuthPrompt {
    pub eap: EapMessage,
}

impl AuthPrompt {
    pub fn eap_type(&self) -> Option<EapType> {
        self.eap.eap_type
    }

    /// The method's data. EAP-GTC defines it as text to display.
    pub fn data(&self) -> &Bytes {
        &self.eap.data
    }
}

#[derive(Debug)]
pub enum Ikev2Step {
    NeedsChallenge(AuthPrompt),
    Done(Box<AuthResult>),
}

/// What a renewed office mode lease settled. The gateway answers a renewal
/// with the address and netmask only — no DNS or domains — so the rest of the
/// configuration from login still stands.
#[derive(Debug, Clone, Copy)]
pub struct OfficeModeLease {
    pub address: Ipv4Addr,
    pub netmask: Option<Ipv4Addr>,
    pub expiry: Option<Duration>,
}

/// What a peer-initiated exchange turned out to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerRequest {
    /// The peer rekeyed the child SA. `esp_in`/`esp_out` now hold new keys and
    /// SPIs, and the data path has to be reconfigured with them.
    ChildSaRekeyed,
    /// The peer deleted an SA. The tunnel is over.
    Deleted,
    /// Answered, with nothing for the caller to do.
    Other,
}

#[derive(Debug, Clone)]
pub struct AuthResult {
    pub office_mode: OfficeMode,
    pub ts_i: Vec<TrafficSelector>,
    pub ts_r: Vec<TrafficSelector>,
    pub notifies: Vec<NotifyPayload>,
    pub address_expiry: Option<Duration>,
    pub auth_log: Option<Bytes>,
}

struct AuthContext {
    id_i: IdentificationPayload,
    id_r: IdentificationPayload,
    certificates: Vec<Bytes>,
    esp_spi: u32,
    username: String,
    pending: Option<EapMessage>,
    authenticated: bool,
}

enum ClientAuth {
    /// No certificate
    Password,
    /// A machine certificate
    Machine(Arc<dyn ClientCertificate + Send + Sync>),
    /// The user's own certificate
    User(Arc<dyn ClientCertificate + Send + Sync>),
}

impl Ikev2Service {
    pub async fn do_auth(&mut self, request: Ikev2AuthRequest) -> anyhow::Result<Ikev2Step> {
        debug!("Begin IKE_AUTH");

        anyhow::ensure!(self.session.is_keyed(), "IKE_AUTH before IKE_SA_INIT");

        let client_auth = self.client_auth();

        // RFC 7296 §3.5: KEY_ID data is opaque, and Check Point puts a
        // NUL-terminated user name in it.
        let user_id = IdentificationPayload {
            id_type: IdentificationType::KeyId,
            data: Bytes::from(format!("{}\0", request.username)),
        };

        let id_i = match &client_auth {
            ClientAuth::User(certificate) => IdentificationPayload {
                id_type: IdentificationType::DerAsn1Dn,
                data: certificate.subject(),
            },
            ClientAuth::Machine(_) => {
                let machine_name = request
                    .machine_name
                    .as_deref()
                    .context("A machine certificate needs the machine name for IDi")?;

                IdentificationPayload {
                    id_type: IdentificationType::KeyId,
                    data: Bytes::from(format!("{machine_name}$")),
                }
            }
            ClientAuth::Password => user_id.clone(),
        };

        let esp_spi: u32 = random();

        let payloads = self.build_ike_auth(
            &client_auth,
            &id_i,
            esp_spi,
            request.address,
            Bytes::from(request.auth_blob.into_bytes()),
        )?;

        let response = self.exchange(ExchangeType::IkeAuth, payloads, None).await?;

        let (id_r, certificates) = self.authenticate_responder(&response)?;

        self.auth = Some(AuthContext {
            id_i,
            id_r,
            certificates,
            esp_spi,
            username: request.username,
            pending: None,
            authenticated: matches!(client_auth, ClientAuth::User(_)),
        });

        if matches!(client_auth, ClientAuth::Machine(_)) {
            return self.do_second_auth(user_id).await;
        }

        self.continue_auth(response).await
    }

    async fn do_second_auth(&mut self, user_id: IdentificationPayload) -> anyhow::Result<Ikev2Step> {
        debug!("Machine authenticated, beginning the user's authentication round");

        self.auth.as_mut().context("IKE_AUTH is not running")?.id_i = user_id.clone();

        let response = self
            .exchange(
                ExchangeType::IkeAuth,
                vec![Payload::IdentificationInitiator(user_id)],
                None,
            )
            .await?;

        self.continue_auth(response).await
    }

    fn build_ike_auth(
        &self,
        client_auth: &ClientAuth,
        id_i: &IdentificationPayload,
        esp_spi: u32,
        address: Option<Ipv4Addr>,
        auth_blob: Bytes,
    ) -> anyhow::Result<Vec<Payload>> {
        let mut payloads = vec![Payload::IdentificationInitiator(id_i.clone())];

        match client_auth {
            ClientAuth::Password => {}
            ClientAuth::Machine(certificate) => {
                debug!("Authenticating the machine as '{}'", certificate.subject_name());

                payloads.extend(Self::certificate_payloads(certificate.certs().into_iter().take(1)));

                payloads.push(Payload::CertificateRequest(CertificatePayload {
                    encoding: CertificateEncoding::X509CertificateSignature,
                    data: Bytes::default(),
                }));

                payloads.push(Payload::Authentication(
                    self.session.auth_i_signature(&id_i.to_bytes())?,
                ));
            }
            ClientAuth::User(certificate) => {
                debug!("Authenticating the user as '{}'", certificate.subject_name());

                payloads.extend(Self::certificate_payloads(certificate.certs()));
                payloads.push(Payload::Authentication(
                    self.session.auth_i_signature(&id_i.to_bytes())?,
                ));
            }
        }

        payloads.extend([
            Payload::Configuration(Self::build_config_request(address, true)),
            Payload::SecurityAssociation(SecurityAssociationPayload {
                proposals: Self::build_esp_proposals(esp_spi),
            }),
            // we propose everything and let the gateway narrow it
            Payload::TrafficSelectorInitiator(TrafficSelectorPayload {
                selectors: vec![TrafficSelector::any_ipv4()],
            }),
            Payload::TrafficSelectorResponder(TrafficSelectorPayload {
                selectors: vec![TrafficSelector::any_ipv4()],
            }),
            Payload::Notify(NotifyPayload::new(NotifyType::InitialContact, Bytes::default())),
            Payload::Notify(NotifyPayload::new(
                NotifyType::EspTfcPaddingNotSupported,
                Bytes::default(),
            )),
            Payload::Notify(NotifyPayload::new(NotifyType::NonFirstFragmentsAlso, Bytes::default())),
        ]);

        debug!("Sending the CCC auth blob as {:?}", self.ccc_auth_notify);

        payloads.extend(
            self.ccc_auth_notify
                .iter()
                .map(|notify_type| Payload::Notify(NotifyPayload::new(*notify_type, auth_blob.clone()))),
        );

        payloads.push(Payload::Notify(NotifyPayload::new(
            NotifyType::MultipleAuthSupported,
            Bytes::default(),
        )));

        if matches!(client_auth, ClientAuth::Machine(_)) {
            if let Some(notify_type) = self.machine_auth_notify {
                payloads.push(Payload::Notify(NotifyPayload::new(notify_type, Bytes::default())));
            }

            payloads.push(Payload::Notify(NotifyPayload::new(
                NotifyType::AnotherAuthFollows,
                Bytes::default(),
            )));
        }

        Ok(payloads)
    }

    fn certificate_payloads(certificates: impl IntoIterator<Item = Bytes>) -> impl Iterator<Item = Payload> {
        certificates.into_iter().map(|data| {
            Payload::Certificate(CertificatePayload {
                encoding: CertificateEncoding::X509CertificateSignature,
                data,
            })
        })
    }

    fn authenticate_responder(&self, response: &Ikev2Message) -> anyhow::Result<(IdentificationPayload, Vec<Bytes>)> {
        let (id_r, certificates) = Self::responder_identity(response)?;

        let auth = response
            .payloads
            .iter()
            .find_map(|p| match p {
                Payload::Authentication(auth) => Some(auth),
                _ => None,
            })
            .context("No AUTH payload in the IKE_AUTH response")?;

        self.session.verify_auth_r(&id_r.to_bytes(), auth, &certificates)?;
        debug!("Responder authenticated with {:?}", auth.auth_method);

        Ok((id_r, certificates))
    }

    pub async fn step(&mut self, answer: Bytes) -> anyhow::Result<Ikev2Step> {
        let pending = self
            .auth
            .as_mut()
            .and_then(|auth| auth.pending.take())
            .context("No outstanding challenge to answer")?;

        let response = self
            .exchange(
                ExchangeType::IkeAuth,
                vec![Payload::Eap(BasicPayload::new(
                    EapMessage::response(&pending, answer).to_bytes(),
                ))],
                Some(AUTH_TIMEOUT),
            )
            .await?;

        self.continue_auth(response).await
    }

    async fn continue_auth(&mut self, response: Ikev2Message) -> anyhow::Result<Ikev2Step> {
        let eap = response
            .payloads
            .iter()
            .find_map(|p| match p {
                Payload::Eap(eap) => Some(EapMessage::parse(&eap.data)),
                _ => None,
            })
            .transpose()?;

        let auth_log = response.payloads.iter().find_map(|p| match p {
            Payload::Notify(payload) if payload.notify_type == NotifyType::CpRaAuthLog => Some(payload.data.clone()),
            _ => None,
        });

        let Some(eap) = eap else {
            anyhow::ensure!(
                self.auth.as_ref().is_some_and(|auth| auth.authenticated),
                "Responder did not request EAP, and the user has not authenticated"
            );

            debug!("Certificate authentication accepted, no EAP requested");

            return self.finish(response, auth_log).map(Box::new).map(Ikev2Step::Done);
        };

        match eap.code {
            EapCode::Failure => anyhow::bail!("EAP authentication failed"),
            EapCode::Success => {
                debug!("EAP succeeded, sending AUTH");
            }
            _ => {
                trace!("EAP challenge: {:?} id {}", eap.eap_type, eap.identifier);

                let auth = self.auth.as_mut().context("IKE_AUTH is not running")?;
                auth.pending = Some(eap.clone());

                return Ok(Ikev2Step::NeedsChallenge(AuthPrompt { eap }));
            }
        }

        let id_i = self.auth.as_ref().context("IKE_AUTH is not running")?.id_i.clone();
        let auth = self.session.auth_i(&id_i.to_bytes())?;

        let response = self
            .exchange(ExchangeType::IkeAuth, vec![Payload::Authentication(auth)], None)
            .await?;

        self.finish(response, auth_log).map(Box::new).map(Ikev2Step::Done)
    }

    fn finish(&mut self, response: Ikev2Message, auth_log: Option<Bytes>) -> anyhow::Result<AuthResult> {
        let context = self.auth.take().context("IKE_AUTH is not running")?;

        let auth = response
            .payloads
            .iter()
            .find_map(|p| match p {
                Payload::Authentication(auth) => Some(auth),
                _ => None,
            })
            .context("No AUTH payload in the final IKE_AUTH response")?;

        self.session
            .verify_auth_r(&context.id_r.to_bytes(), auth, &context.certificates)?;

        let proposal = Self::parse_esp_proposal(&response, context.esp_spi)?;
        self.session.init_from_child_sa(proposal)?;

        if let Some(lifetime) = response
            .find_notify(NotifyType::AuthLifetime)
            .filter(|n| n.data.len() >= 4)
            .map(|n| u32::from_be_bytes(n.data[..4].try_into().unwrap_or_default()))
        {
            debug!("Authentication lifetime: {lifetime} seconds");
            self.session.set_lifetime(Duration::from_secs(lifetime as u64));
        }

        let office_mode = Self::parse_config_reply(&response, context.username)?;
        let address_expiry = Self::parse_address_expiry(&response);

        match address_expiry {
            Some(expiry) => debug!("Office mode address expires in {} seconds", expiry.as_secs()),
            None => debug!("Gateway stated no office mode address expiry"),
        }

        let selectors = |payload: &Payload| match payload {
            Payload::TrafficSelectorInitiator(ts) | Payload::TrafficSelectorResponder(ts) => ts.selectors.clone(),
            _ => Vec::new(),
        };

        let result = AuthResult {
            office_mode,
            ts_i: response
                .payloads
                .iter()
                .find(|p| matches!(p, Payload::TrafficSelectorInitiator(_)))
                .map(selectors)
                .context("No TSi payload in the final IKE_AUTH response")?,
            ts_r: response
                .payloads
                .iter()
                .find(|p| matches!(p, Payload::TrafficSelectorResponder(_)))
                .map(selectors)
                .context("No TSr payload in the final IKE_AUTH response")?,
            notifies: response.notifies().cloned().collect(),
            address_expiry,
            auth_log,
        };

        let (esp_in, esp_out) = (self.session.esp_in(), self.session.esp_out());
        trace!("IN  SPI : {:08x}, key len {}", esp_in.spi, esp_in.sk_e.len());
        trace!("OUT SPI : {:08x}, key len {}", esp_out.spi, esp_out.sk_e.len());

        debug!("End IKE_AUTH, address: {}", result.office_mode.ip_address);

        Ok(result)
    }

    async fn exchange(
        &mut self,
        exchange_type: ExchangeType,
        payloads: Vec<Payload>,
        timeout: Option<Duration>,
    ) -> anyhow::Result<Ikev2Message> {
        let message_id = self.message_id;

        let request = Ikev2Message {
            initiator_spi: self.session.initiator_spi(),
            responder_spi: self.session.responder_spi(),
            version: IKEV2_VERSION,
            exchange_type,
            flags: Flags::INITIATOR,
            message_id,
            payloads,
        };

        self.transport.send(&request).await?;

        let response = loop {
            let response = self.transport.receive(timeout.unwrap_or(self.socket_timeout)).await?;

            if response.exchange_type == ExchangeType::Informational && !response.is_response() {
                debug!("Acknowledging a responder-initiated INFORMATIONAL");
                self.acknowledge(&response).await?;
                continue;
            }

            if response.message_id != message_id {
                warn!(
                    "Ignoring a response for message {} while waiting for {}",
                    response.message_id, message_id
                );
                continue;
            }

            break response;
        };

        if let Some(notify) = response.error_notify() {
            anyhow::bail!("{:?} rejected: {:?}", exchange_type, notify);
        }

        self.message_id += 1;

        Ok(response)
    }

    /// Rekeys the ESP child SA: a new one is created and keyed, then the one it
    /// replaces is deleted (RFC 7296 §1.3.2).
    ///
    /// No Diffie-Hellman payload, so no PFS — the new keys come from `SK_d` and
    /// this exchange's nonces. Afterwards [`IsakmpSession::esp_in`] and
    /// [`IsakmpSession::esp_out`] carry the new material and SPIs.
    pub async fn rekey_child_sa(&mut self) -> anyhow::Result<()> {
        debug!("Rekeying the child SA");

        let replacing = self.session.esp_in().spi;

        self.establish_child_sa(Some(replacing)).await
    }

    /// Creates a child SA where there is none, which is what a restored IKE SA
    /// needs: the saved session carries the IKE keys but no ESP material.
    ///
    /// The same exchange as a rekey, without the `N(REKEY_SA)` that names an SA
    /// to replace and without the DELETE that follows one (RFC 7296 §1.3.1).
    pub async fn create_child_sa(&mut self) -> anyhow::Result<()> {
        debug!("Creating a child SA");

        self.establish_child_sa(None).await
    }

    async fn establish_child_sa(&mut self, replacing: Option<u32>) -> anyhow::Result<()> {
        let spi: u32 = random();
        let nonce = Bytes::copy_from_slice(&random::<[u8; CHILD_SA_NONCE_SIZE]>());

        let mut payloads = Vec::new();

        // RFC 7296 §3.10: the notify names the SA being replaced by the SPI its
        // sender expects inbound, which is ours.
        if let Some(old_spi) = replacing {
            payloads.push(Payload::Notify(NotifyPayload {
                protocol_id: ProtocolId::Esp,
                spi: Bytes::copy_from_slice(&old_spi.to_be_bytes()),
                notify_type: NotifyType::RekeySa,
                data: Bytes::default(),
            }));
        }

        payloads.extend([
            Payload::SecurityAssociation(SecurityAssociationPayload {
                proposals: Self::build_esp_proposals(spi),
            }),
            Payload::Nonce(BasicPayload::new(nonce.clone())),
            Payload::TrafficSelectorInitiator(TrafficSelectorPayload {
                selectors: vec![TrafficSelector::any_ipv4()],
            }),
            Payload::TrafficSelectorResponder(TrafficSelectorPayload {
                selectors: vec![TrafficSelector::any_ipv4()],
            }),
        ]);

        let response = self.exchange(ExchangeType::CreateChildSa, payloads, None).await?;

        let proposal = Self::parse_esp_proposal(&response, spi)?;
        let peer_nonce = Self::nonce_of(&response)?;

        self.session.rekey_child_sa(proposal, &nonce, &peer_nonce, true)?;

        debug!(
            "Child SA established, IN SPI {:08x}, OUT SPI {:08x}",
            self.session.esp_in().spi,
            self.session.esp_out().spi
        );

        match replacing {
            Some(old_spi) => self.delete_child_sa(old_spi).await,
            None => Ok(()),
        }
    }

    /// An INFORMATIONAL carrying a DELETE for one of our inbound ESP SAs.
    pub async fn delete_child_sa(&mut self, spi: u32) -> anyhow::Result<()> {
        debug!("Deleting child SA {:08x}", spi);

        let payloads = vec![Payload::Delete(DeletePayload {
            protocol_id: ProtocolId::Esp,
            spi_size: 4,
            spis: vec![Bytes::copy_from_slice(&spi.to_be_bytes())],
        })];

        self.exchange(ExchangeType::Informational, payloads, None).await?;

        Ok(())
    }

    /// An INFORMATIONAL carrying a DELETE for the IKE SA, which takes its child
    /// SAs with it. A DELETE for an IKE SA carries no SPIs (RFC 7296 §3.11).
    pub async fn delete_ike_sa(&mut self) -> anyhow::Result<()> {
        debug!("Deleting the IKE SA");

        let payloads = vec![Payload::Delete(DeletePayload {
            protocol_id: ProtocolId::Ike,
            spi_size: 0,
            spis: Vec::new(),
        })];

        self.exchange(ExchangeType::Informational, payloads, None).await?;

        Ok(())
    }

    /// The session as a blob, for a caller that wants to resume it later.
    /// Carries the Message ID as well as the keys, so a restored SA continues
    /// the peer's window instead of replaying it.
    pub fn save_session(&mut self, office_mode: &OfficeMode) -> anyhow::Result<Vec<u8>> {
        self.session.set_message_id(self.message_id);
        self.session.save(office_mode)
    }

    /// Restores a session saved by [`Ikev2Service::save_session`]. The IKE SA
    /// is usable afterwards, but has no child SA: ESP material is not persisted,
    /// so [`Ikev2Service::create_child_sa`] has to follow.
    pub fn load_session(&mut self, data: &[u8]) -> anyhow::Result<OfficeMode> {
        let office_mode = self.session.load(data)?;
        self.message_id = self.session.message_id();

        debug!("Restored IKE session, next message id {}", self.message_id);

        Ok(office_mode)
    }

    /// Renews the office mode address lease: a CFG_REQUEST naming the address
    /// we already hold, carried in an INFORMATIONAL exchange.
    ///
    /// This is what the Windows client does, at roughly half the lease. The
    /// gateway answers with a CFG_REPLY carrying the address — the same one, in
    /// every capture seen — and a fresh `INTERNAL_ADDRESS_EXPIRY`.
    pub async fn renew_office_mode(&mut self, address: Ipv4Addr) -> anyhow::Result<OfficeModeLease> {
        debug!("Renewing the office mode lease on {}", address);

        let payloads = vec![Payload::Configuration(Self::build_config_request(Some(address), false))];

        let response = self.exchange(ExchangeType::Informational, payloads, None).await?;

        let lease = OfficeModeLease {
            address: Self::config_address(&response, ConfigurationAttributeType::InternalIp4Address)
                .context("No address in the CFG_REPLY")?,
            netmask: Self::config_address(&response, ConfigurationAttributeType::InternalIp4Netmask),
            expiry: Self::parse_address_expiry(&response),
        };

        match lease.expiry {
            Some(expiry) => debug!(
                "Office mode lease renewed: {} for {} seconds",
                lease.address,
                expiry.as_secs()
            ),
            None => debug!("Office mode lease renewed: {}, no expiry stated", lease.address),
        }

        Ok(lease)
    }

    /// One IPv4-shaped configuration attribute out of a CFG_REPLY.
    fn config_address(response: &Ikev2Message, attribute_type: ConfigurationAttributeType) -> Option<Ipv4Addr> {
        response
            .payloads
            .iter()
            .find_map(|p| match p {
                Payload::Configuration(config) => Some(config),
                _ => None,
            })?
            .attributes
            .iter()
            .find(|a| a.attribute_type == attribute_type)
            .and_then(|a| <[u8; 4]>::try_from(a.data.as_ref()).ok())
            .map(Ipv4Addr::from)
    }

    /// Waits briefly for a request the peer may have opened, returning `None`
    /// when none arrives in `timeout`.
    ///
    /// Nothing reads the IKE channel between exchanges, so a caller that wants
    /// to notice a gateway-initiated rekey or delete has to come looking. Pair
    /// it with [`Ikev2Service::handle_request`].
    pub async fn poll_request(&mut self, timeout: Duration) -> anyhow::Result<Option<Ikev2Message>> {
        match self.transport.receive(timeout).await {
            Ok(message) if !message.is_response() => Ok(Some(message)),
            Ok(message) => {
                warn!("Discarding a stray response for message {}", message.message_id);
                Ok(None)
            }
            // nothing to read is the normal case, not a failure
            Err(e) if e.downcast_ref::<tokio::time::error::Elapsed>().is_some() => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Answers a request the peer opened, and reports what it asked for.
    ///
    /// IKEv2 does not negotiate child SA lifetimes — each side rekeys on its
    /// own policy — so the gateway opens a CREATE_CHILD_SA of its own, and an
    /// unanswered one ends with it deleting the SA. The caller feeds anything
    /// arriving outside its own exchanges here.
    pub async fn handle_request(&mut self, request: &Ikev2Message) -> anyhow::Result<PeerRequest> {
        anyhow::ensure!(!request.is_response(), "Not a peer request");

        match request.exchange_type {
            ExchangeType::CreateChildSa => self.answer_child_sa_rekey(request).await,
            ExchangeType::Informational => {
                let deleted = request.payloads.iter().any(|p| matches!(p, Payload::Delete(_)));

                // RFC 7296 §2.4 wants a response even when there is nothing to
                // say, and an empty one answers a DELETE too: the SA is going
                // away either way.
                self.respond(request, Vec::new()).await?;

                Ok(match deleted {
                    true => PeerRequest::Deleted,
                    false => PeerRequest::Other,
                })
            }
            other => {
                debug!("Ignoring a peer-initiated {:?}", other);
                Ok(PeerRequest::Other)
            }
        }
    }

    /// The responder half of a child SA rekey: choose from what the peer
    /// offered, answer with our own SPI and nonce, then key from both nonces.
    async fn answer_child_sa_rekey(&mut self, request: &Ikev2Message) -> anyhow::Result<PeerRequest> {
        debug!("Peer is rekeying the child SA");

        let peer_nonce = Self::nonce_of(request)?;
        let chosen = Self::select_esp_proposal(request)?;

        let spi: u32 = random();
        let nonce = Bytes::copy_from_slice(&random::<[u8; CHILD_SA_NONCE_SIZE]>());

        // The peer opened this exchange, so the SPI its proposal carries is the
        // *initiator's*; `esp_proposal_from` parks it in `spi_r` because it is
        // written for reading a response. Ours takes the responder's slot.
        let proposal = Ikev2EspProposal {
            spi_i: chosen.spi_r,
            spi_r: spi,
            ..chosen
        };

        // the selectors are echoed rather than narrowed: this replaces an SA
        // that already carries them
        let payloads = vec![
            Payload::SecurityAssociation(SecurityAssociationPayload {
                proposals: vec![Self::echo_esp_proposal(spi, &proposal)],
            }),
            Payload::Nonce(BasicPayload::new(nonce.clone())),
            Payload::TrafficSelectorInitiator(TrafficSelectorPayload {
                selectors: vec![TrafficSelector::any_ipv4()],
            }),
            Payload::TrafficSelectorResponder(TrafficSelectorPayload {
                selectors: vec![TrafficSelector::any_ipv4()],
            }),
        ];

        self.respond(request, payloads).await?;

        self.session.rekey_child_sa(proposal, &peer_nonce, &nonce, false)?;

        debug!(
            "Child SA rekeyed by the peer, IN SPI {:08x}, OUT SPI {:08x}",
            self.session.esp_in().spi,
            self.session.esp_out().spi
        );

        Ok(PeerRequest::ChildSaRekeyed)
    }

    /// Sends a response to a request the peer opened. Its Message ID belongs to
    /// the peer's window, so ours is left alone.
    async fn respond(&mut self, request: &Ikev2Message, payloads: Vec<Payload>) -> anyhow::Result<()> {
        let response = Ikev2Message {
            initiator_spi: request.initiator_spi,
            responder_spi: request.responder_spi,
            version: IKEV2_VERSION,
            exchange_type: request.exchange_type,
            flags: Flags::RESPONSE,
            message_id: request.message_id,
            payloads,
        };

        self.transport.send(&response).await
    }

    fn nonce_of(message: &Ikev2Message) -> anyhow::Result<Bytes> {
        message
            .payloads
            .iter()
            .find_map(|p| match p {
                Payload::Nonce(nonce) => Some(nonce.data.clone()),
                _ => None,
            })
            .context("No nonce payload")
    }

    /// The first ESP proposal the peer offered that we can key.
    fn select_esp_proposal(request: &Ikev2Message) -> anyhow::Result<Ikev2EspProposal> {
        request
            .payloads
            .iter()
            .find_map(|p| match p {
                Payload::SecurityAssociation(sa) => Some(&sa.proposals),
                _ => None,
            })
            .context("No SA payload in the CREATE_CHILD_SA request")?
            .iter()
            .find_map(|proposal| Self::esp_proposal_from(proposal).ok())
            .context("No ESP proposal we can key")
    }

    /// The chosen proposal alone, which is what a responder answers with.
    fn echo_esp_proposal(spi: u32, proposal: &Ikev2EspProposal) -> Proposal {
        let mut transforms = vec![Transform::encryption(
            proposal.encryption,
            (proposal.key_len > 0).then_some(proposal.key_len as u16),
        )];

        if proposal.integrity != IntegrityAlgorithm::None {
            transforms.push(Transform::integrity(proposal.integrity));
        }

        transforms.push(Transform::esn(ExtendedSequenceNumbers::None));

        Proposal {
            proposal_num: 1,
            protocol_id: ProtocolId::Esp,
            spi: Bytes::copy_from_slice(&spi.to_be_bytes()),
            transforms,
        }
    }

    async fn acknowledge(&mut self, request: &Ikev2Message) -> anyhow::Result<()> {
        let response = Ikev2Message {
            initiator_spi: request.initiator_spi,
            responder_spi: request.responder_spi,
            version: IKEV2_VERSION,
            exchange_type: ExchangeType::Informational,
            flags: Flags::INITIATOR | Flags::RESPONSE,
            message_id: request.message_id,
            payloads: Vec::new(),
        };

        self.transport.send(&response).await
    }

    /// CFG_REQUEST. `address` is empty at login and the address we already hold
    /// when renewing it. The session cookie is asked for only at login: the
    /// captured client leaves it out of a renewal.
    fn build_config_request(address: Option<Ipv4Addr>, with_session_cookie: bool) -> ConfigurationPayload {
        let mut attributes = vec![ConfigurationAttribute {
            attribute_type: ConfigurationAttributeType::InternalIp4Address,
            data: address.map(|a| Bytes::copy_from_slice(&a.octets())).unwrap_or_default(),
        }];

        attributes.extend(
            [
                ConfigurationAttributeType::InternalIp4Netmask,
                ConfigurationAttributeType::InternalIp4Dns,
                ConfigurationAttributeType::InternalIp4Nbns,
                ConfigurationAttributeType::InternalAddressExpiry,
                ConfigurationAttributeType::CccDomainName,
            ]
            .map(ConfigurationAttribute::request),
        );

        if with_session_cookie {
            attributes.extend([ConfigurationAttributeType::CccSessionCookie].map(ConfigurationAttribute::request));
        }

        ConfigurationPayload {
            cfg_type: ConfigurationType::Request,
            attributes,
        }
    }

    fn build_esp_proposals(spi: u32) -> Vec<Proposal> {
        let spi = Bytes::copy_from_slice(&spi.to_be_bytes());

        let aead = Proposal {
            proposal_num: 1,
            protocol_id: ProtocolId::Esp,
            spi: spi.clone(),
            transforms: vec![
                Transform::encryption(EncryptionAlgorithm::AesGcm16, Some(32)),
                Transform::encryption(EncryptionAlgorithm::AesGcm16, Some(16)),
                Transform::encryption(EncryptionAlgorithm::AesGcm12, Some(32)),
                Transform::encryption(EncryptionAlgorithm::AesGcm12, Some(16)),
                Transform::integrity(IntegrityAlgorithm::None),
                Transform::esn(ExtendedSequenceNumbers::None),
            ],
        };

        let cbc = Proposal {
            proposal_num: 2,
            protocol_id: ProtocolId::Esp,
            spi,
            transforms: vec![
                Transform::encryption(EncryptionAlgorithm::AesCbc, Some(32)),
                Transform::encryption(EncryptionAlgorithm::AesCbc, Some(16)),
                Transform::encryption(EncryptionAlgorithm::DesEde3Cbc, None),
                Transform::integrity(IntegrityAlgorithm::HmacSha512_256),
                Transform::integrity(IntegrityAlgorithm::HmacSha384_192),
                Transform::integrity(IntegrityAlgorithm::HmacSha256_128),
                Transform::integrity(IntegrityAlgorithm::HmacSha1_96),
                Transform::esn(ExtendedSequenceNumbers::None),
            ],
        };

        vec![aead, cbc]
    }

    fn responder_identity(response: &Ikev2Message) -> anyhow::Result<(IdentificationPayload, Vec<Bytes>)> {
        let id_r = response
            .payloads
            .iter()
            .find_map(|p| match p {
                Payload::IdentificationResponder(id) => Some(id.clone()),
                _ => None,
            })
            .context("No IDr payload in the IKE_AUTH response")?;

        let certificates = response
            .payloads
            .iter()
            .filter_map(|p| match p {
                Payload::Certificate(cert) => Some(cert.data.clone()),
                _ => None,
            })
            .collect();

        Ok((id_r, certificates))
    }

    fn parse_esp_proposal(response: &Ikev2Message, spi_i: u32) -> anyhow::Result<Ikev2EspProposal> {
        let proposal = response
            .payloads
            .iter()
            .find_map(|p| match p {
                Payload::SecurityAssociation(sa) => sa.proposals.first(),
                _ => None,
            })
            .context("No SA payload in the response")?;

        Ok(Ikev2EspProposal {
            spi_i,
            ..Self::esp_proposal_from(proposal)?
        })
    }

    /// One ESP proposal read into the crypto parameters it names.
    ///
    /// The SPI the proposal carries lands in `spi_r` and `spi_i` is left zero,
    /// which suits reading a response. Reading a *request* means the SPI is the
    /// initiator's, so the caller swaps it — see `answer_child_sa_rekey`.
    fn esp_proposal_from(proposal: &Proposal) -> anyhow::Result<Ikev2EspProposal> {
        let encryption = proposal
            .find(TransformType::EncryptionAlgorithm)
            .and_then(Transform::as_encryption)
            .context("No encryption transform in the child SA")?;

        let key_len = proposal
            .find(TransformType::EncryptionAlgorithm)
            .and_then(Transform::key_len)
            .unwrap_or(match encryption {
                EncryptionAlgorithm::DesEde3Cbc => 24,
                _ => 0,
            });

        anyhow::ensure!(
            proposal.spi.len() == 4,
            "Child SA proposal carries a {}-octet SPI, expected 4",
            proposal.spi.len()
        );

        let integrity = proposal
            .find(TransformType::IntegrityAlgorithm)
            .and_then(Transform::as_integrity)
            .unwrap_or(IntegrityAlgorithm::None);

        // reject here rather than at keying time, so a proposal we cannot use
        // is simply passed over when choosing among several
        encryption.to_cipher_type(key_len)?;
        integrity.to_authentication()?;

        Ok(Ikev2EspProposal {
            spi_i: 0,
            spi_r: u32::from_be_bytes(proposal.spi[..4].try_into()?),
            encryption,
            key_len,
            integrity,
        })
    }

    /// `INTERNAL_ADDRESS_EXPIRY` from the CFG_REPLY: four octets of seconds.
    fn parse_address_expiry(response: &Ikev2Message) -> Option<Duration> {
        response
            .payloads
            .iter()
            .find_map(|p| match p {
                Payload::Configuration(config) => Some(config),
                _ => None,
            })?
            .attributes
            .iter()
            .find(|a| a.attribute_type == ConfigurationAttributeType::InternalAddressExpiry)
            .and_then(|a| <[u8; 4]>::try_from(a.data.as_ref()).ok())
            .map(|seconds| Duration::from_secs(u32::from_be_bytes(seconds) as u64))
    }

    fn parse_config_reply(response: &Ikev2Message, username: String) -> anyhow::Result<OfficeMode> {
        let config = response
            .payloads
            .iter()
            .find_map(|p| match p {
                Payload::Configuration(config) => Some(config),
                _ => None,
            })
            .context("No CFG_REPLY payload in the final IKE_AUTH response")?;

        anyhow::ensure!(
            config.cfg_type == ConfigurationType::Reply,
            "Expected a CFG_REPLY, got {:?}",
            config.cfg_type
        );

        let address =
            |data: &Bytes| -> Option<Ipv4Addr> { <[u8; 4]>::try_from(data.as_ref()).ok().map(Ipv4Addr::from) };

        let find = |attribute_type| {
            config
                .attributes
                .iter()
                .find(|a| a.attribute_type == attribute_type)
                .map(|a| a.data.clone())
        };

        let all = |attribute_type| {
            config
                .attributes
                .iter()
                .filter(move |a| a.attribute_type == attribute_type)
                .map(|a| a.data.clone())
        };

        Ok(OfficeMode {
            username,
            // the cookie arrives as 32 ASCII hex characters, not 16 octets,
            // exactly as the IKEv1 `CccSessionId` attribute does
            ccc_session: find(ConfigurationAttributeType::CccSessionCookie)
                .map(|data| String::from_utf8_lossy(&data).trim_matches('\0').to_owned())
                .unwrap_or_default(),
            ip_address: find(ConfigurationAttributeType::InternalIp4Address)
                .and_then(|data| address(&data))
                .context("No address in the CFG_REPLY")?,
            netmask: find(ConfigurationAttributeType::InternalIp4Netmask)
                .and_then(|data| address(&data))
                .unwrap_or(Ipv4Addr::UNSPECIFIED),
            dns: all(ConfigurationAttributeType::InternalIp4Dns)
                .filter_map(|data| address(&data))
                .collect(),
            domains: all(ConfigurationAttributeType::CccDomainName)
                .filter_map(|data| String::from_utf8(data.to_vec()).ok())
                .flat_map(|domains| {
                    domains
                        .split(',')
                        .map(|domain| domain.trim().to_owned())
                        .filter(|domain| !domain.is_empty())
                        .collect::<Vec<_>>()
                })
                .collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
    };

    use async_trait::async_trait;

    use openssl::{
        asn1::Asn1Time,
        hash::MessageDigest,
        pkcs12::Pkcs12,
        pkey::{PKey, Private},
        rsa::Rsa,
        sign::Verifier,
        x509::{X509, X509NameBuilder},
    };
    use secrecy::SecretString;

    use crate::{
        crypto::{CipherType, Crypto, DigestType, IcvLength},
        ikev2::{
            model::{AuthMethod, PayloadType},
            payload::{AuthenticationPayload, KeyExchangePayload},
        },
        model::Identity,
        session::SessionType,
    };

    use super::*;

    const LOCAL: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 39123);
    const GATEWAY: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(172, 24, 1, 5), 4500);
    const RESPONDER_SPI: u64 = 0x38886c6561301a09;

    /// Queued responses and the requests they drew, shared with the transport
    /// so a test can keep scripting as the exchange proceeds — the later
    /// responses depend on keys that only exist once IKE_SA_INIT has run.
    #[derive(Clone, Default)]
    struct Script {
        requests: Arc<Mutex<Vec<Ikev2Message>>>,
        responses: Arc<Mutex<VecDeque<Ikev2Message>>>,
    }

    impl Script {
        fn push(&self, message: Ikev2Message) {
            self.responses.lock().unwrap().push_back(message);
        }

        fn requests(&self) -> Vec<Ikev2Message> {
            self.requests.lock().unwrap().clone()
        }
    }

    /// Replies from a [`Script`] and keeps every request, so an exchange can be
    /// driven and inspected without a gateway.
    struct ScriptedTransport(Script);

    #[async_trait]
    impl IsakmpTransport<Ikev2Message> for ScriptedTransport {
        async fn send(&mut self, message: &Ikev2Message) -> anyhow::Result<()> {
            self.0.requests.lock().unwrap().push(message.clone());
            Ok(())
        }

        async fn receive(&mut self, _timeout: Duration) -> anyhow::Result<Ikev2Message> {
            self.0
                .responses
                .lock()
                .unwrap()
                .pop_front()
                .context("The script ran out of responses")
        }

        fn disconnect(&mut self) {}
    }

    /// A service whose script is built around the SPI the session just picked.
    fn new_service(responses: impl FnOnce(u64) -> Vec<Ikev2Message>) -> (Ikev2Service, Script) {
        new_service_for(Identity::None, responses)
    }

    fn new_service_for(identity: Identity, responses: impl FnOnce(u64) -> Vec<Ikev2Message>) -> (Ikev2Service, Script) {
        // pinned rather than left to `DEFAULT_GROUP`: these tests are about the
        // exchange, not about which group the default happens to be
        let session = Ikev2Session::with_dh_group(identity, SessionType::Initiator, GroupType::Oakley2).unwrap();

        let script = Script::default();
        for response in responses(session.initiator_spi()) {
            script.push(response);
        }

        let transport = ScriptedTransport(script.clone());

        (Ikev2Service::new(Box::new(transport), session).unwrap(), script)
    }

    fn response(initiator_spi: u64, payloads: Vec<Payload>) -> Ikev2Message {
        Ikev2Message {
            initiator_spi,
            responder_spi: RESPONDER_SPI,
            version: IKEV2_VERSION,
            exchange_type: ExchangeType::IkeSaInit,
            flags: Flags::RESPONSE,
            message_id: 0,
            payloads,
        }
    }

    /// An IKE_SA_INIT response in the shape the Check Point gateway sends:
    /// AES-256, PRF-SHA1, HMAC-SHA1-96, MODP-1024, with NAT detection and two
    /// vendor notifies that must survive as `Other`.
    fn sa_init_response(initiator_spi: u64, group: DhGroup, nat: bool) -> Ikev2Message {
        let peer =
            Crypto::with_parameters(DigestType::Sha1, CipherType::Aes256Cbc, group.to_group_type().unwrap()).unwrap();

        let source = if nat {
            SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 4500)
        } else {
            GATEWAY
        };

        response(
            initiator_spi,
            vec![
                Payload::SecurityAssociation(SecurityAssociationPayload {
                    proposals: vec![Proposal {
                        proposal_num: 1,
                        protocol_id: ProtocolId::Ike,
                        spi: Bytes::copy_from_slice(&RESPONDER_SPI.to_be_bytes()),
                        transforms: vec![
                            Transform::encryption(EncryptionAlgorithm::AesCbc, Some(32)),
                            Transform::prf(PseudoRandomFunction::HmacSha1),
                            Transform::integrity(IntegrityAlgorithm::HmacSha1_96),
                            Transform::dh_group(group),
                        ],
                    }],
                }),
                Payload::KeyExchange(KeyExchangePayload {
                    dh_group: group,
                    data: peer.public_key().unwrap(),
                }),
                Payload::Nonce(BasicPayload::new(Bytes::from_static(&[0x42; 32]))),
                Payload::Notify(NotifyPayload::new(
                    NotifyType::NatDetectionSourceIp,
                    nat_detection_hash(initiator_spi, RESPONDER_SPI, source),
                )),
                Payload::Notify(NotifyPayload::new(
                    NotifyType::NatDetectionDestinationIp,
                    nat_detection_hash(initiator_spi, RESPONDER_SPI, LOCAL),
                )),
                // CCC Policy ID / CCC Realm: numbers pending, names known
                Payload::Notify(NotifyPayload::new(
                    NotifyType::Other(40001),
                    Bytes::from_static(&[0x7d, 0xb3, 0xaa, 0x6a]),
                )),
                Payload::Notify(NotifyPayload::new(
                    NotifyType::Other(40002),
                    Bytes::from_static(&[0x6a; 16]),
                )),
            ],
        )
    }

    fn sent_payload(request: &Ikev2Message, payload_type: PayloadType) -> Option<&Payload> {
        request.payloads.iter().find(|p| p.as_payload_type() == payload_type)
    }

    #[tokio::test]
    async fn test_sa_init_keys_the_session() {
        let (mut service, script) = new_service(|spi| vec![sa_init_response(spi, DhGroup::Modp1024, false)]);

        let result = service.do_sa_init(LOCAL, GATEWAY).await.unwrap();

        assert!(service.session.is_keyed());
        assert_eq!(service.session.responder_spi(), RESPONDER_SPI);
        assert_eq!(service.message_id(), 1);
        assert!(!result.local_nat);
        assert!(!result.remote_nat);

        // the vendor notifies are kept for IKE_AUTH rather than dropped
        assert_eq!(result.notifies.len(), 4);
        assert!(
            result
                .notifies
                .iter()
                .any(|n| n.notify_type == NotifyType::Other(40001))
        );

        // the key schedule ran with the negotiated transforms
        let keys = service.session.session_keys();
        assert_eq!(keys.sk_d.len(), 20, "PRF-SHA1");
        assert_eq!(keys.sk_ai.len(), 20, "HMAC-SHA1");
        assert_eq!(keys.sk_ei.len(), 32, "AES-256");

        let requests = script.requests();
        assert_eq!(requests.len(), 1);

        let request = &requests[0];
        assert_eq!(request.exchange_type, ExchangeType::IkeSaInit);
        assert_eq!(request.message_id, 0);
        assert_eq!(request.flags, Flags::INITIATOR);
        assert_eq!(request.responder_spi, 0);

        // the KE payload matches the group we offered first
        let Some(Payload::KeyExchange(ke)) = sent_payload(request, PayloadType::KeyExchange) else {
            panic!("no KE payload")
        };
        assert_eq!(ke.dh_group, DhGroup::Modp1024);
        assert_eq!(ke.data.len(), 128);

        assert!(sent_payload(request, PayloadType::VendorId).is_some());
        assert_eq!(request.notifies().filter(|n| n.notify_type.is_error()).count(), 0);
    }

    #[tokio::test]
    async fn test_sa_init_answers_a_cookie_challenge() {
        let cookie = Bytes::from_static(b"a cookie from the responder");

        let (mut service, script) = new_service(|spi| {
            vec![
                response(
                    spi,
                    vec![Payload::Notify(NotifyPayload::new(NotifyType::Cookie, cookie.clone()))],
                ),
                sa_init_response(spi, DhGroup::Modp1024, false),
            ]
        });

        service.do_sa_init(LOCAL, GATEWAY).await.unwrap();
        assert!(service.session.is_keyed());

        let requests = script.requests();
        assert_eq!(requests.len(), 2);

        // RFC 7296 §2.6: the cookie leads the retried request
        match &requests[1].payloads[0] {
            Payload::Notify(notify) => {
                assert_eq!(notify.notify_type, NotifyType::Cookie);
                assert_eq!(notify.data, cookie);
            }
            other => panic!("expected the cookie first, got {other:?}"),
        }

        // and nothing else about the request changed
        assert_eq!(requests[0].initiator_spi, requests[1].initiator_spi);
        assert_eq!(requests[0].payloads.len() + 1, requests[1].payloads.len());
    }

    #[tokio::test]
    async fn test_sa_init_retries_with_the_group_the_responder_wants() {
        let (mut service, script) = new_service(|spi| {
            vec![
                response(
                    spi,
                    vec![Payload::Notify(NotifyPayload::new(
                        NotifyType::InvalidKePayload,
                        Bytes::copy_from_slice(&14u16.to_be_bytes()),
                    ))],
                ),
                sa_init_response(spi, DhGroup::Modp2048, false),
            ]
        });

        service.do_sa_init(LOCAL, GATEWAY).await.unwrap();

        assert!(service.session.is_keyed());
        assert_eq!(service.session.dh_group(), GroupType::Oakley14);

        let requests = script.requests();
        assert_eq!(requests.len(), 2);

        let ke = |request: &Ikev2Message| match sent_payload(request, PayloadType::KeyExchange) {
            Some(Payload::KeyExchange(ke)) => (ke.dh_group, ke.data.len()),
            _ => panic!("no KE payload"),
        };

        assert_eq!(ke(&requests[0]), (DhGroup::Modp1024, 128));
        assert_eq!(ke(&requests[1]), (DhGroup::Modp2048, 256));

        // the SA identity survives the retry (RFC 7296 §2.7)
        assert_eq!(requests[0].initiator_spi, requests[1].initiator_spi);
    }

    #[tokio::test]
    async fn test_sa_init_detects_nat() {
        // the responder hashed a different source address than the one we sent
        // to, and our own address matched
        let (mut service, _script) = new_service(|spi| vec![sa_init_response(spi, DhGroup::Modp1024, true)]);

        let result = service.do_sa_init(LOCAL, GATEWAY).await.unwrap();
        assert!(result.remote_nat);
        assert!(!result.local_nat);

        // a gateway answering on several addresses sends one source notify per
        // address: any match means no NAT
        let (mut service, _script) = new_service(|spi| {
            let mut scripted = sa_init_response(spi, DhGroup::Modp1024, true);
            scripted.payloads.push(Payload::Notify(NotifyPayload::new(
                NotifyType::NatDetectionSourceIp,
                nat_detection_hash(spi, RESPONDER_SPI, GATEWAY),
            )));
            vec![scripted]
        });

        let result = service.do_sa_init(LOCAL, GATEWAY).await.unwrap();
        assert!(!result.remote_nat);
    }

    #[tokio::test]
    async fn test_sa_init_reports_a_rejection() {
        let (mut service, _script) = new_service(|spi| {
            vec![response(
                spi,
                vec![Payload::Notify(NotifyPayload::new(
                    NotifyType::NoProposalChosen,
                    Bytes::default(),
                ))],
            )]
        });

        let err = service.do_sa_init(LOCAL, GATEWAY).await.unwrap_err().to_string();
        assert!(err.contains("NoProposalChosen"), "{err}");
        assert!(!service.session.is_keyed());
    }

    #[tokio::test]
    async fn test_sa_init_gives_up_on_a_looping_responder() {
        let (mut service, _script) = new_service(|spi| {
            let cookie = |n: u8| {
                response(
                    spi,
                    vec![Payload::Notify(NotifyPayload::new(
                        NotifyType::Cookie,
                        Bytes::copy_from_slice(&[n; 8]),
                    ))],
                )
            };
            vec![cookie(1), cookie(2), cookie(3), cookie(4)]
        });

        // the second cookie is not answered again: it is not an error notify,
        // so it falls through to the proposal parse and fails there
        assert!(service.do_sa_init(LOCAL, GATEWAY).await.is_err());
        assert!(!service.session.is_keyed());
    }

    /// The child SA offer is two proposals, AEAD first, because a responder
    /// chooses one transform of each type within a single proposal: AES-GCM
    /// and an HMAC in the same one could be answered with both.
    #[test]
    fn test_esp_proposals_keep_aead_separate() {
        let proposals = Ikev2Service::build_esp_proposals(ESP_SPI_I);

        assert_eq!(proposals.len(), 2);

        for (proposal, num) in proposals.iter().zip(1..) {
            assert_eq!(proposal.proposal_num, num);
            assert_eq!(proposal.protocol_id, ProtocolId::Esp);
            assert_eq!(proposal.spi, Bytes::copy_from_slice(&ESP_SPI_I.to_be_bytes()));
            assert!(proposal.find(TransformType::ExtendedSequenceNumbers).is_some());

            // every encryption transform in a proposal agrees with every
            // integrity transform in it about whether the cipher is AEAD
            let aead = proposal
                .transforms
                .iter()
                .filter_map(Transform::as_encryption)
                .map(|encryption| encryption.is_aead())
                .collect::<Vec<_>>();
            let integ_none = proposal
                .transforms
                .iter()
                .filter_map(Transform::as_integrity)
                .map(|integrity| integrity == IntegrityAlgorithm::None)
                .collect::<Vec<_>>();

            assert!(!aead.is_empty() && !integ_none.is_empty());
            assert!(aead.iter().chain(&integ_none).all(|is_aead| *is_aead == aead[0]));
        }

        assert!(
            proposals[0]
                .transforms
                .iter()
                .filter_map(Transform::as_encryption)
                .all(|encryption| encryption.is_aead()),
            "the AEAD proposal is the preferred one"
        );
    }

    /// A gateway that picks AES-GCM answers with no integrity transform at
    /// all, which is INTEG_NONE rather than a missing one.
    #[test]
    fn test_esp_response_without_integrity_is_aead() {
        let response = Ikev2Message {
            initiator_spi: 1,
            responder_spi: 2,
            version: IKEV2_VERSION,
            exchange_type: ExchangeType::IkeAuth,
            flags: Flags::RESPONSE,
            message_id: 1,
            payloads: vec![Payload::SecurityAssociation(SecurityAssociationPayload {
                proposals: vec![Proposal {
                    proposal_num: 1,
                    protocol_id: ProtocolId::Esp,
                    spi: Bytes::copy_from_slice(&ESP_SPI_R.to_be_bytes()),
                    transforms: vec![
                        Transform::encryption(EncryptionAlgorithm::AesGcm16, Some(32)),
                        Transform::esn(ExtendedSequenceNumbers::None),
                    ],
                }],
            })],
        };

        let proposal = Ikev2Service::parse_esp_proposal(&response, ESP_SPI_I).unwrap();

        assert_eq!(proposal.encryption, EncryptionAlgorithm::AesGcm16);
        assert_eq!(proposal.key_len, 32);
        assert_eq!(proposal.integrity, IntegrityAlgorithm::None);
        assert_eq!(
            proposal.encryption.to_cipher_type(proposal.key_len).unwrap(),
            CipherType::Aes256Gcm(IcvLength::Sixteen)
        );
    }

    /// A gateway that returns its whole policy instead of a choice: only the
    /// transforms we actually offered are candidates, and the first of those
    /// wins. Taking the responder's first outright would key the SA from a
    /// transform we never proposed.
    #[tokio::test]
    async fn test_ambiguous_response_is_narrowed_to_what_we_offered() {
        let (mut service, _script) = new_service(|spi| {
            let mut scripted = sa_init_response(spi, DhGroup::Modp1024, false);
            if let Some(Payload::SecurityAssociation(sa)) = scripted
                .payloads
                .iter_mut()
                .find(|p| p.as_payload_type() == PayloadType::SecurityAssociation)
            {
                sa.proposals[0].transforms = vec![
                    // AES-192 and AES-XCBC are not in our offer and must be skipped
                    Transform::encryption(EncryptionAlgorithm::AesCbc, Some(24)),
                    Transform::encryption(EncryptionAlgorithm::AesCbc, Some(32)),
                    Transform::prf(PseudoRandomFunction::AesXCbc),
                    Transform::prf(PseudoRandomFunction::HmacSha256),
                    Transform::prf(PseudoRandomFunction::HmacSha1),
                    Transform::integrity(IntegrityAlgorithm::AesXCbc96),
                    Transform::integrity(IntegrityAlgorithm::HmacSha256_128),
                    Transform::dh_group(DhGroup::Modp1024),
                ];
            }
            vec![scripted]
        });

        service.do_sa_init(LOCAL, GATEWAY).await.unwrap();

        let keys = service.session.session_keys();
        assert_eq!(keys.sk_ei.len(), 32, "AES-256, not the AES-192 listed first");
        assert_eq!(keys.sk_d.len(), 32, "PRF-SHA256, not the AES-XCBC listed first");
        assert_eq!(keys.sk_ai.len(), 32, "HMAC-SHA2-256");
    }

    /// A responder that answers with a transform we never proposed is not
    /// negotiating, and keying from it would fail invisibly.
    #[tokio::test]
    async fn test_sa_init_rejects_a_transform_we_did_not_offer() {
        let (mut service, _script) = new_service(|spi| {
            let mut scripted = sa_init_response(spi, DhGroup::Modp1024, false);
            if let Some(Payload::SecurityAssociation(sa)) = scripted
                .payloads
                .iter_mut()
                .find(|p| p.as_payload_type() == PayloadType::SecurityAssociation)
            {
                sa.proposals[0].transforms = vec![
                    Transform::encryption(EncryptionAlgorithm::AesCbc, Some(32)),
                    Transform::prf(PseudoRandomFunction::AesCmac),
                    Transform::integrity(IntegrityAlgorithm::HmacSha1_96),
                    Transform::dh_group(DhGroup::Modp1024),
                ];
            }
            vec![scripted]
        });

        let err = service.do_sa_init(LOCAL, GATEWAY).await.unwrap_err().to_string();
        assert!(err.contains("no PRF transform we offered"), "{err}");
    }

    /// RFC 7296 §3.4 makes the KE payload the statement of which group the
    /// data is in, and real gateways need that: one Check Point build answers
    /// with a proposal of ENCR/PRF/INTEG and no D-H transform, another names a
    /// group its own KE payload contradicts. Neither may stop the exchange.
    #[tokio::test]
    async fn test_sa_init_keys_from_the_ke_payload_not_the_proposal() {
        // a proposal naming a group the KE payload disagrees with
        let (mut service, _script) = new_service(|spi| {
            let mut scripted = sa_init_response(spi, DhGroup::Modp1024, false);
            if let Some(Payload::SecurityAssociation(sa)) = scripted
                .payloads
                .iter_mut()
                .find(|p| p.as_payload_type() == PayloadType::SecurityAssociation)
            {
                sa.proposals[0].transforms = sa.proposals[0]
                    .transforms
                    .iter()
                    .map(|t| match t.transform_type {
                        TransformType::DiffieHellmanGroup => Transform::dh_group(DhGroup::Ecp521),
                        _ => t.clone(),
                    })
                    .collect();
            }
            vec![scripted]
        });

        service.do_sa_init(LOCAL, GATEWAY).await.unwrap();
        assert!(service.session.is_keyed());
        assert_eq!(service.session.dh_group(), GroupType::Oakley2);

        // and a proposal with no D-H transform at all
        let (mut service, _script) = new_service(|spi| {
            let mut scripted = sa_init_response(spi, DhGroup::Modp1024, false);
            if let Some(Payload::SecurityAssociation(sa)) = scripted
                .payloads
                .iter_mut()
                .find(|p| p.as_payload_type() == PayloadType::SecurityAssociation)
            {
                sa.proposals[0]
                    .transforms
                    .retain(|t| t.transform_type != TransformType::DiffieHellmanGroup);
            }
            vec![scripted]
        });

        service.do_sa_init(LOCAL, GATEWAY).await.unwrap();
        assert!(service.session.is_keyed());
        assert_eq!(service.session.session_keys().sk_ei.len(), 32);
    }

    /// A public key of the wrong width would otherwise surface much later, as
    /// an opaque integrity failure on the first SK-framed message.
    #[tokio::test]
    async fn test_sa_init_rejects_a_short_public_key() {
        let (mut service, _script) = new_service(|spi| {
            let mut scripted = sa_init_response(spi, DhGroup::Modp1024, false);
            if let Some(Payload::KeyExchange(ke)) = scripted
                .payloads
                .iter_mut()
                .find(|p| p.as_payload_type() == PayloadType::KeyExchange)
            {
                ke.data = ke.data.slice(..64);
            }
            vec![scripted]
        });

        let err = service.do_sa_init(LOCAL, GATEWAY).await.unwrap_err().to_string();
        assert!(err.contains("64 bytes"), "{err}");
        assert!(!service.session.is_keyed());
    }

    /// A KE payload for a group we hold no private key for is still fatal: the
    /// responder has to ask for another group with INVALID_KE_PAYLOAD first.
    #[tokio::test]
    async fn test_sa_init_rejects_a_ke_payload_for_another_group() {
        let (mut service, _script) = new_service(|spi| {
            let mut scripted = sa_init_response(spi, DhGroup::Modp1024, false);
            if let Some(Payload::KeyExchange(ke)) = scripted
                .payloads
                .iter_mut()
                .find(|p| p.as_payload_type() == PayloadType::KeyExchange)
            {
                ke.dh_group = DhGroup::Modp2048;
            }
            vec![scripted]
        });

        let err = service.do_sa_init(LOCAL, GATEWAY).await.unwrap_err().to_string();
        assert!(err.contains("KE payload is for"), "{err}");
    }
    const OFFICE_IP: Ipv4Addr = Ipv4Addr::new(172, 16, 10, 2);
    const ESP_SPI_I: u32 = 0x74940b66;
    const ESP_SPI_R: u32 = 0x6d7636f8;
    const EAP_ID: u8 = 80;

    /// A service that has completed IKE_SA_INIT.
    ///
    /// The scripted transport carries messages rather than octets, so the
    /// IKE_SA_INIT octets the AUTH payload signs have to be put in by hand —
    /// the codec records them on the real path, which
    /// `session::tests::test_sa_init_octets_are_recorded` covers.
    async fn authenticated_service() -> (Ikev2Service, Script) {
        let (mut service, script) = new_service(|spi| vec![sa_init_response(spi, DhGroup::Modp1024, false)]);

        service.do_sa_init(LOCAL, GATEWAY).await.unwrap();

        service
            .session
            .set_sa_init_octets(false, Bytes::from_static(b"IKE_SA_INIT request octets"));
        service
            .session
            .set_sa_init_octets(true, Bytes::from_static(b"IKE_SA_INIT response octets"));

        (service, script)
    }

    fn auth_request() -> Ikev2AuthRequest {
        Ikev2AuthRequest {
            username: "testuser".to_owned(),
            auth_blob: "(\n\t:clientType (TRAC)\n)".to_owned(),
            address: None,
            machine_name: None,
        }
    }

    fn machine_auth_request() -> Ikev2AuthRequest {
        Ikev2AuthRequest {
            machine_name: Some("WORKSTATION".to_owned()),
            ..auth_request()
        }
    }

    fn responder_id() -> IdentificationPayload {
        IdentificationPayload {
            id_type: IdentificationType::Ipv4Address,
            data: Bytes::copy_from_slice(&GATEWAY.ip().octets()),
        }
    }

    /// The responder's AUTH, computed from first principles rather than
    /// through the session, so the test does not vouch for itself.
    ///
    /// The captured gateway signs its first AUTH with RSA and MICs the last
    /// one; the loop treats them alike, and
    /// `session::tests::test_verify_auth_r_accepts_an_rsa_signature` covers the
    /// signature path.
    fn responder_auth(session: &Ikev2Session) -> AuthenticationPayload {
        let crypto = session.crypto();
        let keys = session.session_keys();
        let id_r = responder_id().to_bytes();

        let octets = [
            session.sa_init_response().as_ref(),
            session.initiator().nonce.as_ref(),
            crypto.prf(&keys.sk_pr, [id_r.as_ref()]).unwrap().as_ref(),
        ]
        .concat();

        let key = crypto.prf(&keys.sk_pr, [b"Key Pad for IKEv2".as_slice()]).unwrap();

        AuthenticationPayload {
            auth_method: crate::ikev2::model::AuthMethod::SharedKeyMic,
            data: crypto.prf(&key, [octets.as_slice()]).unwrap(),
        }
    }

    fn ike_auth_response(service: &Ikev2Service, message_id: u32, payloads: Vec<Payload>) -> Ikev2Message {
        Ikev2Message {
            initiator_spi: service.session.initiator_spi(),
            responder_spi: service.session.responder_spi(),
            version: IKEV2_VERSION,
            exchange_type: ExchangeType::IkeAuth,
            flags: Flags::RESPONSE,
            message_id,
            payloads,
        }
    }

    fn eap(code: EapCode, eap_type: Option<EapType>, data: &'static [u8]) -> Payload {
        Payload::Eap(BasicPayload::new(
            EapMessage {
                code,
                identifier: EAP_ID,
                eap_type,
                data: Bytes::from_static(data),
            }
            .to_bytes(),
        ))
    }

    /// The final response: AUTH, the child SA, the narrowed selectors and the
    /// office-mode reply, laid out as the captured gateway sends them.
    fn final_payloads(service: &Ikev2Service) -> Vec<Payload> {
        vec![
            Payload::Authentication(responder_auth(&service.session)),
            Payload::Configuration(ConfigurationPayload {
                cfg_type: ConfigurationType::Reply,
                attributes: vec![
                    ConfigurationAttribute {
                        attribute_type: ConfigurationAttributeType::InternalIp4Address,
                        data: Bytes::copy_from_slice(&OFFICE_IP.octets()),
                    },
                    ConfigurationAttribute {
                        attribute_type: ConfigurationAttributeType::InternalIp4Netmask,
                        data: Bytes::from_static(&[255, 255, 255, 0]),
                    },
                    ConfigurationAttribute {
                        attribute_type: ConfigurationAttributeType::InternalIp4Dns,
                        data: Bytes::from_static(&[10, 0, 0, 1]),
                    },
                    ConfigurationAttribute {
                        attribute_type: ConfigurationAttributeType::InternalIp4Dns,
                        data: Bytes::from_static(&[10, 0, 0, 2]),
                    },
                    ConfigurationAttribute {
                        attribute_type: ConfigurationAttributeType::CccDomainName,
                        data: Bytes::from_static(b"example.com, vpn.example.com"),
                    },
                    // 32 ASCII hex characters, as the gateway sends it
                    ConfigurationAttribute {
                        attribute_type: ConfigurationAttributeType::CccSessionCookie,
                        data: Bytes::from_static(b"f42285023f780c51e8280c78b2fe34a6"),
                    },
                ],
            }),
            Payload::SecurityAssociation(SecurityAssociationPayload {
                proposals: vec![Proposal {
                    proposal_num: 1,
                    protocol_id: ProtocolId::Esp,
                    spi: Bytes::copy_from_slice(&ESP_SPI_R.to_be_bytes()),
                    transforms: vec![
                        Transform::encryption(EncryptionAlgorithm::AesCbc, Some(32)),
                        Transform::integrity(IntegrityAlgorithm::HmacSha256_128),
                        Transform::esn(ExtendedSequenceNumbers::None),
                    ],
                }],
            }),
            Payload::TrafficSelectorInitiator(TrafficSelectorPayload {
                selectors: vec![TrafficSelector {
                    start_address: Bytes::copy_from_slice(&OFFICE_IP.octets()),
                    end_address: Bytes::copy_from_slice(&OFFICE_IP.octets()),
                    ..TrafficSelector::any_ipv4()
                }],
            }),
            // the gateway narrows to a set, not a single range
            Payload::TrafficSelectorResponder(TrafficSelectorPayload {
                selectors: vec![
                    TrafficSelector {
                        start_address: Bytes::from_static(&[172, 24, 1, 0]),
                        end_address: Bytes::from_static(&[172, 24, 1, 255]),
                        ..TrafficSelector::any_ipv4()
                    },
                    TrafficSelector {
                        start_address: Bytes::from_static(&[192, 168, 100, 5]),
                        end_address: Bytes::from_static(&[192, 168, 100, 5]),
                        ..TrafficSelector::any_ipv4()
                    },
                ],
            }),
            Payload::Notify(NotifyPayload::new(
                NotifyType::AuthLifetime,
                Bytes::copy_from_slice(&28800u32.to_be_bytes()),
            )),
        ]
    }

    /// The whole IKE_AUTH run, in the shape of the phase-1 capture: one
    /// exchange without AUTH, one EAP-GTC round, then AUTH both ways.
    #[tokio::test]
    async fn test_ike_auth_runs_the_eap_loop() {
        let (mut service, script) = authenticated_service().await;

        script.push(ike_auth_response(
            &service,
            1,
            vec![
                Payload::IdentificationResponder(responder_id()),
                Payload::Authentication(responder_auth(&service.session)),
                eap(
                    EapCode::Request,
                    Some(EapType::GenericTokenCard),
                    b"Enter your password",
                ),
            ],
        ));
        script.push(ike_auth_response(&service, 2, vec![eap(EapCode::Success, None, b"")]));
        script.push(ike_auth_response(&service, 3, final_payloads(&service)));

        let step = service.do_auth(auth_request()).await.unwrap();

        let Ikev2Step::NeedsChallenge(prompt) = step else {
            panic!("expected a challenge, got {step:?}");
        };
        assert_eq!(prompt.eap_type(), Some(EapType::GenericTokenCard));
        assert_eq!(prompt.data(), &Bytes::from_static(b"Enter your password"));

        let step = service.step(Bytes::from_static(b"s3cret!!")).await.unwrap();

        let Ikev2Step::Done(result) = step else {
            panic!("expected the exchange to finish, got {step:?}");
        };

        // office mode carries the same data as the IKEv1 path, from CFG_REPLY
        assert_eq!(result.office_mode.ip_address, OFFICE_IP);
        assert_eq!(result.office_mode.netmask, Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(
            result.office_mode.dns,
            vec![Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)]
        );
        assert_eq!(result.office_mode.domains, vec!["example.com", "vpn.example.com"]);
        assert_eq!(result.office_mode.ccc_session, "f42285023f780c51e8280c78b2fe34a6");
        assert_eq!(result.office_mode.username, "testuser");

        // the gateway narrows the selectors and we keep every one
        assert_eq!(result.ts_i.len(), 1);
        assert_eq!(result.ts_r.len(), 2);

        assert_eq!(service.session.lifetime(), Duration::from_secs(28800));

        // and the child SA is keyed, addressed to the gateway's SPI outbound
        let (esp_in, esp_out) = (service.session.esp_in(), service.session.esp_out());
        assert_eq!(esp_out.spi, ESP_SPI_R);
        assert_eq!(esp_in.sk_e.len(), 32);
        assert_eq!(esp_in.sk_a.len(), 32);
        assert_ne!(esp_in.sk_e, esp_out.sk_e);
        assert_eq!(esp_in.auth.unwrap().icv_len, 16);

        let requests = script.requests();
        assert_eq!(requests.len(), 4, "IKE_SA_INIT plus three IKE_AUTH exchanges");

        // Message IDs run consecutively from 0, with the initiator counting
        assert_eq!(
            requests.iter().map(|r| r.message_id).collect::<Vec<_>>(),
            vec![0, 1, 2, 3]
        );
        assert_eq!(service.message_id(), 4);

        let first = &requests[1];
        assert_eq!(first.exchange_type, ExchangeType::IkeAuth);
        assert_eq!(first.responder_spi, service.session.responder_spi());

        // no AUTH payload: that is what asks for EAP
        assert!(sent_payload(first, PayloadType::Authentication).is_none());

        let Some(Payload::IdentificationInitiator(id_i)) = sent_payload(first, PayloadType::IdentificationInitiator)
        else {
            panic!("no IDi")
        };
        assert_eq!(id_i.id_type, IdentificationType::KeyId);
        assert_eq!(id_i.data, Bytes::from_static(b"testuser\0"));

        let Some(Payload::Configuration(config)) = sent_payload(first, PayloadType::Configuration) else {
            panic!("no CP payload")
        };
        assert_eq!(config.cfg_type, ConfigurationType::Request);
        assert!(
            config
                .attributes
                .iter()
                .any(|a| a.attribute_type == ConfigurationAttributeType::CccSessionCookie)
        );
        assert!(config.attributes.iter().all(|a| a.data.is_empty()));

        let Some(Payload::SecurityAssociation(sa)) = sent_payload(first, PayloadType::SecurityAssociation) else {
            panic!("no SAi2")
        };
        assert_eq!(sa.proposals[0].protocol_id, ProtocolId::Esp);
        assert_eq!(sa.proposals[0].spi.len(), 4, "an ESP SPI, not the IKE SA's");
        assert!(sa.proposals[0].find(TransformType::DiffieHellmanGroup).is_none());

        let notifies = first.notifies().map(|n| n.notify_type).collect::<Vec<_>>();
        assert!(notifies.contains(&NotifyType::InitialContact));
        assert!(notifies.contains(&NotifyType::MultipleAuthSupported));
        assert!(notifies.contains(&NotifyType::CccAuth));

        let blob = first.find_notify(NotifyType::CccAuth).unwrap();
        assert!(blob.data.starts_with(b"(\n\t:clientType"));

        // the EAP response echoes the request's identifier and method
        let Some(Payload::Eap(answer)) = sent_payload(&requests[2], PayloadType::ExtensibleAuthentication) else {
            panic!("no EAP response")
        };
        let answer = EapMessage::parse(&answer.data).unwrap();
        assert_eq!(answer.code, EapCode::Response);
        assert_eq!(answer.identifier, EAP_ID);
        assert_eq!(answer.eap_type, Some(EapType::GenericTokenCard));
        assert_eq!(answer.data, Bytes::from_static(b"s3cret!!"));

        // our AUTH goes last, keyed by SK_pi
        let Some(Payload::Authentication(auth)) = sent_payload(&requests[3], PayloadType::Authentication) else {
            panic!("no AUTH")
        };
        assert_eq!(auth.auth_method, crate::ikev2::model::AuthMethod::SharedKeyMic);
        assert_eq!(requests[3].payloads.len(), 1);

        let keys = service.session.session_keys();
        let crypto = service.session.crypto();
        let octets = [
            service.session.sa_init_request().as_ref(),
            service.session.responder().nonce.as_ref(),
            crypto.prf(&keys.sk_pi, [id_i.to_bytes().as_ref()]).unwrap().as_ref(),
        ]
        .concat();
        let key = crypto.prf(&keys.sk_pi, [b"Key Pad for IKEv2".as_slice()]).unwrap();
        assert_eq!(auth.data, crypto.prf(&key, [octets.as_slice()]).unwrap());
    }

    /// Several challenges in a row, which is what an MFA login looks like.
    #[tokio::test]
    async fn test_ike_auth_carries_more_than_one_challenge() {
        let (mut service, script) = authenticated_service().await;

        script.push(ike_auth_response(
            &service,
            1,
            vec![
                Payload::IdentificationResponder(responder_id()),
                Payload::Authentication(responder_auth(&service.session)),
                eap(EapCode::Request, Some(EapType::GenericTokenCard), b"Password:"),
            ],
        ));
        script.push(ike_auth_response(
            &service,
            2,
            vec![eap(
                EapCode::Request,
                Some(EapType::GenericTokenCard),
                b"One-time code:",
            )],
        ));
        script.push(ike_auth_response(&service, 3, vec![eap(EapCode::Success, None, b"")]));
        script.push(ike_auth_response(&service, 4, final_payloads(&service)));

        let step = service.do_auth(auth_request()).await.unwrap();
        assert!(matches!(step, Ikev2Step::NeedsChallenge(_)));

        let step = service.step(Bytes::from_static(b"password")).await.unwrap();
        let Ikev2Step::NeedsChallenge(prompt) = step else {
            panic!("expected a second challenge, got {step:?}");
        };
        assert_eq!(prompt.data(), &Bytes::from_static(b"One-time code:"));

        let step = service.step(Bytes::from_static(b"123456")).await.unwrap();
        assert!(matches!(step, Ikev2Step::Done(_)));

        assert_eq!(script.requests().len(), 5);
        assert_eq!(service.message_id(), 5);
    }

    /// RFC 7296 §2.4: the responder may open an INFORMATIONAL of its own once
    /// the initial exchanges are done — the captured gateway does, to evict an
    /// earlier session. It must not be mistaken for our own response.
    #[tokio::test]
    async fn test_ike_auth_acknowledges_a_responder_informational() {
        let (mut service, script) = authenticated_service().await;

        script.push(Ikev2Message {
            initiator_spi: service.session.initiator_spi(),
            responder_spi: service.session.responder_spi(),
            version: IKEV2_VERSION,
            exchange_type: ExchangeType::Informational,
            flags: Flags::empty(),
            message_id: 0,
            payloads: vec![Payload::Notify(NotifyPayload::new(
                NotifyType::Other(40007),
                Bytes::default(),
            ))],
        });
        script.push(ike_auth_response(
            &service,
            1,
            vec![
                Payload::IdentificationResponder(responder_id()),
                Payload::Authentication(responder_auth(&service.session)),
                eap(EapCode::Request, Some(EapType::GenericTokenCard), b"Password:"),
            ],
        ));

        let step = service.do_auth(auth_request()).await.unwrap();
        assert!(matches!(step, Ikev2Step::NeedsChallenge(_)));

        let requests = script.requests();
        assert_eq!(requests.len(), 3);

        let acknowledgement = &requests[2];
        assert_eq!(acknowledgement.exchange_type, ExchangeType::Informational);
        assert!(acknowledgement.flags.contains(Flags::RESPONSE));
        assert_eq!(acknowledgement.message_id, 0, "the responder's own counter");
        assert!(acknowledgement.payloads.is_empty());

        // and our own exchange carried on undisturbed
        assert_eq!(service.message_id(), 2);
    }

    #[tokio::test]
    async fn test_ike_auth_reports_eap_failure() {
        let (mut service, script) = authenticated_service().await;

        script.push(ike_auth_response(
            &service,
            1,
            vec![
                Payload::IdentificationResponder(responder_id()),
                Payload::Authentication(responder_auth(&service.session)),
                eap(EapCode::Request, Some(EapType::GenericTokenCard), b"Password:"),
            ],
        ));
        script.push(ike_auth_response(&service, 2, vec![eap(EapCode::Failure, None, b"")]));

        service.do_auth(auth_request()).await.unwrap();

        let err = service
            .step(Bytes::from_static(b"wrong"))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("EAP authentication failed"), "{err}");
    }

    #[tokio::test]
    async fn test_ike_auth_rejects_a_responder_that_does_not_authenticate() {
        let (mut service, script) = authenticated_service().await;

        let mut auth = responder_auth(&service.session);
        auth.data = Bytes::from(vec![0; auth.data.len()]);

        script.push(ike_auth_response(
            &service,
            1,
            vec![
                Payload::IdentificationResponder(responder_id()),
                Payload::Authentication(auth),
                eap(EapCode::Request, Some(EapType::GenericTokenCard), b"Password:"),
            ],
        ));

        let err = service.do_auth(auth_request()).await.unwrap_err().to_string();
        assert!(err.contains("AUTH does not match"), "{err}");
    }

    #[tokio::test]
    async fn test_ike_auth_reports_a_rejection() {
        let (mut service, script) = authenticated_service().await;

        script.push(ike_auth_response(
            &service,
            1,
            vec![Payload::Notify(NotifyPayload::new(
                NotifyType::AuthenticationFailed,
                Bytes::default(),
            ))],
        ));

        let err = service.do_auth(auth_request()).await.unwrap_err().to_string();
        assert!(err.contains("AuthenticationFailed"), "{err}");
    }

    /// A throwaway machine identity: an RSA key, a self-signed certificate for
    /// it, and the PKCS12 the session loads it from.
    fn machine_identity() -> (Identity, PKey<Private>, Bytes) {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();

        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "workstation.example.com").unwrap();
        let name = name.build();

        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&key).unwrap();
        builder.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
        builder.set_not_after(&Asn1Time::days_from_now(1).unwrap()).unwrap();
        builder.sign(&key, MessageDigest::sha256()).unwrap();
        let certificate = builder.build();

        let pkcs12 = Pkcs12::builder()
            .name("machine")
            .pkey(&key)
            .cert(&certificate)
            .build2("secret")
            .unwrap()
            .to_der()
            .unwrap();

        let identity = Identity::Pkcs12 {
            data: pkcs12,
            password: SecretString::from("secret"),
            hybrid_auth: true,
        };

        (identity, key, Bytes::from(certificate.to_der().unwrap()))
    }

    /// A service carrying a machine certificate, with IKE_SA_INIT behind it.
    async fn machine_auth_service() -> (Ikev2Service, Script, PKey<Private>, Bytes) {
        let (identity, key, certificate) = machine_identity();

        let (mut service, script) =
            new_service_for(identity, |spi| vec![sa_init_response(spi, DhGroup::Modp1024, false)]);

        service.do_sa_init(LOCAL, GATEWAY).await.unwrap();

        service
            .session
            .set_sa_init_octets(false, Bytes::from_static(b"IKE_SA_INIT request octets"));
        service
            .session
            .set_sa_init_octets(true, Bytes::from_static(b"IKE_SA_INIT response octets"));

        (service, script, key, certificate)
    }

    /// Machine authentication is RFC 4739's two-round exchange, as the gateway
    /// trace shows: a complete IKE_AUTH for the machine, ended by
    /// `N(ANOTHER_AUTH_FOLLOWS)`, then a bare `IDi` for the user, then EAP.
    #[tokio::test]
    async fn test_machine_certificate_authenticates_in_a_round_of_its_own() {
        let (mut service, script, key, certificate) = machine_auth_service().await;

        // the machine round: the gateway authenticates and asks nothing
        script.push(ike_auth_response(
            &service,
            1,
            vec![
                Payload::IdentificationResponder(responder_id()),
                Payload::Authentication(responder_auth(&service.session)),
            ],
        ));
        // the user round, where EAP begins
        script.push(ike_auth_response(
            &service,
            2,
            vec![eap(EapCode::Request, Some(EapType::GenericTokenCard), b"Password:")],
        ));
        script.push(ike_auth_response(&service, 3, vec![eap(EapCode::Success, None, b"")]));
        script.push(ike_auth_response(&service, 4, final_payloads(&service)));

        let step = service.do_auth(machine_auth_request()).await.unwrap();
        let Ikev2Step::NeedsChallenge(prompt) = step else {
            panic!("expected a challenge, got {step:?}");
        };
        assert_eq!(prompt.data(), &Bytes::from_static(b"Password:"));

        let step = service.step(Bytes::from_static(b"s3cret!!")).await.unwrap();
        assert!(matches!(step, Ikev2Step::Done(_)), "{step:?}");

        let requests = script.requests();
        assert_eq!(
            requests.len(),
            5,
            "IKE_SA_INIT, the machine round, then the user's three"
        );

        let machine = &requests[1];

        // the first round speaks for the machine: the name the caller gave,
        // with the Windows machine-account marker and no NUL terminator
        let Some(Payload::IdentificationInitiator(machine_id)) =
            sent_payload(machine, PayloadType::IdentificationInitiator)
        else {
            panic!("no IDi")
        };
        assert_eq!(machine_id.id_type, IdentificationType::KeyId);
        assert_eq!(machine_id.data, Bytes::from_static(b"WORKSTATION$"));

        // the entity certificate alone, in the standard slot
        let certs = machine
            .payloads
            .iter()
            .filter(|p| p.as_payload_type() == PayloadType::Certificate)
            .count();
        assert_eq!(certs, 1);

        let Some(Payload::Certificate(cert)) = sent_payload(machine, PayloadType::Certificate) else {
            panic!("no CERT")
        };
        assert_eq!(cert.encoding, CertificateEncoding::X509CertificateSignature);
        assert_eq!(cert.data, certificate);

        let Some(Payload::CertificateRequest(cert_req)) = sent_payload(machine, PayloadType::CertificateRequest) else {
            panic!("no CERTREQ")
        };
        assert!(cert_req.data.is_empty());

        // AUTH signs the machine's identity, which only an outside verifier
        // can show
        let Some(Payload::Authentication(auth)) = sent_payload(machine, PayloadType::Authentication) else {
            panic!("no AUTH")
        };
        assert_eq!(auth.auth_method, AuthMethod::RsaDigitalSignature);

        let octets = service.session.signed_octets_i(&machine_id.to_bytes()).unwrap();
        let mut verifier = Verifier::new(MessageDigest::sha1(), &key).unwrap();
        verifier.update(&octets).unwrap();
        assert!(verifier.verify(&auth.data).unwrap());

        // everything the password path sends is in this round, not the user's
        assert!(sent_payload(machine, PayloadType::SecurityAssociation).is_some());
        assert!(sent_payload(machine, PayloadType::Configuration).is_some());
        assert!(sent_payload(machine, PayloadType::TrafficSelectorInitiator).is_some());

        let notifies = machine.notifies().map(|n| n.notify_type).collect::<Vec<_>>();
        assert!(notifies.contains(&NotifyType::CccAuth));
        assert!(notifies.contains(&NotifyType::MultipleAuthSupported));
        assert!(notifies.contains(&NotifyType::CpRaUsingMachineAuth));
        assert_eq!(
            notifies.last(),
            Some(&NotifyType::AnotherAuthFollows),
            "the machine round ends by announcing the user's"
        );

        // the user's round carries the identity and nothing else: an AUTH here
        // would claim they are already authenticated and suppress EAP
        let user = &requests[2];
        assert_eq!(user.payloads.len(), 1);

        let Some(Payload::IdentificationInitiator(user_id)) = sent_payload(user, PayloadType::IdentificationInitiator)
        else {
            panic!("no IDi")
        };
        assert_eq!(user_id.id_type, IdentificationType::KeyId);
        assert_eq!(user_id.data, Bytes::from_static(b"testuser\0"));

        // and the final MIC signs the user's identity, not the machine's
        let Some(Payload::Authentication(auth)) = sent_payload(&requests[4], PayloadType::Authentication) else {
            panic!("no final AUTH")
        };
        assert_eq!(auth.auth_method, AuthMethod::SharedKeyMic);
        assert_eq!(auth.data, service.session.auth_i(&user_id.to_bytes()).unwrap().data);
    }

    #[tokio::test]
    async fn test_machine_certificate_still_needs_the_user_to_authenticate() {
        let (mut service, script, _key, _certificate) = machine_auth_service().await;

        script.push(ike_auth_response(
            &service,
            1,
            vec![
                Payload::IdentificationResponder(responder_id()),
                Payload::Authentication(responder_auth(&service.session)),
            ],
        ));

        // the user's round answered as if the login were finished, with no EAP
        script.push(ike_auth_response(&service, 2, final_payloads(&service)));

        let err = service.do_auth(machine_auth_request()).await.unwrap_err().to_string();
        assert!(err.contains("user has not authenticated"), "{err}");
    }

    /// A certificate without `hybrid_auth` is the *user's*, and replaces the
    /// credentials: IDi is its subject, AUTH is signed by it, and the gateway
    /// has nothing to ask — one IKE_AUTH exchange and the SA is up.
    #[tokio::test]
    async fn test_user_certificate_replaces_the_eap_loop() {
        let (identity, key, certificate) = machine_identity();
        let Identity::Pkcs12 { data, password, .. } = identity else {
            unreachable!()
        };

        let (mut service, script) = new_service_for(
            Identity::Pkcs12 {
                data,
                password,
                hybrid_auth: false,
            },
            |spi| vec![sa_init_response(spi, DhGroup::Modp1024, false)],
        );

        service.do_sa_init(LOCAL, GATEWAY).await.unwrap();
        service
            .session
            .set_sa_init_octets(false, Bytes::from_static(b"IKE_SA_INIT request octets"));
        service
            .session
            .set_sa_init_octets(true, Bytes::from_static(b"IKE_SA_INIT response octets"));

        let mut payloads = vec![Payload::IdentificationResponder(responder_id())];
        payloads.extend(final_payloads(&service));

        script.push(ike_auth_response(&service, 1, payloads));

        let step = service.do_auth(auth_request()).await.unwrap();
        let Ikev2Step::Done(result) = step else {
            panic!("expected the exchange to finish, got {step:?}");
        };
        assert_eq!(result.office_mode.ip_address, OFFICE_IP);
        assert_eq!(service.session.esp_out().spi, ESP_SPI_R);

        let requests = script.requests();
        assert_eq!(requests.len(), 2, "IKE_SA_INIT and one IKE_AUTH");

        let first = &requests[1];

        // the certificate is the identity here, unlike the machine case
        let Some(Payload::IdentificationInitiator(id_i)) = sent_payload(first, PayloadType::IdentificationInitiator)
        else {
            panic!("no IDi")
        };
        assert_eq!(id_i.id_type, IdentificationType::DerAsn1Dn);
        assert_eq!(
            id_i.data,
            X509::from_der(&certificate).unwrap().subject_name().to_der().unwrap()
        );

        let Some(Payload::Authentication(auth)) = sent_payload(first, PayloadType::Authentication) else {
            panic!("no AUTH")
        };
        assert_eq!(auth.auth_method, AuthMethod::RsaDigitalSignature);

        let octets = service.session.signed_octets_i(&id_i.to_bytes()).unwrap();
        let mut verifier = Verifier::new(MessageDigest::sha1(), &key).unwrap();
        verifier.update(&octets).unwrap();
        assert!(verifier.verify(&auth.data).unwrap());
    }

    /// Without a certificate the request is unchanged, and a gateway that
    /// still skips EAP is an error rather than a silent success.
    #[tokio::test]
    async fn test_a_password_login_without_eap_is_rejected() {
        let (mut service, script) = authenticated_service().await;

        script.push(ike_auth_response(
            &service,
            1,
            vec![
                Payload::IdentificationResponder(responder_id()),
                Payload::Authentication(responder_auth(&service.session)),
            ],
        ));

        let err = service.do_auth(auth_request()).await.unwrap_err().to_string();
        assert!(err.contains("user has not authenticated"), "{err}");
    }

    #[tokio::test]
    async fn test_auth_needs_the_sa_to_be_keyed_and_a_pending_challenge() {
        let (mut service, _script) = new_service(|_| vec![]);

        let err = service.do_auth(auth_request()).await.unwrap_err().to_string();
        assert!(err.contains("IKE_AUTH before IKE_SA_INIT"), "{err}");

        let (mut service, _script) = authenticated_service().await;
        let err = service
            .step(Bytes::from_static(b"answer"))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("No outstanding challenge"), "{err}");
    }
    /// Drives a full password login so the child SA is keyed and the service is
    /// sitting where a rekey would find it.
    async fn service_with_child_sa() -> (Ikev2Service, Script) {
        let (mut service, script) = authenticated_service().await;

        script.push(ike_auth_response(
            &service,
            1,
            vec![
                Payload::IdentificationResponder(responder_id()),
                Payload::Authentication(responder_auth(&service.session)),
                eap(
                    EapCode::Request,
                    Some(EapType::GenericTokenCard),
                    b"Enter your password",
                ),
            ],
        ));
        script.push(ike_auth_response(&service, 2, vec![eap(EapCode::Success, None, b"")]));
        script.push(ike_auth_response(&service, 3, final_payloads(&service)));

        service.do_auth(auth_request()).await.unwrap();
        service.step(Bytes::from_static(b"secret")).await.unwrap();

        (service, script)
    }

    fn child_sa_response(
        service: &Ikev2Service,
        exchange_type: ExchangeType,
        message_id: u32,
        payloads: Vec<Payload>,
    ) -> Ikev2Message {
        Ikev2Message {
            initiator_spi: service.session.initiator_spi(),
            responder_spi: service.session.responder_spi(),
            version: IKEV2_VERSION,
            exchange_type,
            flags: Flags::RESPONSE,
            message_id,
            payloads,
        }
    }

    fn esp_proposal(spi: u32) -> Payload {
        Payload::SecurityAssociation(SecurityAssociationPayload {
            proposals: vec![Proposal {
                proposal_num: 1,
                protocol_id: ProtocolId::Esp,
                spi: Bytes::copy_from_slice(&spi.to_be_bytes()),
                transforms: vec![
                    Transform::encryption(EncryptionAlgorithm::AesCbc, Some(32)),
                    Transform::integrity(IntegrityAlgorithm::HmacSha256_128),
                    Transform::esn(ExtendedSequenceNumbers::None),
                ],
            }],
        })
    }

    fn selectors() -> Vec<Payload> {
        vec![
            Payload::TrafficSelectorInitiator(TrafficSelectorPayload {
                selectors: vec![TrafficSelector::any_ipv4()],
            }),
            Payload::TrafficSelectorResponder(TrafficSelectorPayload {
                selectors: vec![TrafficSelector::any_ipv4()],
            }),
        ]
    }

    /// Rekeying replaces both directions' keys and SPIs, names the SA it is
    /// replacing, and deletes it afterwards.
    #[tokio::test]
    async fn test_rekey_child_sa_replaces_the_keys_and_deletes_the_old_sa() {
        let (mut service, script) = service_with_child_sa().await;

        let before = (service.session.esp_in(), service.session.esp_out());

        let peer_spi: u32 = 0x1234_5678;
        let mut payloads = vec![
            esp_proposal(peer_spi),
            Payload::Nonce(BasicPayload::new(Bytes::from_static(&[0x5a; 32]))),
        ];
        payloads.extend(selectors());

        script.push(child_sa_response(&service, ExchangeType::CreateChildSa, 4, payloads));
        // the DELETE that follows is answered with an empty INFORMATIONAL
        script.push(child_sa_response(&service, ExchangeType::Informational, 5, Vec::new()));

        service.rekey_child_sa().await.unwrap();

        let after = (service.session.esp_in(), service.session.esp_out());

        assert_ne!(before.0.sk_e, after.0.sk_e, "inbound key");
        assert_ne!(before.1.sk_e, after.1.sk_e, "outbound key");
        assert_ne!(before.0.spi, after.0.spi, "inbound SPI");
        assert_eq!(after.1.spi, peer_spi, "we send to the SPI the peer chose");
        // the two directions must not share material
        assert_ne!(after.0.sk_e, after.1.sk_e);

        let requests = script.requests();
        let rekey = &requests[requests.len() - 2];
        assert_eq!(rekey.exchange_type, ExchangeType::CreateChildSa);

        let notify = rekey.find_notify(NotifyType::RekeySa).expect("no REKEY_SA");
        assert_eq!(notify.protocol_id, ProtocolId::Esp);
        assert_eq!(notify.spi, Bytes::copy_from_slice(&before.0.spi.to_be_bytes()));

        let delete = requests.last().unwrap();
        assert_eq!(delete.exchange_type, ExchangeType::Informational);
        let Some(Payload::Delete(delete)) = delete.payloads.first() else {
            panic!("no DELETE")
        };
        assert_eq!(delete.protocol_id, ProtocolId::Esp);
        assert_eq!(delete.spis, vec![Bytes::copy_from_slice(&before.0.spi.to_be_bytes())]);
    }

    /// The gateway rekeys on its own schedule, and an unanswered request ends
    /// with it deleting the SA — so the responder half has to work too.
    #[tokio::test]
    async fn test_peer_initiated_rekey_is_answered_and_keyed() {
        let (mut service, script) = service_with_child_sa().await;

        let before = (service.session.esp_in(), service.session.esp_out());

        let peer_spi: u32 = 0x0bad_c0de;
        let mut payloads = vec![
            Payload::Notify(NotifyPayload {
                protocol_id: ProtocolId::Esp,
                spi: Bytes::copy_from_slice(&before.1.spi.to_be_bytes()),
                notify_type: NotifyType::RekeySa,
                data: Bytes::default(),
            }),
            esp_proposal(peer_spi),
            Payload::Nonce(BasicPayload::new(Bytes::from_static(&[0xa5; 32]))),
        ];
        payloads.extend(selectors());

        let request = Ikev2Message {
            initiator_spi: service.session.initiator_spi(),
            responder_spi: service.session.responder_spi(),
            version: IKEV2_VERSION,
            exchange_type: ExchangeType::CreateChildSa,
            flags: Flags::INITIATOR,
            message_id: 0,
            payloads,
        };

        let outcome = service.handle_request(&request).await.unwrap();
        assert_eq!(outcome, PeerRequest::ChildSaRekeyed);

        let after = (service.session.esp_in(), service.session.esp_out());
        assert_ne!(before.0.sk_e, after.0.sk_e);
        assert_ne!(after.0.sk_e, after.1.sk_e);
        assert_eq!(after.1.spi, peer_spi, "we send to the SPI the peer chose");

        let response = script.requests().last().unwrap().clone();
        assert_eq!(response.exchange_type, ExchangeType::CreateChildSa);
        assert!(response.is_response());
        assert_eq!(response.message_id, 0, "the peer's window, not ours");

        // the answer names our new inbound SPI
        let Some(Payload::SecurityAssociation(sa)) = response
            .payloads
            .iter()
            .find(|p| matches!(p, Payload::SecurityAssociation(_)))
        else {
            panic!("no SA in the response")
        };
        assert_eq!(sa.proposals[0].spi, Bytes::copy_from_slice(&after.0.spi.to_be_bytes()));
    }

    /// Our own Message ID counter belongs to our exchanges only.
    #[tokio::test]
    async fn test_answering_a_peer_request_leaves_our_message_id_alone() {
        let (mut service, _script) = service_with_child_sa().await;

        let before = service.message_id();

        let request = Ikev2Message {
            initiator_spi: service.session.initiator_spi(),
            responder_spi: service.session.responder_spi(),
            version: IKEV2_VERSION,
            exchange_type: ExchangeType::Informational,
            flags: Flags::INITIATOR,
            message_id: 0,
            payloads: vec![Payload::Delete(DeletePayload {
                protocol_id: ProtocolId::Esp,
                spi_size: 4,
                spis: vec![Bytes::from_static(&[1, 2, 3, 4])],
            })],
        };

        assert_eq!(service.handle_request(&request).await.unwrap(), PeerRequest::Deleted);
        assert_eq!(service.message_id(), before);
    }

    /// The lease is requested in IKE_AUTH and answered in the CFG_REPLY; the
    /// gateway's own trace shows 15 minutes, far short of the IKE SA's 8 hours.
    #[tokio::test]
    async fn test_address_expiry_is_read_from_the_config_reply() {
        let (mut service, script) = authenticated_service().await;

        let mut payloads = final_payloads(&service);
        let Some(Payload::Configuration(config)) = payloads.iter_mut().find(|p| matches!(p, Payload::Configuration(_)))
        else {
            panic!("no CFG_REPLY in the fixture")
        };
        config.attributes.push(ConfigurationAttribute {
            attribute_type: ConfigurationAttributeType::InternalAddressExpiry,
            data: Bytes::copy_from_slice(&900u32.to_be_bytes()),
        });

        script.push(ike_auth_response(
            &service,
            1,
            vec![
                Payload::IdentificationResponder(responder_id()),
                Payload::Authentication(responder_auth(&service.session)),
                eap(EapCode::Request, Some(EapType::GenericTokenCard), b"Password:"),
            ],
        ));
        script.push(ike_auth_response(&service, 2, vec![eap(EapCode::Success, None, b"")]));
        script.push(ike_auth_response(&service, 3, payloads));

        service.do_auth(auth_request()).await.unwrap();
        let Ikev2Step::Done(result) = service.step(Bytes::from_static(b"secret")).await.unwrap() else {
            panic!("expected the login to finish")
        };

        assert_eq!(result.address_expiry, Some(Duration::from_secs(900)));
    }

    /// The gateway trace shows renewal as a CFG_REQUEST naming the address we
    /// already hold, carried in an INFORMATIONAL, answered with the same
    /// address and a fresh expiry — and without the session cookie the login
    /// request asks for.
    #[tokio::test]
    async fn test_office_mode_lease_is_renewed_in_an_informational() {
        let (mut service, script) = service_with_child_sa().await;

        let address = Ipv4Addr::new(172, 16, 10, 5);

        script.push(child_sa_response(
            &service,
            ExchangeType::Informational,
            4,
            vec![Payload::Configuration(ConfigurationPayload {
                cfg_type: ConfigurationType::Reply,
                attributes: vec![
                    ConfigurationAttribute {
                        attribute_type: ConfigurationAttributeType::InternalIp4Address,
                        data: Bytes::copy_from_slice(&address.octets()),
                    },
                    ConfigurationAttribute {
                        attribute_type: ConfigurationAttributeType::InternalIp4Netmask,
                        data: Bytes::from_static(&[255, 255, 255, 0]),
                    },
                    ConfigurationAttribute {
                        attribute_type: ConfigurationAttributeType::InternalAddressExpiry,
                        data: Bytes::copy_from_slice(&900u32.to_be_bytes()),
                    },
                ],
            })],
        ));

        let lease = service.renew_office_mode(address).await.unwrap();

        assert_eq!(lease.address, address);
        assert_eq!(lease.netmask, Some(Ipv4Addr::new(255, 255, 255, 0)));
        assert_eq!(lease.expiry, Some(Duration::from_secs(900)));

        let request = script.requests().last().unwrap().clone();
        assert_eq!(request.exchange_type, ExchangeType::Informational);

        let Some(Payload::Configuration(config)) = request.payloads.first() else {
            panic!("no CFG_REQUEST")
        };
        assert_eq!(config.cfg_type, ConfigurationType::Request);
        assert_eq!(request.payloads.len(), 1, "the renewal carries nothing else");

        // the address is named, the rest asked for, and the session cookie left
        // out — exactly the attribute list the captured client sends
        assert_eq!(
            config.attributes.iter().map(|a| a.attribute_type).collect::<Vec<_>>(),
            vec![
                ConfigurationAttributeType::InternalIp4Address,
                ConfigurationAttributeType::InternalIp4Netmask,
                ConfigurationAttributeType::InternalIp4Dns,
                ConfigurationAttributeType::InternalIp4Nbns,
                ConfigurationAttributeType::InternalAddressExpiry,
                ConfigurationAttributeType::CccDomainName,
            ]
        );
        assert_eq!(config.attributes[0].data, Bytes::copy_from_slice(&address.octets()));
    }

    /// A saved session has to carry the Message ID as well as the keys: a
    /// restored SA continues the peer's window rather than replaying it.
    #[tokio::test]
    async fn test_session_round_trips_through_save_and_load() {
        let (mut service, _script) = service_with_child_sa().await;

        let office_mode = OfficeMode {
            ccc_session: "937f6864e385550cb8c53b4fcb95e551".to_owned(),
            username: "testuser".to_owned(),
            ip_address: Ipv4Addr::new(172, 16, 10, 5),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            dns: vec![Ipv4Addr::new(10, 0, 0, 1)],
            domains: vec!["example.com".to_owned()],
        };

        let message_id = service.message_id();
        assert!(message_id > 0, "the login used some");

        let data = service.save_session(&office_mode).unwrap();

        // a fresh service, as a reconnect would build
        let (mut restored, _script) = new_service(|_| Vec::new());
        let loaded = restored.load_session(&data).unwrap();

        assert_eq!(restored.message_id(), message_id);
        assert_eq!(loaded.ccc_session, office_mode.ccc_session);
        assert_eq!(loaded.username, office_mode.username);
        assert_eq!(loaded.ip_address, office_mode.ip_address);
        assert_eq!(loaded.dns, office_mode.dns);
        assert_eq!(loaded.domains, office_mode.domains);

        // the IKE SA is usable again, but carries no child SA
        assert!(restored.session.is_keyed());
        assert_eq!(restored.session.esp_in().spi, 0);
    }

    #[tokio::test]
    async fn test_a_peer_response_is_not_a_request() {
        let (mut service, _script) = service_with_child_sa().await;

        let response = child_sa_response(&service, ExchangeType::Informational, 0, Vec::new());
        let err = service.handle_request(&response).await.unwrap_err().to_string();
        assert!(err.contains("Not a peer request"), "{err}");
    }
}
