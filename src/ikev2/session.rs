//! IKEv2 session state and key schedule (RFC 7296 §2.14).

use std::{
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, SystemTime},
};

use anyhow::Context;
use bytes::{BufMut, Bytes, BytesMut};
use rand::random;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::{
    certs::ClientCertificate,
    crypto::{CipherType, Crypto, DigestType, GroupType},
    ikev2::{
        codec::{DirectionalKeys, Ikev2Codec, Ikev2Crypt},
        message::Ikev2Message,
        model::{AuthMethod, Ikev2EspProposal, Ikev2SaProposal, IntegrityAlgorithm},
        payload::AuthenticationPayload,
    },
    message::IsakmpMessageCodec,
    model::{EspCryptMaterial, Identity},
    session::{EndpointData, IsakmpSession, OfficeMode, SessionType},
};

// RFC 7296 §2.10 wants at least 16 octets, and at least half the negotiated
// PRF's key size: 32 satisfies every PRF in [`crate::ikev2::model`].
const NONCE_SIZE: usize = 32;

// RFC 7296 §2.15: the shared secret is run through the PRF with this string before it keys the AUTH payload.
const KEY_PAD: &[u8] = b"Key Pad for IKEv2";

const RSA_AUTH_DIGESTS: [DigestType; 4] = [
    DigestType::Sha1,
    DigestType::Sha256,
    DigestType::Sha384,
    DigestType::Sha512,
];

// RFC 7296 §3.8 only says SHA-1 SHOULD be supported.
const DEFAULT_SIGNATURE_DIGEST: DigestType = DigestType::Sha1;
const DEFAULT_GROUP: GroupType = GroupType::Oakley2;

/// RFC 7296 §2.14. `SK_d` seeds child-SA key material, `SK_a*`/`SK_e*` protect the SK payload in each direction,
/// and `SK_p*` key the AUTH payloads.
#[derive(Default, Clone, Serialize, Deserialize)]
pub struct Ikev2SessionKeys {
    pub shared_secret: Bytes,
    pub skeyseed: Bytes,
    pub sk_d: Bytes,
    pub sk_ai: Bytes,
    pub sk_ar: Bytes,
    pub sk_ei: Bytes,
    pub sk_er: Bytes,
    pub sk_pi: Bytes,
    pub sk_pr: Bytes,
}

#[derive(Clone)]
pub struct Ikev2Session(Arc<Mutex<Ikev2SessionImpl>>);

impl Ikev2Session {
    pub fn new(identity: Identity, session_type: SessionType) -> anyhow::Result<Self> {
        Self::with_dh_group(identity, session_type, DEFAULT_GROUP)
    }

    pub fn with_dh_group(identity: Identity, session_type: SessionType, group: GroupType) -> anyhow::Result<Self> {
        Ok(Self(Arc::new(Mutex::new(Ikev2SessionImpl::new(
            identity,
            session_type,
            group,
        )?))))
    }

    fn inner(&self) -> MutexGuard<'_, Ikev2SessionImpl> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn session_type(&self) -> SessionType {
        self.inner().session_type
    }

    pub fn hybrid_auth(&self) -> bool {
        self.inner().hybrid_auth
    }

    pub fn dh_group(&self) -> GroupType {
        self.inner().crypto.group_type()
    }

    pub fn set_dh_group(&self, group: GroupType) -> anyhow::Result<()> {
        self.inner().set_dh_group(group)
    }

    pub fn init_from_sa(&self, proposal: Ikev2SaProposal) -> anyhow::Result<()> {
        self.inner().init_from_sa(proposal)
    }

    pub fn init_from_ke(&self, public_key_r: Bytes, nonce_r: Bytes) -> anyhow::Result<()> {
        self.inner().init_from_ke(public_key_r, nonce_r)
    }

    pub fn session_keys(&self) -> Arc<Ikev2SessionKeys> {
        self.inner().session_keys.clone()
    }

    /// The SK payload crypto context, `None` until the key schedule has run.
    pub fn crypt(&self) -> Option<Arc<Ikev2Crypt>> {
        self.inner().crypt.clone()
    }

    pub fn crypto(&self) -> Arc<Crypto> {
        self.inner().crypto.clone()
    }

    pub fn integrity(&self) -> IntegrityAlgorithm {
        self.inner().integrity
    }

    pub fn is_keyed(&self) -> bool {
        self.inner().crypt.is_some()
    }

    pub fn set_sa_init_octets(&self, response: bool, data: Bytes) {
        let mut inner = self.inner();
        if response {
            inner.sa_init_response = data;
        } else {
            inner.sa_init_request = data;
        }
    }

    pub fn sa_init_request(&self) -> Bytes {
        self.inner().sa_init_request.clone()
    }

    pub fn sa_init_response(&self) -> Bytes {
        self.inner().sa_init_response.clone()
    }

    /// Whether the EAP-keyed AUTH payload runs the `"Key Pad for IKEv2"` step.
    /// Defaults to `true`, which is what strongSwan does — and a mismatch shows up as AUTHENTICATION_FAILED
    pub fn set_auth_key_pad(&self, key_pad: bool) {
        self.inner().auth_key_pad = key_pad;
    }

    /// `InitiatorSignedOctets` (RFC 7296 §2.15):
    pub fn signed_octets_i(&self, id_i: &[u8]) -> anyhow::Result<Bytes> {
        self.inner().signed_octets_i(id_i)
    }

    /// `ResponderSignedOctets`: the mirror, over the IKE_SA_INIT response, our
    pub fn signed_octets_r(&self, id_r: &[u8]) -> anyhow::Result<Bytes> {
        self.inner().signed_octets_r(id_r)
    }

    pub fn auth_i(&self, id_i: &[u8]) -> anyhow::Result<AuthenticationPayload> {
        self.inner().auth_i(id_i)
    }

    pub fn auth_i_signature(&self, id_i: &[u8]) -> anyhow::Result<AuthenticationPayload> {
        self.inner().auth_i_signature(id_i)
    }

    pub fn set_signature_digest(&self, digest: DigestType) {
        self.inner().signature_digest = digest;
    }

    pub fn verify_auth_r(
        &self,
        id_r: &[u8],
        auth: &AuthenticationPayload,
        certificates: &[Bytes],
    ) -> anyhow::Result<()> {
        self.inner().verify_auth_r(id_r, auth, certificates)
    }

    /// Derives the child SA keys and installs them for [`crate::esp`].
    pub fn init_from_child_sa(&self, proposal: Ikev2EspProposal) -> anyhow::Result<()> {
        self.inner().init_from_child_sa(proposal)
    }

    /// Replaces the child SA's keys after a CREATE_CHILD_SA exchange. See
    /// [`Ikev2SessionImpl::rekey_child_sa`].
    pub fn rekey_child_sa(
        &self,
        proposal: Ikev2EspProposal,
        nonce_i: &[u8],
        nonce_r: &[u8],
        we_initiated: bool,
    ) -> anyhow::Result<()> {
        self.inner().rekey_child_sa(proposal, nonce_i, nonce_r, we_initiated)
    }

    pub fn message_id(&self) -> u32 {
        self.inner().message_id
    }

    pub fn set_message_id(&self, message_id: u32) {
        self.inner().message_id = message_id;
    }

    pub fn set_lifetime(&self, lifetime: Duration) {
        self.inner().lifetime = lifetime;
    }
}

impl IsakmpSession for Ikev2Session {
    type Message = Ikev2Message;

    fn initiator(&self) -> Arc<EndpointData> {
        self.inner().initiator.clone()
    }

    fn responder(&self) -> Arc<EndpointData> {
        self.inner().responder.clone()
    }

    fn esp_in(&self) -> Arc<EspCryptMaterial> {
        self.inner().esp_in.clone()
    }

    fn esp_out(&self) -> Arc<EspCryptMaterial> {
        self.inner().esp_out.clone()
    }

    fn client_certificate(&self) -> Option<Arc<dyn ClientCertificate + Send + Sync>> {
        self.inner().client_cert.clone()
    }

    fn load(&self, data: &[u8]) -> anyhow::Result<OfficeMode> {
        self.inner().load(data)
    }

    fn save(&self, office_mode: &OfficeMode) -> anyhow::Result<Vec<u8>> {
        self.inner().save(office_mode)
    }

    fn new_codec(&self) -> Box<dyn IsakmpMessageCodec<Ikev2Message> + Send + Sync> {
        Box::new(Ikev2Codec::for_session(self.clone()))
    }

    fn timestamp(&self) -> u64 {
        self.inner().timestamp
    }

    fn lifetime(&self) -> Duration {
        self.inner().lifetime
    }
}

#[derive(Serialize, Deserialize)]
struct Ikev2SessionStore {
    initiator: Arc<EndpointData>,
    responder: Arc<EndpointData>,
    session_keys: Arc<Ikev2SessionKeys>,
    office_mode: OfficeMode,
    digest_type: DigestType,
    prf_type: DigestType,
    cipher_type: CipherType,
    group_type: GroupType,
    integrity: u16,
    lifetime: Duration,
    timestamp: u64,
    message_id: u32,
}

struct Ikev2SessionImpl {
    session_type: SessionType,
    hybrid_auth: bool,
    crypto: Arc<Crypto>,
    integrity: IntegrityAlgorithm,
    client_cert: Option<Arc<dyn ClientCertificate + Send + Sync>>,
    initiator: Arc<EndpointData>,
    responder: Arc<EndpointData>,
    session_keys: Arc<Ikev2SessionKeys>,
    crypt: Option<Arc<Ikev2Crypt>>,
    sa_init_request: Bytes,
    sa_init_response: Bytes,
    auth_key_pad: bool,
    signature_digest: DigestType,
    esp_in: Arc<EspCryptMaterial>,
    esp_out: Arc<EspCryptMaterial>,
    lifetime: Duration,
    timestamp: u64,
    message_id: u32,
}

impl Ikev2SessionImpl {
    fn new(identity: Identity, session_type: SessionType, group: GroupType) -> anyhow::Result<Self> {
        let (hybrid_auth, client_cert) = crate::certs::load_identity(identity)?;

        let crypto = Crypto::with_parameters(DigestType::Sha256, CipherType::Aes256Cbc, group)?;
        let public_key = crypto.public_key()?;

        let (spi_i, spi_r) = match session_type {
            SessionType::Initiator => (random(), 0),
            SessionType::Responder => (0, random()),
        };

        let (public_key_i, public_key_r) = match session_type {
            SessionType::Initiator => (public_key, Bytes::default()),
            SessionType::Responder => (Bytes::default(), public_key),
        };

        Ok(Self {
            session_type,
            hybrid_auth,
            crypto: Arc::new(crypto),
            integrity: IntegrityAlgorithm::None,
            client_cert,
            initiator: Arc::new(EndpointData {
                spi: spi_i,
                public_key: public_key_i,
                nonce: Bytes::copy_from_slice(&random::<[u8; NONCE_SIZE]>()),
                ..Default::default()
            }),
            responder: Arc::new(EndpointData {
                spi: spi_r,
                public_key: public_key_r,
                nonce: Bytes::copy_from_slice(&random::<[u8; NONCE_SIZE]>()),
                ..Default::default()
            }),
            session_keys: Arc::default(),
            crypt: None,
            sa_init_request: Bytes::default(),
            sa_init_response: Bytes::default(),
            auth_key_pad: true,
            signature_digest: DEFAULT_SIGNATURE_DIGEST,
            esp_in: Arc::default(),
            esp_out: Arc::default(),
            lifetime: Duration::default(),
            timestamp: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_secs(),
            message_id: 0,
        })
    }

    fn set_local_public_key(&mut self, public_key: Bytes) {
        match self.session_type {
            SessionType::Initiator => {
                self.initiator = Arc::new(EndpointData {
                    public_key,
                    ..(*self.initiator).clone()
                })
            }
            SessionType::Responder => {
                self.responder = Arc::new(EndpointData {
                    public_key,
                    ..(*self.responder).clone()
                })
            }
        }
    }

    fn set_dh_group(&mut self, group: GroupType) -> anyhow::Result<()> {
        let mut crypto = Crypto::with_parameters(self.crypto.digest_type(), self.crypto.cipher_type(), group)?;
        crypto.set_prf(self.crypto.prf_type());

        let public_key = crypto.public_key()?;
        self.crypto = Arc::new(crypto);
        self.set_local_public_key(public_key);

        Ok(())
    }

    fn init_from_sa(&mut self, proposal: Ikev2SaProposal) -> anyhow::Result<()> {
        let cipher = proposal.encryption.to_cipher_type(proposal.key_len)?;
        let prf = proposal.prf.to_digest_type()?;

        // An AEAD cipher carries its own integrity and must be paired with
        // INTEG_NONE; anything else is a proposal we cannot key (RFC 5282 §8).
        if proposal.encryption.is_aead() != (proposal.integrity == IntegrityAlgorithm::None) {
            anyhow::bail!(
                "Responder chose {:?} with {:?}, which cannot be keyed",
                proposal.encryption,
                proposal.integrity
            );
        }

        let digest = match proposal.integrity {
            IntegrityAlgorithm::None => prf,
            integrity => integrity.to_digest_type()?,
        };

        let group = proposal.dh_group.to_group_type()?;
        if group != self.crypto.group_type() {
            anyhow::bail!(
                "Responder's KE payload is for group {:?}, ours was for {:?}",
                group,
                self.crypto.group_type()
            );
        }

        let crypto = Arc::get_mut(&mut self.crypto)
            .context("Cannot apply the negotiated transforms: the crypto context is already in use")?;
        crypto.set_cipher(cipher);
        crypto.set_digest(digest);
        crypto.set_prf(prf);

        self.integrity = proposal.integrity;

        self.initiator = Arc::new(EndpointData {
            spi: proposal.initiator_spi,
            ..(*self.initiator).clone()
        });
        self.responder = Arc::new(EndpointData {
            spi: proposal.responder_spi,
            ..(*self.responder).clone()
        });

        debug!(
            "Negotiated IKE SA: {:?}/{} {:?} {:?} {:?}",
            proposal.encryption, proposal.key_len, proposal.prf, proposal.integrity, proposal.dh_group
        );

        Ok(())
    }

    fn init_from_ke(&mut self, public_key: Bytes, nonce: Bytes) -> anyhow::Result<()> {
        let peer_key = match self.session_type {
            SessionType::Initiator => {
                self.responder = Arc::new(EndpointData {
                    public_key,
                    nonce,
                    ..(*self.responder).clone()
                });
                &self.responder.public_key
            }
            SessionType::Responder => {
                self.initiator = Arc::new(EndpointData {
                    public_key,
                    nonce,
                    ..(*self.initiator).clone()
                });
                &self.initiator.public_key
            }
        };

        let expected = self.crypto.group_type().public_key_len();
        anyhow::ensure!(
            peer_key.len() == expected,
            "Responder's public key is {} bytes, group {:?} wants {}",
            peer_key.len(),
            self.crypto.group_type(),
            expected
        );

        let shared_secret = self.crypto.shared_secret(peer_key)?;

        // RFC 7296 §2.14: SKEYSEED = prf(Ni | Nr, g^ir)
        let nonces = [self.initiator.nonce.as_ref(), self.responder.nonce.as_ref()].concat();
        let skeyseed = self.crypto.prf(&nonces, [shared_secret.as_ref()])?;

        // prf+(SKEYSEED, Ni | Nr | SPIi | SPIr), cut into the seven keys
        let mut seed = BytesMut::with_capacity(nonces.len() + 16);
        seed.put_slice(&nonces);
        seed.put_u64(self.initiator.spi);
        seed.put_u64(self.responder.spi);

        let prf_len = self.crypto.prf_len();
        let integ_len = match self.integrity {
            IntegrityAlgorithm::None => 0,
            _ => self.crypto.hash_len(),
        };
        let enc_len = self.crypto.key_material_len();

        let keymat = self
            .crypto
            .prf_plus(&skeyseed, &seed, prf_len * 3 + integ_len * 2 + enc_len * 2)?;

        let mut offset = 0;
        let mut take = |len: usize| {
            let key = keymat.slice(offset..offset + len);
            offset += len;
            key
        };

        // the order of the cuts is the order of the fields: RFC 7296 §2.14
        let session_keys = Ikev2SessionKeys {
            sk_d: take(prf_len),
            sk_ai: take(integ_len),
            sk_ar: take(integ_len),
            sk_ei: take(enc_len),
            sk_er: take(enc_len),
            sk_pi: take(prf_len),
            sk_pr: take(prf_len),
            shared_secret,
            skeyseed,
        };

        let initiator_keys = DirectionalKeys {
            sk_e: session_keys.sk_ei.clone(),
            sk_a: session_keys.sk_ai.clone(),
        };
        let responder_keys = DirectionalKeys {
            sk_e: session_keys.sk_er.clone(),
            sk_a: session_keys.sk_ar.clone(),
        };

        let (outbound, inbound) = match self.session_type {
            SessionType::Initiator => (initiator_keys, responder_keys),
            SessionType::Responder => (responder_keys, initiator_keys),
        };

        self.crypt = Some(Arc::new(Ikev2Crypt::new(
            self.crypto.clone(),
            self.integrity,
            outbound,
            inbound,
        )?));

        self.session_keys = Arc::new(session_keys);

        Ok(())
    }

    fn signed_octets(&self, message: &Bytes, nonce: &Bytes, key: &[u8], id: &[u8]) -> anyhow::Result<Bytes> {
        anyhow::ensure!(!message.is_empty(), "No IKE_SA_INIT octets: the exchange has not run");

        let mac = self.crypto.prf(key, [id])?;

        let mut buf = BytesMut::with_capacity(message.len() + nonce.len() + mac.len());
        buf.put_slice(message);
        buf.put_slice(nonce);
        buf.put_slice(&mac);

        Ok(buf.freeze())
    }

    fn signed_octets_i(&self, id_i: &[u8]) -> anyhow::Result<Bytes> {
        self.signed_octets(
            &self.sa_init_request,
            &self.responder.nonce,
            &self.session_keys.sk_pi,
            id_i,
        )
    }

    fn signed_octets_r(&self, id_r: &[u8]) -> anyhow::Result<Bytes> {
        self.signed_octets(
            &self.sa_init_response,
            &self.initiator.nonce,
            &self.session_keys.sk_pr,
            id_r,
        )
    }

    /// RFC 7296 §2.15: `prf(prf(Shared Secret, "Key Pad for IKEv2"), octets)`, or the outer PRF alone
    /// where the padding step does not apply.
    fn auth_shared_key(&self, signed_octets: &[u8], secret: &[u8], key_pad: bool) -> anyhow::Result<Bytes> {
        let key = if key_pad {
            self.crypto.prf(secret, [KEY_PAD])?
        } else {
            Bytes::copy_from_slice(secret)
        };

        self.crypto.prf(&key, [signed_octets])
    }

    fn auth_i(&self, id_i: &[u8]) -> anyhow::Result<AuthenticationPayload> {
        let octets = self.signed_octets_i(id_i)?;

        Ok(AuthenticationPayload {
            auth_method: AuthMethod::SharedKeyMic,
            data: self.auth_shared_key(&octets, &self.session_keys.sk_pi, self.auth_key_pad)?,
        })
    }

    /// RFC 7296 §3.8 method 1: RSASSA-PKCS1-v1_5 over the initiator's signed octets
    fn auth_i_signature(&self, id_i: &[u8]) -> anyhow::Result<AuthenticationPayload> {
        let certificate = self
            .client_cert
            .as_ref()
            .context("No client certificate to sign the AUTH payload with")?;

        let octets = self.signed_octets_i(id_i)?;

        debug!(
            "Signing AUTH with certificate '{}' and {:?}",
            certificate.subject_name(),
            self.signature_digest
        );

        Ok(AuthenticationPayload {
            auth_method: AuthMethod::RsaDigitalSignature,
            data: certificate.sign(&self.signature_digest.digest_info(&octets)?)?,
        })
    }

    fn verify_auth_r(&self, id_r: &[u8], auth: &AuthenticationPayload, certificates: &[Bytes]) -> anyhow::Result<()> {
        let octets = self.signed_octets_r(id_r)?;

        match auth.auth_method {
            AuthMethod::SharedKeyMic => {
                let expected = self.auth_shared_key(&octets, &self.session_keys.sk_pr, self.auth_key_pad)?;

                if openssl::memcmp::eq(&expected, &auth.data) {
                    return Ok(());
                }

                let other = self.auth_shared_key(&octets, &self.session_keys.sk_pr, !self.auth_key_pad)?;
                if openssl::memcmp::eq(&other, &auth.data) {
                    warn!(
                        "Responder's AUTH verifies with key_pad={}, not the configured {}",
                        !self.auth_key_pad, self.auth_key_pad
                    );
                }

                anyhow::bail!("Responder's shared-key AUTH does not match");
            }
            AuthMethod::RsaDigitalSignature => {
                let certificate = certificates.first().context("No certificate to verify AUTH against")?;

                for digest in RSA_AUTH_DIGESTS {
                    if self
                        .crypto
                        .verify_rsa_signature(&octets, &auth.data, certificate, digest)
                        .is_ok()
                    {
                        debug!("Responder's AUTH signature verified with {:?}", digest);
                        return Ok(());
                    }
                }

                anyhow::bail!("Responder's RSA AUTH signature does not verify");
            }
            other => anyhow::bail!("Unsupported AUTH method: {:?}", other),
        }
    }

    /// RFC 7296 §2.17: `KEYMAT = prf+(SK_d, Ni | Nr)` for the child SA created by IKE_AUTH
    fn init_from_child_sa(&mut self, proposal: Ikev2EspProposal) -> anyhow::Result<()> {
        let nonces = [self.initiator.nonce.as_ref(), self.responder.nonce.as_ref()].concat();
        let we_initiated = self.session_type == SessionType::Initiator;

        self.key_child_sa(proposal, &nonces, we_initiated)
    }

    fn rekey_child_sa(
        &mut self,
        proposal: Ikev2EspProposal,
        nonce_i: &[u8],
        nonce_r: &[u8],
        we_initiated: bool,
    ) -> anyhow::Result<()> {
        let nonces = [nonce_i, nonce_r].concat();

        self.key_child_sa(proposal, &nonces, we_initiated)
    }

    fn key_child_sa(&mut self, proposal: Ikev2EspProposal, nonces: &[u8], we_initiated: bool) -> anyhow::Result<()> {
        if proposal.encryption.is_aead() != (proposal.integrity == IntegrityAlgorithm::None) {
            anyhow::bail!(
                "Responder chose {:?} with {:?} for the child SA, which cannot be keyed",
                proposal.encryption,
                proposal.integrity
            );
        }

        let cipher = proposal.encryption.to_cipher_type(proposal.key_len)?;
        let authentication = proposal.integrity.to_authentication()?;

        let enc_len = cipher.key_material_len();
        let auth_len = match authentication {
            Some(auth) => auth.digest.hash_len(),
            None => 0,
        };

        let keymat = self
            .crypto
            .prf_plus(&self.session_keys.sk_d, nonces, (enc_len + auth_len) * 2)?;

        let mut offset = 0;
        let mut take = |len: usize| {
            let key = keymat.slice(offset..offset + len);
            offset += len;
            key
        };

        let i_to_r = EspCryptMaterial {
            spi: proposal.spi_r,
            sk_e: take(enc_len),
            sk_a: take(auth_len),
            cipher,
            auth: authentication,
        };
        let r_to_i = EspCryptMaterial {
            spi: proposal.spi_i,
            sk_e: take(enc_len),
            sk_a: take(auth_len),
            cipher,
            auth: authentication,
        };

        let (esp_out, esp_in) = if we_initiated {
            (i_to_r, r_to_i)
        } else {
            (r_to_i, i_to_r)
        };

        self.initiator = Arc::new(EndpointData {
            esp_spi: proposal.spi_i,
            ..(*self.initiator).clone()
        });
        self.responder = Arc::new(EndpointData {
            esp_spi: proposal.spi_r,
            ..(*self.responder).clone()
        });

        self.esp_in = Arc::new(esp_in);
        self.esp_out = Arc::new(esp_out);

        Ok(())
    }

    fn load(&mut self, data: &[u8]) -> anyhow::Result<OfficeMode> {
        let store = rmp_serde::from_slice::<Ikev2SessionStore>(data)?;

        let mut crypto = Crypto::with_parameters(store.digest_type, store.cipher_type, store.group_type)?;
        crypto.set_prf(store.prf_type);

        self.crypto = Arc::new(crypto);
        self.integrity = store.integrity.into();
        self.initiator = store.initiator;
        self.responder = store.responder;
        self.session_keys = store.session_keys;
        self.lifetime = store.lifetime;
        self.timestamp = store.timestamp;
        self.message_id = store.message_id;

        let initiator_keys = DirectionalKeys {
            sk_e: self.session_keys.sk_ei.clone(),
            sk_a: self.session_keys.sk_ai.clone(),
        };
        let responder_keys = DirectionalKeys {
            sk_e: self.session_keys.sk_er.clone(),
            sk_a: self.session_keys.sk_ar.clone(),
        };

        let (outbound, inbound) = match self.session_type {
            SessionType::Initiator => (initiator_keys, responder_keys),
            SessionType::Responder => (responder_keys, initiator_keys),
        };

        self.crypt = Some(Arc::new(Ikev2Crypt::new(
            self.crypto.clone(),
            self.integrity,
            outbound,
            inbound,
        )?));

        Ok(store.office_mode)
    }

    fn save(&self, office_mode: &OfficeMode) -> anyhow::Result<Vec<u8>> {
        let store = Ikev2SessionStore {
            initiator: self.initiator.clone(),
            responder: self.responder.clone(),
            session_keys: self.session_keys.clone(),
            office_mode: office_mode.clone(),
            digest_type: self.crypto.digest_type(),
            prf_type: self.crypto.prf_type(),
            cipher_type: self.crypto.cipher_type(),
            group_type: self.crypto.group_type(),
            integrity: self.integrity.into(),
            lifetime: self.lifetime,
            timestamp: self.timestamp,
            message_id: self.message_id,
        };

        Ok(rmp_serde::to_vec(&store)?)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use openssl::{
        asn1::Asn1Time,
        hash::MessageDigest,
        pkcs12::Pkcs12,
        pkey::{PKey, Private},
        rsa::Rsa,
        sign::{Signer, Verifier},
        x509::{X509, X509NameBuilder},
    };
    use secrecy::SecretString;

    use super::*;
    use crate::{
        crypto::IcvLength,
        ikev2::{
            message::Ikev2Message,
            model::{DhGroup, EncryptionAlgorithm, ExchangeType, Flags, PayloadType, PseudoRandomFunction},
            payload::{IdentificationPayload, Payload},
        },
        payload::{BasicPayload, PayloadLike},
    };

    fn office_mode() -> OfficeMode {
        OfficeMode {
            ccc_session: "deadbeef".to_owned(),
            username: "user".to_owned(),
            ip_address: Ipv4Addr::new(172, 16, 10, 2),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            dns: vec![Ipv4Addr::new(10, 0, 0, 1)],
            domains: vec!["example.com".to_owned()],
        }
    }

    fn proposal(
        session: &Ikev2Session,
        encryption: EncryptionAlgorithm,
        key_len: usize,
        prf: PseudoRandomFunction,
        integrity: IntegrityAlgorithm,
    ) -> Ikev2SaProposal {
        Ikev2SaProposal {
            initiator_spi: session.initiator_spi(),
            responder_spi: 0x1122334455667788,
            encryption,
            key_len,
            prf,
            integrity,
            dh_group: DhGroup::from(session.dh_group()),
        }
    }

    /// A session that has completed IKE_SA_INIT against a synthetic responder.
    fn established(
        encryption: EncryptionAlgorithm,
        key_len: usize,
        prf: PseudoRandomFunction,
        integrity: IntegrityAlgorithm,
    ) -> Ikev2Session {
        let session = test_session(SessionType::Initiator);

        let peer = Crypto::with_parameters(DigestType::Sha256, CipherType::Aes256Cbc, session.dh_group()).unwrap();

        session
            .init_from_sa(proposal(&session, encryption, key_len, prf, integrity))
            .unwrap();
        session
            .init_from_ke(peer.public_key().unwrap(), Bytes::from_static(&[0x42; NONCE_SIZE]))
            .unwrap();

        session
    }

    /// A keyed session with IKE_SA_INIT octets in place, as the codec would
    /// have recorded them.
    fn authenticated() -> Ikev2Session {
        let session = default_session();
        session.set_sa_init_octets(false, Bytes::from_static(b"IKE_SA_INIT request octets"));
        session.set_sa_init_octets(true, Bytes::from_static(b"IKE_SA_INIT response octets"));
        session
    }

    fn id_payload(id_type: crate::ikev2::model::IdentificationType, data: &'static [u8]) -> IdentificationPayload {
        IdentificationPayload {
            id_type,
            data: Bytes::from_static(data),
        }
    }

    /// `prf(prf(secret, "Key Pad for IKEv2"), octets)`, spelled out here rather
    /// than taken from the session, so the test pins the formula.
    fn shared_key_mic(session: &Ikev2Session, secret: &[u8], octets: &[u8], key_pad: bool) -> Bytes {
        let crypto = session.crypto();
        let key = if key_pad {
            crypto.prf(secret, [b"Key Pad for IKEv2".as_slice()]).unwrap()
        } else {
            Bytes::copy_from_slice(secret)
        };
        crypto.prf(&key, [octets]).unwrap()
    }

    /// A throwaway RSA key and a self-signed certificate holding its public
    /// half, for checking a real AUTH signature.
    fn self_signed_certificate() -> (PKey<Private>, Bytes) {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();

        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "gw VPN Certificate").unwrap();
        let name = name.build();

        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&key).unwrap();
        builder.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
        builder.set_not_after(&Asn1Time::days_from_now(1).unwrap()).unwrap();
        builder.sign(&key, MessageDigest::sha256()).unwrap();

        (key, Bytes::from(builder.build().to_der().unwrap()))
    }

    /// A keyed session holding a client certificate, as machine
    /// authentication needs, with the IKE_SA_INIT octets in place. Returns the
    /// private key and the certificate so a test can check the signature the
    /// session produces from the outside.
    fn certificate_session(hybrid_auth: bool) -> (Ikev2Session, PKey<Private>, Bytes) {
        let (key, certificate) = self_signed_certificate();

        let pkcs12 = Pkcs12::builder()
            .name("machine")
            .pkey(&key)
            .cert(&X509::from_der(&certificate).unwrap())
            .build2("secret")
            .unwrap()
            .to_der()
            .unwrap();

        let identity = Identity::Pkcs12 {
            data: pkcs12,
            password: SecretString::from("secret"),
            hybrid_auth,
        };

        let session = Ikev2Session::with_dh_group(identity, SessionType::Initiator, GroupType::Oakley2).unwrap();
        let peer = Crypto::with_parameters(DigestType::Sha256, CipherType::Aes256Cbc, session.dh_group()).unwrap();

        session
            .init_from_sa(proposal(
                &session,
                EncryptionAlgorithm::AesCbc,
                32,
                PseudoRandomFunction::HmacSha256,
                IntegrityAlgorithm::HmacSha256_128,
            ))
            .unwrap();
        session
            .init_from_ke(peer.public_key().unwrap(), Bytes::from_static(&[0x42; NONCE_SIZE]))
            .unwrap();

        session.set_sa_init_octets(false, Bytes::from_static(b"IKE_SA_INIT request octets"));
        session.set_sa_init_octets(true, Bytes::from_static(b"IKE_SA_INIT response octets"));

        (session, key, certificate)
    }

    /// Pinned rather than left to `DEFAULT_GROUP`: these tests are about the
    /// key schedule, not about which group the default happens to be.
    fn test_session(session_type: SessionType) -> Ikev2Session {
        Ikev2Session::with_dh_group(Identity::None, session_type, GroupType::Oakley2).unwrap()
    }

    fn default_session() -> Ikev2Session {
        established(
            EncryptionAlgorithm::AesCbc,
            32,
            PseudoRandomFunction::HmacSha256,
            IntegrityAlgorithm::HmacSha256_128,
        )
    }

    fn message(exchange_type: ExchangeType, flags: Flags, session: &Ikev2Session) -> Ikev2Message {
        Ikev2Message {
            initiator_spi: session.initiator_spi(),
            responder_spi: session.responder_spi(),
            version: crate::message::IKEV2_VERSION,
            exchange_type,
            flags,
            message_id: 1,
            payloads: vec![Payload::IdentificationInitiator(IdentificationPayload {
                id_type: crate::ikev2::model::IdentificationType::KeyId,
                data: Bytes::from_static(b"testuser\0"),
            })],
        }
    }

    /// The key schedule, recomputed from the session's own inputs. Catches a
    /// wrong PRF key, a wrong seed order or a mis-cut `prf+` stream — all of
    /// which produce keys that are self-consistent but wrong on the wire.
    /// `InitiatorSignedOctets` and the shared-key AUTH over them, recomputed
    /// from the session's own state (RFC 7296 §2.15).
    #[test]
    fn test_auth_payload_follows_rfc_7296() {
        let session = authenticated();
        let keys = session.session_keys();
        let crypto = session.crypto();

        let id_i = id_payload(crate::ikev2::model::IdentificationType::KeyId, b"testuser\0");
        let id_body = id_i.to_bytes();

        // RealMessage1 | NonceRData | prf(SK_pi, RestOfInitIDPayload)
        let expected = [
            session.sa_init_request().as_ref(),
            session.responder().nonce.as_ref(),
            crypto.prf(&keys.sk_pi, [id_body.as_ref()]).unwrap().as_ref(),
        ]
        .concat();

        assert_eq!(
            session.signed_octets_i(&id_body).unwrap(),
            Bytes::from(expected.clone())
        );

        // AUTH = prf(prf(SK_pi, "Key Pad for IKEv2"), signed octets)
        let auth = session.auth_i(&id_body).unwrap();
        assert_eq!(auth.auth_method, AuthMethod::SharedKeyMic);
        assert_eq!(auth.data, shared_key_mic(&session, &keys.sk_pi, &expected, true));
        assert_eq!(auth.data.len(), crypto.prf_len());

        // the responder's octets differ in all three parts
        let id_r = id_payload(crate::ikev2::model::IdentificationType::Ipv4Address, &[172, 24, 1, 5]);
        let octets_r = session.signed_octets_r(&id_r.to_bytes()).unwrap();

        assert!(octets_r.starts_with(&session.sa_init_response()));
        assert_ne!(octets_r, Bytes::from(expected));
    }

    /// Whether the key-pad step applies to EAP-keyed AUTH is the one part of
    /// RFC 7296 §2.16 left open, so both variants must be reachable.
    #[test]
    fn test_auth_key_pad_is_switchable() {
        let session = authenticated();
        let keys = session.session_keys();
        let id_body = id_payload(crate::ikev2::model::IdentificationType::KeyId, b"testuser\0").to_bytes();
        let octets = session.signed_octets_i(&id_body).unwrap();

        let with_pad = session.auth_i(&id_body).unwrap().data;

        session.set_auth_key_pad(false);
        let without_pad = session.auth_i(&id_body).unwrap().data;

        assert_ne!(with_pad, without_pad);
        assert_eq!(with_pad, shared_key_mic(&session, &keys.sk_pi, &octets, true));
        assert_eq!(without_pad, shared_key_mic(&session, &keys.sk_pi, &octets, false));
    }

    #[test]
    fn test_verify_auth_r_accepts_a_shared_key_mic() {
        let session = authenticated();
        let keys = session.session_keys();

        let id_r = id_payload(crate::ikev2::model::IdentificationType::Ipv4Address, &[172, 24, 1, 5]);
        let octets = session.signed_octets_r(&id_r.to_bytes()).unwrap();

        let auth = AuthenticationPayload {
            auth_method: AuthMethod::SharedKeyMic,
            data: shared_key_mic(&session, &keys.sk_pr, &octets, true),
        };

        session.verify_auth_r(&id_r.to_bytes(), &auth, &[]).unwrap();

        // keyed by SK_pi instead of SK_pr, i.e. our own direction
        let wrong_key = AuthenticationPayload {
            data: shared_key_mic(&session, &keys.sk_pi, &octets, true),
            ..auth.clone()
        };
        assert!(session.verify_auth_r(&id_r.to_bytes(), &wrong_key, &[]).is_err());

        // right MIC, wrong ID
        let other_id = id_payload(crate::ikev2::model::IdentificationType::Ipv4Address, &[10, 0, 0, 1]);
        assert!(session.verify_auth_r(&other_id.to_bytes(), &auth, &[]).is_err());
    }

    /// AUTH method 1 is RSASSA-PKCS1-v1_5 *with* the DigestInfo prefix, unlike
    /// the raw construction IKEv1 uses — the difference is invisible until a
    /// real signature is checked.
    #[test]
    fn test_verify_auth_r_accepts_an_rsa_signature() {
        let session = authenticated();

        let id_r = id_payload(crate::ikev2::model::IdentificationType::Ipv4Address, &[172, 24, 1, 5]);
        let octets = session.signed_octets_r(&id_r.to_bytes()).unwrap();

        let (key, certificate) = self_signed_certificate();

        for digest in [MessageDigest::sha1(), MessageDigest::sha256()] {
            let mut signer = Signer::new(digest, &key).unwrap();
            signer.update(&octets).unwrap();

            let auth = AuthenticationPayload {
                auth_method: AuthMethod::RsaDigitalSignature,
                data: signer.sign_to_vec().unwrap().into(),
            };

            session
                .verify_auth_r(&id_r.to_bytes(), &auth, std::slice::from_ref(&certificate))
                .unwrap();

            // a signature over other octets must not verify
            let mut signer = Signer::new(digest, &key).unwrap();
            signer.update(b"other octets").unwrap();
            let forged = AuthenticationPayload {
                data: signer.sign_to_vec().unwrap().into(),
                ..auth.clone()
            };

            assert!(
                session
                    .verify_auth_r(&id_r.to_bytes(), &forged, std::slice::from_ref(&certificate))
                    .is_err()
            );
        }

        // and a signature method needs a certificate at all
        let auth = AuthenticationPayload {
            auth_method: AuthMethod::RsaDigitalSignature,
            data: Bytes::from_static(&[0; 256]),
        };
        assert!(session.verify_auth_r(&id_r.to_bytes(), &auth, &[]).is_err());
    }

    /// The AUTH payload the machine-authentication round sends: an ordinary
    /// RSASSA-PKCS1-v1_5 signature over `InitiatorSignedOctets`, which is only
    /// visible as such when an openssl verifier — not our own code — checks it.
    #[test]
    fn test_auth_i_signature_signs_the_initiator_octets() {
        let (session, key, certificate) = certificate_session(true);

        assert!(session.hybrid_auth());

        let id_i = id_payload(crate::ikev2::model::IdentificationType::DerAsn1Dn, b"DER subject name");
        let id_body = id_i.to_bytes();
        let octets = session.signed_octets_i(&id_body).unwrap();

        let auth = session.auth_i_signature(&id_body).unwrap();
        assert_eq!(auth.auth_method, AuthMethod::RsaDigitalSignature);
        assert_eq!(auth.data.len(), 256, "a 2048-bit signature");

        // SHA-1 by default, as the captured gateway signs its own AUTH
        let mut verifier = Verifier::new(MessageDigest::sha1(), &key).unwrap();
        verifier.update(&octets).unwrap();
        assert!(verifier.verify(&auth.data).unwrap());

        // the octets are the initiator's, so the same signature must not pass
        // as a responder AUTH over the certificate the round carries
        assert!(
            session
                .verify_auth_r(&id_body, &auth, std::slice::from_ref(&certificate))
                .is_err()
        );

        // the hash is a setting, since AUTH method 1 does not name one
        session.set_signature_digest(DigestType::Sha256);
        let sha256 = session.auth_i_signature(&id_body).unwrap();
        assert_ne!(sha256.data, auth.data);

        let mut verifier = Verifier::new(MessageDigest::sha256(), &key).unwrap();
        verifier.update(&octets).unwrap();
        assert!(verifier.verify(&sha256.data).unwrap());

        // a signature over anything else must not verify
        let mut verifier = Verifier::new(MessageDigest::sha256(), &key).unwrap();
        verifier.update(b"other octets").unwrap();
        assert!(!verifier.verify(&sha256.data).unwrap());
    }

    /// Without a certificate there is nothing to sign with, and saying so is
    /// better than an AUTH payload nobody can verify.
    #[test]
    fn test_auth_i_signature_needs_a_certificate() {
        let session = authenticated();
        let id_body = id_payload(crate::ikev2::model::IdentificationType::KeyId, b"testuser\0").to_bytes();

        let err = session.auth_i_signature(&id_body).unwrap_err().to_string();
        assert!(err.contains("No client certificate"), "{err}");
    }

    /// `KEYMAT = prf+(SK_d, Ni | Nr)` (RFC 7296 §2.17), cut initiator-first,
    /// with each direction's SPI being the one the *other* end chose.
    #[test]
    fn test_child_sa_keys_follow_rfc_7296() {
        let session = authenticated();
        let keys = session.session_keys();
        let crypto = session.crypto();

        session
            .init_from_child_sa(Ikev2EspProposal {
                spi_i: 0x74940b66,
                spi_r: 0x6d7636f8,
                encryption: EncryptionAlgorithm::AesCbc,
                key_len: 32,
                integrity: IntegrityAlgorithm::HmacSha256_128,
            })
            .unwrap();

        let nonces = [session.initiator().nonce.as_ref(), session.responder().nonce.as_ref()].concat();

        let keymat = crypto.prf_plus(&keys.sk_d, &nonces, (32 + 32) * 2).unwrap();

        let (esp_in, esp_out) = (session.esp_in(), session.esp_out());

        // initiator -> responder is what we send, addressed to the SPI the
        // responder chose
        assert_eq!(esp_out.spi, 0x6d7636f8);
        assert_eq!(esp_out.sk_e, keymat.slice(0..32));
        assert_eq!(esp_out.sk_a, keymat.slice(32..64));

        assert_eq!(esp_in.spi, 0x74940b66);
        assert_eq!(esp_in.sk_e, keymat.slice(64..96));
        assert_eq!(esp_in.sk_a, keymat.slice(96..128));

        assert_eq!(esp_in.cipher, CipherType::Aes256Cbc);
        assert_eq!(esp_in.auth.unwrap().icv_len, 16);
        assert_eq!(esp_in.auth.unwrap().digest, DigestType::Sha256);

        // and the child SA keys are not the IKE SA's
        assert_ne!(esp_in.sk_e, keys.sk_ei);
        assert_ne!(esp_out.sk_e, keys.sk_er);
    }

    /// An AEAD child SA draws four octets more than the key length: the RFC
    /// 4106 salt, which lives at the end of `sk_e` and never goes on the wire.
    /// There is no integrity key to draw at all.
    #[test]
    fn test_aead_child_sa_keys_carry_a_salt() {
        let session = authenticated();
        let keys = session.session_keys();
        let crypto = session.crypto();

        session
            .init_from_child_sa(Ikev2EspProposal {
                spi_i: 0x74940b66,
                spi_r: 0x6d7636f8,
                encryption: EncryptionAlgorithm::AesGcm16,
                key_len: 32,
                integrity: IntegrityAlgorithm::None,
            })
            .unwrap();

        let nonces = [session.initiator().nonce.as_ref(), session.responder().nonce.as_ref()].concat();
        let keymat = crypto.prf_plus(&keys.sk_d, &nonces, 36 * 2).unwrap();

        let (esp_in, esp_out) = (session.esp_in(), session.esp_out());

        assert_eq!(esp_out.sk_e, keymat.slice(0..36));
        assert_eq!(esp_in.sk_e, keymat.slice(36..72));

        for esp in [&esp_in, &esp_out] {
            assert_eq!(esp.cipher, CipherType::Aes256Gcm(IcvLength::Sixteen));
            assert!(esp.auth.is_none());
            assert!(esp.sk_a.is_empty());
            assert_eq!(esp.icv_len(), 16);
        }
    }

    /// AES-GCM and an HMAC are offered as separate proposals, so a responder
    /// answering with both has answered with something we cannot key.
    #[test]
    fn test_child_sa_rejects_aead_with_an_integrity_algorithm() {
        let session = authenticated();

        let err = session
            .init_from_child_sa(Ikev2EspProposal {
                spi_i: 1,
                spi_r: 2,
                encryption: EncryptionAlgorithm::AesGcm16,
                key_len: 32,
                integrity: IntegrityAlgorithm::HmacSha256_128,
            })
            .unwrap_err()
            .to_string();
        assert!(err.contains("cannot be keyed"), "{err}");

        // ...and so has one answering with CBC and no integrity at all
        let err = session
            .init_from_child_sa(Ikev2EspProposal {
                spi_i: 1,
                spi_r: 2,
                encryption: EncryptionAlgorithm::AesCbc,
                key_len: 32,
                integrity: IntegrityAlgorithm::None,
            })
            .unwrap_err()
            .to_string();
        assert!(err.contains("cannot be keyed"), "{err}");
    }

    #[test]
    fn test_child_sa_keys_swap_with_the_role() {
        let responder = test_session(SessionType::Responder);
        let peer = Crypto::with_parameters(DigestType::Sha256, CipherType::Aes256Cbc, responder.dh_group()).unwrap();

        responder
            .init_from_sa(proposal(
                &responder,
                EncryptionAlgorithm::AesCbc,
                32,
                PseudoRandomFunction::HmacSha256,
                IntegrityAlgorithm::HmacSha256_128,
            ))
            .unwrap();
        responder
            .init_from_ke(peer.public_key().unwrap(), Bytes::from_static(&[0x42; NONCE_SIZE]))
            .unwrap();

        let esp_proposal = Ikev2EspProposal {
            spi_i: 0x11111111,
            spi_r: 0x22222222,
            encryption: EncryptionAlgorithm::AesCbc,
            key_len: 32,
            integrity: IntegrityAlgorithm::HmacSha256_128,
        };
        responder.init_from_child_sa(esp_proposal).unwrap();

        // a responder sends to the initiator's SPI with the second key pair
        assert_eq!(responder.esp_out().spi, 0x11111111);
        assert_eq!(responder.esp_in().spi, 0x22222222);
    }

    #[test]
    fn test_signed_octets_need_the_sa_init_exchange() {
        let session = default_session();
        let err = session.signed_octets_i(b"id").unwrap_err().to_string();
        assert!(err.contains("has not run"), "{err}");
    }

    #[test]
    fn test_key_schedule_follows_rfc_7296() {
        let session = default_session();
        let crypto = session.crypto();
        let keys = session.session_keys();
        let (initiator, responder) = (session.initiator(), session.responder());

        let nonces = [initiator.nonce.as_ref(), responder.nonce.as_ref()].concat();

        // SKEYSEED = prf(Ni | Nr, g^ir)
        let skeyseed = crypto.prf(&nonces, [keys.shared_secret.as_ref()]).unwrap();
        assert_eq!(keys.skeyseed, skeyseed);

        // prf+(SKEYSEED, Ni | Nr | SPIi | SPIr)
        let seed = [
            nonces.as_slice(),
            &initiator.spi.to_be_bytes(),
            &responder.spi.to_be_bytes(),
        ]
        .concat();

        let prf_len = crypto.prf_len();
        let integ_len = crypto.hash_len();
        let enc_len = crypto.key_material_len();

        let keymat = crypto
            .prf_plus(&skeyseed, &seed, prf_len * 3 + integ_len * 2 + enc_len * 2)
            .unwrap();

        let mut offset = 0;
        let mut take = |len: usize| {
            let key = keymat.slice(offset..offset + len);
            offset += len;
            key
        };

        assert_eq!(keys.sk_d, take(prf_len));
        assert_eq!(keys.sk_ai, take(integ_len));
        assert_eq!(keys.sk_ar, take(integ_len));
        assert_eq!(keys.sk_ei, take(enc_len));
        assert_eq!(keys.sk_er, take(enc_len));
        assert_eq!(keys.sk_pi, take(prf_len));
        assert_eq!(keys.sk_pr, take(prf_len));

        // and the keys are all distinct: a mis-cut stream repeats itself
        let all = [
            &keys.sk_d,
            &keys.sk_ai,
            &keys.sk_ar,
            &keys.sk_ei,
            &keys.sk_er,
            &keys.sk_pi,
            &keys.sk_pr,
        ];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    #[test]
    fn test_key_lengths_follow_the_transforms() {
        for (encryption, key_len, prf, integrity, expected_prf, expected_integ, expected_enc) in [
            (
                EncryptionAlgorithm::AesCbc,
                32,
                PseudoRandomFunction::HmacSha1,
                IntegrityAlgorithm::HmacSha1_96,
                20,
                20,
                32,
            ),
            (
                EncryptionAlgorithm::AesCbc,
                16,
                PseudoRandomFunction::HmacSha512,
                IntegrityAlgorithm::HmacSha256_128,
                64,
                32,
                16,
            ),
            (
                EncryptionAlgorithm::DesEde3Cbc,
                24,
                PseudoRandomFunction::HmacSha256,
                IntegrityAlgorithm::HmacSha384_192,
                32,
                48,
                24,
            ),
            // AEAD: no integrity transform, and the 4-octet salt rides along
            // with the encryption key
            (
                EncryptionAlgorithm::AesGcm16,
                32,
                PseudoRandomFunction::HmacSha256,
                IntegrityAlgorithm::None,
                32,
                0,
                36,
            ),
        ] {
            let session = established(encryption, key_len, prf, integrity);
            let keys = session.session_keys();

            assert_eq!(keys.sk_d.len(), expected_prf, "{encryption:?} SK_d");
            assert_eq!(keys.sk_pi.len(), expected_prf, "{encryption:?} SK_pi");
            assert_eq!(keys.sk_pr.len(), expected_prf, "{encryption:?} SK_pr");
            assert_eq!(keys.sk_ai.len(), expected_integ, "{encryption:?} SK_ai");
            assert_eq!(keys.sk_ar.len(), expected_integ, "{encryption:?} SK_ar");
            assert_eq!(keys.sk_ei.len(), expected_enc, "{encryption:?} SK_ei");
            assert_eq!(keys.sk_er.len(), expected_enc, "{encryption:?} SK_er");
            assert!(session.is_keyed());
        }
    }

    /// Both ends of the same exchange must arrive at the same seven keys, and
    /// map them to opposite directions.
    #[test]
    fn test_initiator_and_responder_agree() {
        let initiator = test_session(SessionType::Initiator);
        let responder = test_session(SessionType::Responder);

        let proposal = Ikev2SaProposal {
            initiator_spi: initiator.initiator_spi(),
            responder_spi: responder.responder_spi(),
            encryption: EncryptionAlgorithm::AesCbc,
            key_len: 32,
            prf: PseudoRandomFunction::HmacSha1,
            integrity: IntegrityAlgorithm::HmacSha1_96,
            dh_group: DhGroup::from(initiator.dh_group()),
        };

        initiator.init_from_sa(proposal).unwrap();
        responder.init_from_sa(proposal).unwrap();

        let (peer_key, peer_nonce) = {
            let endpoint = responder.responder();
            (endpoint.public_key.clone(), endpoint.nonce.clone())
        };
        let (our_key, our_nonce) = {
            let endpoint = initiator.initiator();
            (endpoint.public_key.clone(), endpoint.nonce.clone())
        };

        initiator.init_from_ke(peer_key, peer_nonce).unwrap();
        responder.init_from_ke(our_key, our_nonce).unwrap();

        let (a, b) = (initiator.session_keys(), responder.session_keys());
        assert_eq!(a.shared_secret, b.shared_secret);
        assert_eq!(a.skeyseed, b.skeyseed);
        assert_eq!(a.sk_d, b.sk_d);
        assert_eq!(a.sk_ei, b.sk_ei);
        assert_eq!(a.sk_ar, b.sk_ar);
        assert_eq!(a.sk_pi, b.sk_pi);

        // and the SK framing works across them, which only holds if the
        // directional keys were assigned by role
        let request = message(ExchangeType::IkeAuth, Flags::INITIATOR, &initiator);
        let encoded = initiator.new_codec().encode(&request).unwrap();

        assert_eq!(encoded[16], u8::from(PayloadType::Encrypted));

        let decoded = responder.new_codec().decode(&encoded).unwrap().unwrap();
        assert_eq!(decoded.payloads, request.payloads);

        // the same bytes must not decode with the initiator's inbound keys
        assert!(initiator.new_codec().decode(&encoded).is_err());
    }

    /// IKE_SA_INIT travels unprotected and is signed verbatim by the AUTH
    /// payload, so the session keeps both messages as they went over the wire.
    #[test]
    fn test_sa_init_octets_are_recorded() {
        let session = test_session(SessionType::Initiator);
        let mut codec = session.new_codec();

        let request = message(ExchangeType::IkeSaInit, Flags::INITIATOR, &session);
        let encoded = codec.encode(&request).unwrap();

        assert_eq!(session.sa_init_request(), encoded);
        assert!(session.sa_init_response().is_empty());

        let response = message(ExchangeType::IkeSaInit, Flags::RESPONSE, &session);
        let encoded_response = codec.encode(&response).unwrap();
        codec.decode(&encoded_response).unwrap().unwrap();

        assert_eq!(session.sa_init_response(), encoded_response);
        // recording the response must not disturb the request
        assert_eq!(session.sa_init_request(), encoded);

        // an SK-framed exchange is not part of the signed octets
        let session = default_session();
        let mut codec = session.new_codec();
        codec
            .encode(&message(ExchangeType::IkeAuth, Flags::INITIATOR, &session))
            .unwrap();
        assert!(session.sa_init_request().is_empty());
    }

    #[test]
    fn test_set_dh_group_regenerates_the_key_pair() {
        let session = test_session(SessionType::Initiator);
        assert_eq!(session.dh_group(), GroupType::Oakley2);

        let before = session.initiator().public_key.clone();
        assert_eq!(before.len(), 128);

        session.set_dh_group(GroupType::Oakley14).unwrap();

        let after = session.initiator().public_key.clone();
        assert_eq!(session.dh_group(), GroupType::Oakley14);
        assert_eq!(after.len(), 256);
        assert_ne!(before, after);

        // the retry keeps the SA identity: same SPI, same nonce
        let session2 = test_session(SessionType::Initiator);
        let (spi, nonce) = (session2.initiator_spi(), session2.initiator().nonce.clone());
        session2.set_dh_group(GroupType::EcP256).unwrap();
        assert_eq!(session2.initiator_spi(), spi);
        assert_eq!(session2.initiator().nonce, nonce);
    }

    #[test]
    fn test_init_from_sa_rejects_a_group_we_did_not_send() {
        let session = test_session(SessionType::Initiator);

        let mut chosen = proposal(
            &session,
            EncryptionAlgorithm::AesCbc,
            32,
            PseudoRandomFunction::HmacSha256,
            IntegrityAlgorithm::HmacSha256_128,
        );
        chosen.dh_group = DhGroup::Modp2048;

        let err = session.init_from_sa(chosen).unwrap_err().to_string();
        assert!(err.contains("ours was for"), "{err}");
    }

    #[test]
    fn test_init_from_sa_rejects_mismatched_aead_pairing() {
        let session = test_session(SessionType::Initiator);

        // AEAD cipher with an integrity transform
        assert!(
            session
                .init_from_sa(proposal(
                    &session,
                    EncryptionAlgorithm::AesGcm16,
                    32,
                    PseudoRandomFunction::HmacSha256,
                    IntegrityAlgorithm::HmacSha256_128,
                ))
                .is_err()
        );

        // and a CBC cipher without one
        assert!(
            session
                .init_from_sa(proposal(
                    &session,
                    EncryptionAlgorithm::AesCbc,
                    32,
                    PseudoRandomFunction::HmacSha256,
                    IntegrityAlgorithm::None,
                ))
                .is_err()
        );
    }

    #[test]
    fn test_save_load_roundtrip() {
        let session = established(
            EncryptionAlgorithm::AesCbc,
            16,
            PseudoRandomFunction::HmacSha512,
            IntegrityAlgorithm::HmacSha384_192,
        );
        let saved = session.save(&office_mode()).unwrap();

        let loaded = test_session(SessionType::Initiator);
        let restored = loaded.load(&saved).unwrap();

        assert_eq!(restored.ip_address, office_mode().ip_address);
        assert_eq!(restored.ccc_session, office_mode().ccc_session);

        assert_eq!(loaded.initiator_spi(), session.initiator_spi());
        assert_eq!(loaded.responder_spi(), session.responder_spi());
        assert_eq!(loaded.timestamp(), session.timestamp());
        assert_eq!(loaded.integrity(), IntegrityAlgorithm::HmacSha384_192);

        let keys = session.session_keys();
        let loaded_keys = loaded.session_keys();
        assert_eq!(loaded_keys.sk_d, keys.sk_d);
        assert_eq!(loaded_keys.sk_ei, keys.sk_ei);
        assert_eq!(loaded_keys.sk_ar, keys.sk_ar);
        assert_eq!(loaded_keys.sk_pr, keys.sk_pr);

        // the restored session frames exactly where the saved one left off: a
        // peer loading the same store from the other side reads its messages
        let request = message(ExchangeType::IkeAuth, Flags::INITIATOR, &session);
        let encoded = session.new_codec().encode(&request).unwrap();

        let peer = test_session(SessionType::Responder);
        peer.load(&saved).unwrap();

        assert_eq!(
            peer.new_codec().decode(&encoded).unwrap().unwrap().payloads,
            request.payloads
        );

        // while the same role keeps the same direction, and cannot
        assert!(loaded.new_codec().decode(&encoded).is_err());
    }

    #[test]
    fn test_load_rejects_invalid_data() {
        let session = test_session(SessionType::Initiator);
        assert!(session.load(b"not a msgpack session").is_err());
        assert!(session.load(&[]).is_err());
        assert!(!session.is_keyed());
    }

    #[test]
    fn test_unkeyed_session_frames_in_the_clear() {
        let session = test_session(SessionType::Initiator);
        let mut codec = session.new_codec();

        let request = message(ExchangeType::IkeSaInit, Flags::INITIATOR, &session);
        let encoded = codec.encode(&request).unwrap();

        assert_eq!(encoded[16], u8::from(PayloadType::IdentificationInitiator));
        assert_eq!(codec.decode(&encoded).unwrap().unwrap().payloads, request.payloads);

        // an SK payload cannot be read before the key schedule has run
        let session = default_session();
        let sk = session
            .new_codec()
            .encode(&message(ExchangeType::IkeAuth, Flags::INITIATOR, &session))
            .unwrap();

        let unkeyed = test_session(SessionType::Initiator);
        let err = unkeyed.new_codec().decode(&sk).unwrap_err().to_string();
        assert!(err.contains("before the SA is keyed"), "{err}");
    }

    #[test]
    fn test_nonce_satisfies_rfc_7296() {
        let session = test_session(SessionType::Initiator);
        let nonce = session.initiator().nonce.clone();

        assert!(nonce.len() >= 16);
        // at least half the key size of the widest PRF we offer
        assert!(nonce.len() * 2 >= DigestType::Sha512.hash_len());
        assert_ne!(nonce, session.responder().nonce);

        let _ = BasicPayload::new(nonce);
    }
}
