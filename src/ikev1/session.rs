use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
};

use anyhow::{Context, anyhow};
use bytes::Bytes;
use parking_lot::RwLock;
use rand::random;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::{
    certs::{ClientCertificate, Pkcs8Certificate, Pkcs11Certificate},
    crypto::{CipherType, Crypto, DigestType, GroupType},
    ikev1::codec::Ikev1Codec,
    message::IsakmpMessageCodec,
    model::*,
    session::{EndpointData, IsakmpSession, OfficeMode, SessionKeys, SessionType},
};

// RFC 2409 recommended nonce size
const NONCE_SIZE: usize = 32;
const MAX_RECEIVED_HASHES: usize = 1000;

#[derive(Clone)]
pub struct Ikev1Session(Arc<RwLock<Ikev1SessionImpl>>);

impl Ikev1Session {
    pub fn new(identity: Identity, session_type: SessionType) -> anyhow::Result<Self> {
        Ok(Self(Arc::new(RwLock::new(Ikev1SessionImpl::new(
            identity,
            session_type,
        )?))))
    }
}

impl IsakmpSession for Ikev1Session {
    fn init_from_sa(&mut self, proposal: SaProposal) -> anyhow::Result<()> {
        self.0.write().init_from_sa(proposal)
    }

    fn init_from_ke(&mut self, public_key_r: Bytes, nonce_r: Bytes) -> anyhow::Result<()> {
        self.0.write().init_from_ke(public_key_r, nonce_r)
    }

    fn init_from_qm(&mut self, proposal: EspProposal) -> anyhow::Result<()> {
        self.0.write().init_from_qm(proposal)
    }

    fn encrypt_and_set_iv(&mut self, data: &[u8], id: u32) -> anyhow::Result<Bytes> {
        self.0.write().encrypt_and_set_iv(data, id)
    }

    fn decrypt_and_set_iv(&mut self, data: &[u8], id: u32) -> anyhow::Result<Bytes> {
        self.0.write().decrypt_and_set_iv(data, id)
    }

    fn cipher_block_size(&self) -> usize {
        self.0.read().cipher_block_size()
    }

    fn validate_message(&mut self, data: &[u8]) -> anyhow::Result<bool> {
        self.0.write().validate_message(data)
    }

    fn hash(&self, data: &[&[u8]]) -> anyhow::Result<Bytes> {
        self.0.read().hash(data)
    }

    fn hash_id_i(&self, data: &[u8]) -> anyhow::Result<Bytes> {
        self.0.read().hash_id_i(data)
    }

    fn hash_id_r(&self, data: &[u8]) -> anyhow::Result<Bytes> {
        self.0.read().hash_id_r(data)
    }

    fn verify_signature(&self, hash: &[u8], signature: &[u8], cert: &[u8]) -> anyhow::Result<()> {
        self.0.read().verify_signature(hash, signature, cert)
    }

    fn prf(&self, key: &[u8], data: &[&[u8]]) -> anyhow::Result<Bytes> {
        self.0.read().prf(key, data)
    }

    fn esp_in(&self) -> Arc<EspCryptMaterial> {
        self.0.read().esp_in()
    }

    fn esp_out(&self) -> Arc<EspCryptMaterial> {
        self.0.read().esp_out()
    }

    fn client_certificate(&self) -> Option<Arc<dyn ClientCertificate + Send + Sync>> {
        self.0.read().client_certificate()
    }

    fn initiator(&self) -> Arc<EndpointData> {
        self.0.read().initiator()
    }

    fn responder(&self) -> Arc<EndpointData> {
        self.0.read().responder()
    }

    fn session_keys(&self) -> Arc<SessionKeys> {
        self.0.read().session_keys()
    }

    fn load(&mut self, data: &[u8]) -> anyhow::Result<OfficeMode> {
        self.0.write().load(data)
    }

    fn save(&self, office_mode: &OfficeMode) -> anyhow::Result<Vec<u8>> {
        self.0.write().save(office_mode)
    }

    fn new_codec(&self) -> Box<dyn IsakmpMessageCodec + Send + Sync> {
        Box::new(Ikev1Codec::new(Box::new(self.clone())))
    }

    fn hybrid_auth(&self) -> bool {
        self.0.read().hybrid_auth
    }
}

#[derive(Serialize, Deserialize)]
struct Ikev1SessionStore {
    initiator: Arc<EndpointData>,
    responder: Arc<EndpointData>,
    session_keys: Arc<SessionKeys>,
    iv: HashMap<u32, Bytes>,
    sa_bytes: Bytes,
    received_hashes: VecDeque<Bytes>,
    office_mode: OfficeMode,
    digest_type: DigestType,
    cipher_type: CipherType,
    group_type: GroupType,
}

struct Ikev1SessionImpl {
    session_type: SessionType,
    hybrid_auth: bool,
    crypto: Crypto,
    client_cert: Option<Arc<dyn ClientCertificate + Send + Sync>>,
    initiator: Arc<EndpointData>,
    responder: Arc<EndpointData>,
    session_keys: Arc<SessionKeys>,
    iv: HashMap<u32, Bytes>,
    sa_bytes: Bytes,
    received_hashes: VecDeque<Bytes>,
    esp_in: Arc<EspCryptMaterial>,
    esp_out: Arc<EspCryptMaterial>,
}

impl Ikev1SessionImpl {
    fn new(identity: Identity, session_type: SessionType) -> anyhow::Result<Self> {
        let (hybrid_auth, client_cert): (bool, Option<Arc<dyn ClientCertificate + Send + Sync>>) = match identity {
            Identity::Pkcs12 {
                data,
                password,
                hybrid_auth,
            } => (
                hybrid_auth,
                Some(Arc::new(Pkcs8Certificate::from_pkcs12(
                    &data,
                    password.expose_secret(),
                )?)),
            ),
            Identity::Pkcs8 { path, hybrid_auth } => {
                (hybrid_auth, Some(Arc::new(Pkcs8Certificate::from_pkcs8(&path)?)))
            }
            Identity::Pkcs11 {
                driver_path,
                pin,
                key_id,
                hybrid_auth,
            } => (
                hybrid_auth,
                Some(Arc::new(Pkcs11Certificate::new(driver_path, pin, key_id)?)),
            ),
            Identity::None => (false, None),
        };

        let crypto = Crypto::with_parameters(DigestType::Sha256, CipherType::Aes256Cbc, GroupType::Oakley2)?;

        let (cookie_i, cookie_r) = match session_type {
            SessionType::Initiator => (random(), 0),
            SessionType::Responder => (0, random()),
        };

        Ok(Self {
            session_type,
            hybrid_auth,
            crypto,
            client_cert,
            initiator: Arc::new(EndpointData {
                cookie: cookie_i,
                nonce: Bytes::copy_from_slice(&random::<[u8; NONCE_SIZE]>()),
                ..Default::default()
            }),
            responder: Arc::new(EndpointData {
                cookie: cookie_r,
                nonce: Bytes::copy_from_slice(&random::<[u8; NONCE_SIZE]>()),
                ..Default::default()
            }),
            session_keys: Arc::default(),
            iv: HashMap::default(),
            sa_bytes: Bytes::default(),
            received_hashes: VecDeque::new(),
            esp_in: Arc::default(),
            esp_out: Arc::default(),
        })
    }

    fn gen_esp_material(
        &mut self,
        spi: u32,
        transform_id: TransformId,
        auth_algorithm: EspAuthAlgorithm,
        key_length: usize,
    ) -> anyhow::Result<EspCryptMaterial> {
        let keymat_len = key_length + auth_algorithm.key_len();

        let mut data = Vec::new();
        let mut seed = Bytes::new();
        while data.len() < keymat_len {
            seed = self.crypto.prf(
                &self.session_keys.skeyid_d,
                [
                    seed.as_ref(),
                    &[3],
                    spi.to_be_bytes().as_slice(),
                    &self.initiator.esp_nonce,
                    &self.responder.esp_nonce,
                ],
            )?;
            data.extend(&seed);
        }

        let sk_e = Bytes::copy_from_slice(&data[0..key_length]);
        let sk_a = Bytes::copy_from_slice(&data[key_length..keymat_len]);

        Ok(EspCryptMaterial {
            spi,
            sk_e,
            sk_a,
            transform_id,
            auth_algorithm,
        })
    }

    fn retrieve_iv(&mut self, message_id: u32) -> anyhow::Result<Bytes> {
        let zero_iv = self.iv.get(&0).context("Session IV not initialized")?.clone();

        Ok(self
            .iv
            .entry(message_id)
            .or_insert_with(|| {
                let mut hash = self.crypto.hash([zero_iv.as_ref(), &message_id.to_be_bytes()]).unwrap();
                hash.truncate(self.crypto.block_size());
                hash
            })
            .clone())
    }

    fn init_from_sa(&mut self, proposal: SaProposal) -> anyhow::Result<()> {
        self.sa_bytes = proposal.sa_bytes;

        let digest = match proposal.hash_alg {
            IkeHashAlgorithm::Md5 => DigestType::Md5,
            IkeHashAlgorithm::Sha => DigestType::Sha1,
            IkeHashAlgorithm::Sha256 => DigestType::Sha256,
            IkeHashAlgorithm::Sha384 => DigestType::Sha384,
            IkeHashAlgorithm::Sha512 => DigestType::Sha512,
            _ => return Err(anyhow!("Unsupported hash algorithm: {:?}", proposal.hash_alg)),
        };

        if digest.is_deprecated() {
            warn!("Using deprecated hash algorithm: {:?}", digest);
        }

        let cipher = CipherType::new_for_ike(proposal.enc_alg, proposal.key_len)?;

        let group = match proposal.group {
            IkeGroupDescription::Oakley2 => GroupType::Oakley2,
            IkeGroupDescription::Oakley14 => GroupType::Oakley14,
            IkeGroupDescription::Other(_) => return Err(anyhow!("Unsupported group: {:?}", proposal.group)),
        };

        self.crypto = Crypto::with_parameters(digest, cipher, group)?;

        match self.session_type {
            SessionType::Initiator => {
                self.responder = Arc::new(EndpointData {
                    cookie: proposal.cookie_r,
                    ..(*self.responder).clone()
                });

                self.initiator = Arc::new(EndpointData {
                    cookie: proposal.cookie_i,
                    public_key: self.crypto.public_key(),
                    ..(*self.initiator).clone()
                });
            }
            SessionType::Responder => {
                self.initiator = Arc::new(EndpointData {
                    cookie: proposal.cookie_i,
                    ..(*self.initiator).clone()
                });

                self.responder = Arc::new(EndpointData {
                    cookie: proposal.cookie_r,
                    public_key: self.crypto.public_key(),
                    ..(*self.responder).clone()
                });
            }
        }

        Ok(())
    }

    fn init_from_ke(&mut self, public_key_r: Bytes, nonce_r: Bytes) -> anyhow::Result<()> {
        let key = match self.session_type {
            SessionType::Initiator => {
                self.responder = Arc::new(EndpointData {
                    public_key: public_key_r,
                    nonce: nonce_r,
                    ..(*self.responder).clone()
                });
                &self.responder.public_key
            }
            SessionType::Responder => {
                self.initiator = Arc::new(EndpointData {
                    public_key: public_key_r,
                    nonce: nonce_r,
                    ..(*self.initiator).clone()
                });
                &self.initiator.public_key
            }
        };

        self.session_keys = Arc::new(SessionKeys {
            shared_secret: self.crypto.shared_secret(key)?,
            ..(*self.session_keys).clone()
        });

        let key = self
            .initiator
            .nonce
            .iter()
            .chain(self.responder.nonce.iter())
            .copied()
            .collect::<Bytes>();

        // RFC2409: SKEYID = prf(Ni_b | Nr_b, g^xy)
        let skeyid = self.crypto.prf(&key, [&self.session_keys.shared_secret])?;

        let mut data = Vec::new();
        let mut seed = Bytes::new();

        // SKEYID_{d,a,e}
        for i in 0..3 {
            seed = self.crypto.prf(
                &skeyid,
                [
                    seed.as_ref(),
                    self.session_keys.shared_secret.as_ref(),
                    &self.initiator.cookie.to_be_bytes(),
                    &self.responder.cookie.to_be_bytes(),
                    &[i],
                ],
            )?;
            data.extend(&seed);
        }

        let hash_len = self.crypto.hash_len();

        let skeyid_d = Bytes::copy_from_slice(&data[0..hash_len]);
        let skeyid_a = Bytes::copy_from_slice(&data[hash_len..hash_len * 2]);
        let mut skeyid_e = Bytes::copy_from_slice(&data[hash_len * 2..]);

        if skeyid_e.len() < self.crypto.key_len() {
            let mut data = Vec::new();
            let mut seed = Bytes::from_static(&[0]);
            while data.len() < self.crypto.key_len() {
                seed = self.crypto.prf(&skeyid_e, [seed.as_ref()])?;
                data.extend(&seed);
            }
            data.truncate(self.crypto.key_len());
            skeyid_e = data.into();
        } else {
            skeyid_e.truncate(self.crypto.key_len());
        }

        self.session_keys = Arc::new(SessionKeys {
            skeyid,
            skeyid_d,
            skeyid_a,
            skeyid_e,
            ..(*self.session_keys).clone()
        });

        let mut iv = self
            .crypto
            .hash([&self.initiator.public_key, &self.responder.public_key])?;
        iv.truncate(self.crypto.block_size());

        self.iv.insert(0, iv);

        Ok(())
    }

    fn init_from_qm(&mut self, proposal: EspProposal) -> anyhow::Result<()> {
        self.initiator = Arc::new(EndpointData {
            esp_spi: proposal.spi_i,
            esp_nonce: proposal.nonce_i,
            ..(*self.initiator).clone()
        });

        self.responder = Arc::new(EndpointData {
            esp_spi: proposal.spi_r,
            esp_nonce: proposal.nonce_r,
            ..(*self.responder).clone()
        });

        self.esp_in = Arc::new(self.gen_esp_material(
            self.initiator.esp_spi,
            proposal.transform_id,
            proposal.auth_alg,
            proposal.key_len,
        )?);
        self.esp_out = Arc::new(self.gen_esp_material(
            self.responder.esp_spi,
            proposal.transform_id,
            proposal.auth_alg,
            proposal.key_len,
        )?);

        Ok(())
    }

    fn encrypt_and_set_iv(&mut self, data: &[u8], id: u32) -> anyhow::Result<Bytes> {
        let iv = self.retrieve_iv(id)?;

        let encrypted = self.crypto.encrypt(&self.session_keys.skeyid_e, data, &iv)?;

        self.iv.insert(
            id,
            Bytes::copy_from_slice(&encrypted[encrypted.len() - self.crypto.block_size()..]),
        );

        Ok(encrypted)
    }

    fn decrypt_and_set_iv(&mut self, data: &[u8], id: u32) -> anyhow::Result<Bytes> {
        let iv = self.retrieve_iv(id)?;

        let decrypted = self.crypto.decrypt(&self.session_keys.skeyid_e, data, &iv)?;

        self.iv.insert(
            id,
            Bytes::copy_from_slice(&data[data.len() - self.crypto.block_size()..]),
        );

        Ok(decrypted)
    }

    fn cipher_block_size(&self) -> usize {
        self.crypto.block_size()
    }

    fn validate_message(&mut self, data: &[u8]) -> anyhow::Result<bool> {
        let hash = self.hash(&[data])?;
        if self.received_hashes.contains(&hash) {
            return Ok(false);
        }
        if self.received_hashes.len() >= MAX_RECEIVED_HASHES {
            self.received_hashes.pop_front();
        }
        self.received_hashes.push_back(hash);
        Ok(true)
    }

    fn hash(&self, data: &[&[u8]]) -> anyhow::Result<Bytes> {
        self.crypto.hash(data)
    }

    fn hash_id_i(&self, data: &[u8]) -> anyhow::Result<Bytes> {
        // RFC2409: HASH_I = prf(SKEYID, g^xi | g^xr | CKY-I | CKY-R | SAi_b | IDii_b )
        self.crypto.prf(
            &self.session_keys.skeyid,
            [
                self.initiator.public_key.as_ref(),
                self.responder.public_key.as_ref(),
                &self.initiator.cookie.to_be_bytes(),
                &self.responder.cookie.to_be_bytes(),
                self.sa_bytes.as_ref(),
                data,
            ],
        )
    }

    fn hash_id_r(&self, data: &[u8]) -> anyhow::Result<Bytes> {
        // RFC2409: HASH_R = prf(SKEYID, g^xr | g^xi | CKY-R | CKY-I | SAi_b | IDir_b )
        self.crypto.prf(
            &self.session_keys.skeyid,
            [
                self.responder.public_key.as_ref(),
                self.initiator.public_key.as_ref(),
                &self.responder.cookie.to_be_bytes(),
                &self.initiator.cookie.to_be_bytes(),
                self.sa_bytes.as_ref(),
                data,
            ],
        )
    }

    fn verify_signature(&self, hash: &[u8], signature: &[u8], cert: &[u8]) -> anyhow::Result<()> {
        self.crypto.verify_signature(hash, signature, cert)
    }

    fn prf(&self, key: &[u8], data: &[&[u8]]) -> anyhow::Result<Bytes> {
        self.crypto.prf(key, data)
    }

    fn esp_in(&self) -> Arc<EspCryptMaterial> {
        self.esp_in.clone()
    }

    fn esp_out(&self) -> Arc<EspCryptMaterial> {
        self.esp_out.clone()
    }

    fn client_certificate(&self) -> Option<Arc<dyn ClientCertificate + Send + Sync>> {
        self.client_cert.clone()
    }

    fn initiator(&self) -> Arc<EndpointData> {
        self.initiator.clone()
    }

    fn responder(&self) -> Arc<EndpointData> {
        self.responder.clone()
    }

    fn session_keys(&self) -> Arc<SessionKeys> {
        self.session_keys.clone()
    }

    fn load(&mut self, data: &[u8]) -> anyhow::Result<OfficeMode> {
        let store = rmp_serde::from_slice::<Ikev1SessionStore>(data)?;

        self.initiator = store.initiator;
        self.responder = store.responder;
        self.session_keys = store.session_keys;
        self.iv = store.iv;
        self.sa_bytes = store.sa_bytes;
        self.received_hashes = store.received_hashes;
        self.crypto = Crypto::with_parameters(store.digest_type, store.cipher_type, store.group_type)?;

        Ok(store.office_mode)
    }

    fn save(&self, office_mode: &OfficeMode) -> anyhow::Result<Vec<u8>> {
        let store = Ikev1SessionStore {
            initiator: self.initiator.clone(),
            responder: self.responder.clone(),
            session_keys: self.session_keys.clone(),
            iv: self.iv.clone(),
            sa_bytes: self.sa_bytes.clone(),
            received_hashes: self.received_hashes.clone(),
            office_mode: office_mode.clone(),
            digest_type: self.crypto.digest_type(),
            cipher_type: self.crypto.cipher_type(),
            group_type: self.crypto.group_type(),
        };

        Ok(rmp_serde::to_vec(&store)?)
    }
}
