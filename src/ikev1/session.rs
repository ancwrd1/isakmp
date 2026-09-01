use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex, MutexGuard},
    time::SystemTime,
};

use anyhow::{Context, anyhow};
use bytes::Bytes;
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
    session::{EndpointData, IsakmpSession, OfficeMode, SessionType},
};

// RFC 2409 recommended nonce size
const NONCE_SIZE: usize = 32;
const MAX_RECEIVED_HASHES: usize = 1000;

/// IKEv1 key schedule (RFC 2409 §5). IKEv2 derives an entirely different set
/// (`SK_d`, `SK_a{i,r}`, `SK_e{i,r}`, `SK_p{i,r}`) and gets its own type.
#[derive(Default, Clone, Serialize, Deserialize)]
pub struct SessionKeys {
    pub shared_secret: Bytes,
    pub skeyid: Bytes,
    pub skeyid_d: Bytes,
    pub skeyid_a: Bytes,
    pub skeyid_e: Bytes,
}

#[derive(Clone)]
pub struct Ikev1Session(Arc<Mutex<Ikev1SessionImpl>>);

impl Ikev1Session {
    pub fn new(identity: Identity, session_type: SessionType) -> anyhow::Result<Self> {
        Ok(Self(Arc::new(Mutex::new(Ikev1SessionImpl::new(
            identity,
            session_type,
        )?))))
    }

    fn inner(&self) -> MutexGuard<'_, Ikev1SessionImpl> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn init_from_sa(&self, proposal: SaProposal) -> anyhow::Result<()> {
        self.inner().init_from_sa(proposal)
    }

    pub fn init_from_ke(&self, public_key_r: Bytes, nonce_r: Bytes) -> anyhow::Result<()> {
        self.inner().init_from_ke(public_key_r, nonce_r)
    }

    pub fn init_from_qm(&self, proposal: EspProposal) -> anyhow::Result<()> {
        self.inner().init_from_qm(proposal)
    }

    pub fn encrypt_and_set_iv(&self, data: &[u8], id: u32) -> anyhow::Result<Bytes> {
        self.inner().encrypt_and_set_iv(data, id)
    }

    pub fn decrypt_and_set_iv(&self, data: &[u8], id: u32) -> anyhow::Result<Bytes> {
        self.inner().decrypt_and_set_iv(data, id)
    }

    pub fn cipher_block_size(&self) -> usize {
        self.inner().cipher_block_size()
    }

    pub fn validate_message(&self, data: &[u8]) -> anyhow::Result<bool> {
        self.inner().validate_message(data)
    }

    pub fn hash(&self, data: &[&[u8]]) -> anyhow::Result<Bytes> {
        self.inner().hash(data)
    }

    pub fn hash_id_i(&self, data: &[u8]) -> anyhow::Result<Bytes> {
        self.inner().hash_id_i(data)
    }

    pub fn hash_id_r(&self, data: &[u8]) -> anyhow::Result<Bytes> {
        self.inner().hash_id_r(data)
    }

    pub fn verify_signature(&self, hash: &[u8], signature: &[u8], cert: &[u8]) -> anyhow::Result<()> {
        self.inner().verify_signature(hash, signature, cert)
    }

    pub fn prf(&self, key: &[u8], data: &[&[u8]]) -> anyhow::Result<Bytes> {
        self.inner().prf(key, data)
    }

    pub fn session_keys(&self) -> Arc<SessionKeys> {
        self.inner().session_keys()
    }

    pub fn hybrid_auth(&self) -> bool {
        self.inner().hybrid_auth
    }
}

impl IsakmpSession for Ikev1Session {
    fn initiator(&self) -> Arc<EndpointData> {
        self.inner().initiator()
    }

    fn responder(&self) -> Arc<EndpointData> {
        self.inner().responder()
    }

    fn esp_in(&self) -> Arc<EspCryptMaterial> {
        self.inner().esp_in()
    }

    fn esp_out(&self) -> Arc<EspCryptMaterial> {
        self.inner().esp_out()
    }

    fn client_certificate(&self) -> Option<Arc<dyn ClientCertificate + Send + Sync>> {
        self.inner().client_certificate()
    }

    fn load(&self, data: &[u8]) -> anyhow::Result<OfficeMode> {
        self.inner().load(data)
    }

    fn save(&self, office_mode: &OfficeMode) -> anyhow::Result<Vec<u8>> {
        self.inner().save(office_mode)
    }

    fn new_codec(&self) -> Box<dyn IsakmpMessageCodec + Send + Sync> {
        Box::new(Ikev1Codec::new(self.clone()))
    }

    fn timestamp(&self) -> u64 {
        self.inner().timestamp
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
    timestamp: u64,
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
    timestamp: u64,
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
            #[cfg(windows)]
            Identity::System { common_name } => (
                true,
                Some(Arc::new(crate::certs::windows::SystemCertificate::new(&common_name)?)),
            ),
            Identity::None => (false, None),
        };

        let crypto = Crypto::with_parameters(DigestType::Sha256, CipherType::Aes256Cbc, GroupType::Oakley2)?;

        let (spi_i, spi_r) = match session_type {
            SessionType::Initiator => (random(), 0),
            SessionType::Responder => (0, random()),
        };

        Ok(Self {
            session_type,
            hybrid_auth,
            crypto,
            client_cert,
            initiator: Arc::new(EndpointData {
                spi: spi_i,
                nonce: Bytes::copy_from_slice(&random::<[u8; NONCE_SIZE]>()),
                ..Default::default()
            }),
            responder: Arc::new(EndpointData {
                spi: spi_r,
                nonce: Bytes::copy_from_slice(&random::<[u8; NONCE_SIZE]>()),
                ..Default::default()
            }),
            session_keys: Arc::default(),
            iv: HashMap::default(),
            sa_bytes: Bytes::default(),
            received_hashes: VecDeque::new(),
            esp_in: Arc::default(),
            esp_out: Arc::default(),
            timestamp: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_secs(),
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
                    spi: proposal.responder_spi,
                    ..(*self.responder).clone()
                });

                self.initiator = Arc::new(EndpointData {
                    spi: proposal.initiator_spi,
                    public_key: self.crypto.public_key(),
                    ..(*self.initiator).clone()
                });
            }
            SessionType::Responder => {
                self.initiator = Arc::new(EndpointData {
                    spi: proposal.initiator_spi,
                    ..(*self.initiator).clone()
                });

                self.responder = Arc::new(EndpointData {
                    spi: proposal.responder_spi,
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
                    &self.initiator.spi.to_be_bytes(),
                    &self.responder.spi.to_be_bytes(),
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
                &self.initiator.spi.to_be_bytes(),
                &self.responder.spi.to_be_bytes(),
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
                &self.responder.spi.to_be_bytes(),
                &self.initiator.spi.to_be_bytes(),
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
        self.timestamp = store.timestamp;

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
            timestamp: self.timestamp,
        };

        Ok(rmp_serde::to_vec(&store)?)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn office_mode() -> OfficeMode {
        OfficeMode {
            ccc_session: "deadbeef".to_owned(),
            username: "user".to_owned(),
            ip_address: Ipv4Addr::new(10, 0, 0, 2),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            dns: vec![Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(8, 8, 8, 8)],
            domains: vec!["example.com".to_owned(), "vpn.example.com".to_owned()],
        }
    }

    /// Session with a completed phase 1 and phase 2 exchange against a synthetic peer.
    fn established_session(
        hash_alg: IkeHashAlgorithm,
        enc_alg: IkeEncryptionAlgorithm,
        key_len: usize,
        group: IkeGroupDescription,
        peer_group: GroupType,
    ) -> Ikev1Session {
        let session = Ikev1Session::new(Identity::None, SessionType::Initiator).unwrap();

        session
            .init_from_sa(SaProposal {
                initiator_spi: session.initiator_spi(),
                responder_spi: 0x1122334455667788,
                sa_bytes: Bytes::from_static(b"sa bytes"),
                hash_alg,
                enc_alg,
                key_len,
                group,
                ..Default::default()
            })
            .unwrap();

        // synthetic responder KE payload
        let peer = Crypto::with_parameters(DigestType::Sha256, CipherType::Aes256Cbc, peer_group).unwrap();

        session
            .init_from_ke(peer.public_key(), Bytes::from_static(&[0x42; NONCE_SIZE]))
            .unwrap();

        session
            .init_from_qm(EspProposal {
                spi_i: 0xaabbccdd,
                nonce_i: Bytes::from_static(&[1; NONCE_SIZE]),
                spi_r: 0x11223344,
                nonce_r: Bytes::from_static(&[2; NONCE_SIZE]),
                transform_id: TransformId::EspAesCbc,
                auth_alg: EspAuthAlgorithm::HmacSha256v2,
                key_len: 32,
            })
            .unwrap();

        session
    }

    fn default_session() -> Ikev1Session {
        established_session(
            IkeHashAlgorithm::Sha256,
            IkeEncryptionAlgorithm::AesCbc,
            32,
            IkeGroupDescription::Oakley2,
            GroupType::Oakley2,
        )
    }

    #[test]
    fn test_save_load_roundtrip() {
        let session = default_session();
        let saved = session.save(&office_mode()).unwrap();

        let loaded = Ikev1Session::new(Identity::None, SessionType::Initiator).unwrap();
        let restored = loaded.load(&saved).unwrap();

        let om = office_mode();
        assert_eq!(restored.ccc_session, om.ccc_session);
        assert_eq!(restored.username, om.username);
        assert_eq!(restored.ip_address, om.ip_address);
        assert_eq!(restored.netmask, om.netmask);
        assert_eq!(restored.dns, om.dns);
        assert_eq!(restored.domains, om.domains);

        assert_eq!(loaded.initiator_spi(), session.initiator_spi());
        assert_eq!(loaded.responder_spi(), session.responder_spi());
        assert_eq!(loaded.initiator().nonce, session.initiator().nonce);
        assert_eq!(loaded.initiator().public_key, session.initiator().public_key);
        assert_eq!(loaded.initiator().esp_spi, session.initiator().esp_spi);
        assert_eq!(loaded.initiator().esp_nonce, session.initiator().esp_nonce);
        assert_eq!(loaded.responder().nonce, session.responder().nonce);
        assert_eq!(loaded.responder().public_key, session.responder().public_key);
        assert_eq!(loaded.responder().esp_spi, session.responder().esp_spi);
        assert_eq!(loaded.responder().esp_nonce, session.responder().esp_nonce);
        assert_eq!(loaded.timestamp(), session.timestamp());

        let keys = session.session_keys();
        let loaded_keys = loaded.session_keys();
        assert_eq!(loaded_keys.shared_secret, keys.shared_secret);
        assert_eq!(loaded_keys.skeyid, keys.skeyid);
        assert_eq!(loaded_keys.skeyid_d, keys.skeyid_d);
        assert_eq!(loaded_keys.skeyid_a, keys.skeyid_a);
        assert_eq!(loaded_keys.skeyid_e, keys.skeyid_e);
    }

    #[test]
    fn test_load_restores_crypto_parameters() {
        let session = established_session(
            IkeHashAlgorithm::Sha512,
            IkeEncryptionAlgorithm::AesCbc,
            16,
            IkeGroupDescription::Oakley14,
            GroupType::Oakley14,
        );
        let saved = session.save(&office_mode()).unwrap();

        // the fresh session defaults to SHA256/AES256/Oakley2, so any match must come from the store
        let loaded = Ikev1Session::new(Identity::None, SessionType::Initiator).unwrap();
        loaded.load(&saved).unwrap();

        assert_eq!(loaded.cipher_block_size(), session.cipher_block_size());
        assert_eq!(loaded.hash(&[b"data"]).unwrap().len(), 64);
        assert_eq!(loaded.hash(&[b"data"]).unwrap(), session.hash(&[b"data"]).unwrap());
        assert_eq!(loaded.session_keys().skeyid_e.len(), 16);
    }

    #[test]
    fn test_load_restores_iv_state() {
        let session = default_session();
        let data = [7u8; 32];

        // saved with only the phase 1 zero IV in place
        let saved_before = session.save(&office_mode()).unwrap();

        let encrypted = session.encrypt_and_set_iv(&data, 1).unwrap();

        // a session restored from that point derives the same per-message IV
        let loaded_before = Ikev1Session::new(Identity::None, SessionType::Initiator).unwrap();
        loaded_before.load(&saved_before).unwrap();
        assert_eq!(loaded_before.decrypt_and_set_iv(&encrypted, 1).unwrap(), Bytes::copy_from_slice(&data));

        // saved after the IV of message 1 has been advanced by the encryption
        let saved_after = session.save(&office_mode()).unwrap();

        let loaded_after = Ikev1Session::new(Identity::None, SessionType::Initiator).unwrap();
        loaded_after.load(&saved_after).unwrap();

        // both sessions must produce the same next ciphertext for the same message id
        assert_eq!(
            loaded_after.encrypt_and_set_iv(&data, 1).unwrap(),
            session.encrypt_and_set_iv(&data, 1).unwrap()
        );

        // and an unseen message id still derives its IV from the restored zero IV
        assert_eq!(
            loaded_after.encrypt_and_set_iv(&data, 2).unwrap(),
            loaded_before.encrypt_and_set_iv(&data, 2).unwrap()
        );
    }

    #[test]
    fn test_load_restores_received_hashes() {
        let session = default_session();

        assert!(session.validate_message(b"first message").unwrap());
        assert!(!session.validate_message(b"first message").unwrap());

        let saved = session.save(&office_mode()).unwrap();

        let loaded = Ikev1Session::new(Identity::None, SessionType::Initiator).unwrap();
        loaded.load(&saved).unwrap();

        assert!(!loaded.validate_message(b"first message").unwrap());
        assert!(loaded.validate_message(b"second message").unwrap());
    }

    #[test]
    fn test_load_restores_sa_bytes() {
        let session = default_session();
        let saved = session.save(&office_mode()).unwrap();

        let loaded = Ikev1Session::new(Identity::None, SessionType::Initiator).unwrap();
        loaded.load(&saved).unwrap();

        // HASH_I/HASH_R fold in SA bytes, SPIs, public keys and SKEYID
        assert_eq!(loaded.hash_id_i(b"id").unwrap(), session.hash_id_i(b"id").unwrap());
        assert_eq!(loaded.hash_id_r(b"id").unwrap(), session.hash_id_r(b"id").unwrap());
    }

    #[test]
    fn test_load_rejects_invalid_data() {
        let session = Ikev1Session::new(Identity::None, SessionType::Initiator).unwrap();
        assert!(session.load(b"not a msgpack session").is_err());
        assert!(session.load(&[]).is_err());
    }

    #[test]
    fn test_load_rejects_truncated_data() {
        let session = default_session();
        let saved = session.save(&office_mode()).unwrap();

        let loaded = Ikev1Session::new(Identity::None, SessionType::Initiator).unwrap();
        assert!(loaded.load(&saved[..saved.len() / 2]).is_err());
    }

    #[test]
    fn test_save_does_not_persist_esp_material() {
        // ESP keys are re-derived by a fresh quick mode after a reconnect
        let session = default_session();
        assert!(!session.esp_in().sk_e.is_empty());

        let saved = session.save(&office_mode()).unwrap();

        let loaded = Ikev1Session::new(Identity::None, SessionType::Initiator).unwrap();
        loaded.load(&saved).unwrap();

        assert!(loaded.esp_in().sk_e.is_empty());
        assert!(loaded.esp_out().sk_e.is_empty());
    }
}
