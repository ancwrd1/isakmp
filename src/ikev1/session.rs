use std::{collections::HashMap, sync::Arc};

use crate::{
    certs::{ClientCertificate, Pkcs11Certificate, Pkcs8Certificate},
    crypto::{CipherType, Crypto, DigestType, GroupType},
    model::*,
    session::{EndpointData, IsakmpSession, SessionKeys},
};
use anyhow::anyhow;
use bytes::Bytes;
use parking_lot::RwLock;
use rand::random;
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct Ikev1Session(Arc<RwLock<Ikev1SessionImpl>>);

impl Ikev1Session {
    pub fn new(identity: Identity) -> anyhow::Result<Self> {
        Ok(Self(Arc::new(RwLock::new(Ikev1SessionImpl::new(identity)?))))
    }

    pub fn load<T>(&mut self, data: T) -> anyhow::Result<()>
    where
        T: AsRef<[u8]>,
    {
        self.0.write().load(data)
    }

    pub fn save(&self) -> anyhow::Result<Vec<u8>> {
        self.0.write().save()
    }
}

impl IsakmpSession for Ikev1Session {
    fn init_from_sa(
        &mut self,
        cookie_r: u64,
        sa_bytes: Bytes,
        hash_alg: IkeHashAlgorithm,
        key_len: usize,
        group: IkeGroupDescription,
    ) -> anyhow::Result<()> {
        self.0
            .write()
            .init_from_sa(cookie_r, sa_bytes, hash_alg, key_len, group)
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

    fn validate_message(&mut self, data: &[u8]) -> bool {
        self.0.write().validate_message(data)
    }

    fn hash<T, I>(&self, data: I) -> anyhow::Result<Bytes>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
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

    fn prf<T, I>(&self, key: &[u8], data: I) -> anyhow::Result<Bytes>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
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
}

#[derive(Serialize, Deserialize)]
struct Ikev1SessionStore {
    initiator: Arc<EndpointData>,
    responder: Arc<EndpointData>,
    session_keys: Arc<SessionKeys>,
    iv: HashMap<u32, Bytes>,
    sa_bytes: Bytes,
    received_hashes: Vec<Bytes>,
}

struct Ikev1SessionImpl {
    crypto: Crypto,
    client_cert: Option<Arc<dyn ClientCertificate + Send + Sync>>,
    initiator: Arc<EndpointData>,
    responder: Arc<EndpointData>,
    session_keys: Arc<SessionKeys>,
    iv: HashMap<u32, Bytes>,
    sa_bytes: Bytes,
    received_hashes: Vec<Bytes>,
    esp_in: Arc<EspCryptMaterial>,
    esp_out: Arc<EspCryptMaterial>,
}

impl Ikev1SessionImpl {
    fn new(identity: Identity) -> anyhow::Result<Self> {
        let client_cert: Option<Arc<dyn ClientCertificate + Send + Sync>> = match identity {
            Identity::Pkcs12 { path, password } => Some(Arc::new(Pkcs8Certificate::from_pkcs12(&path, &password)?)),
            Identity::Pkcs8 { path } => Some(Arc::new(Pkcs8Certificate::from_pkcs8(&path)?)),
            Identity::Pkcs11 {
                driver_path,
                pin,
                key_id,
            } => Some(Arc::new(Pkcs11Certificate::new(driver_path, pin, key_id)?)),
            Identity::None => None,
        };

        let crypto = Crypto::with_parameters(DigestType::Sha256, CipherType::Aes256Cbc, GroupType::Oakley2)?;

        Ok(Self {
            crypto,
            client_cert,
            initiator: Arc::new(EndpointData {
                cookie: random(),
                nonce: Bytes::copy_from_slice(&random::<[u8; 32]>()),
                ..Default::default()
            }),
            responder: Arc::default(),
            session_keys: Arc::default(),
            iv: HashMap::default(),
            sa_bytes: Bytes::default(),
            received_hashes: Vec::new(),
            esp_in: Arc::default(),
            esp_out: Arc::default(),
        })
    }

    fn load<T>(&mut self, data: T) -> anyhow::Result<()>
    where
        T: AsRef<[u8]>,
    {
        let store = rmp_serde::from_slice::<Ikev1SessionStore>(data.as_ref())?;

        self.initiator = store.initiator;
        self.responder = store.responder;
        self.session_keys = store.session_keys;
        self.iv = store.iv;
        self.sa_bytes = store.sa_bytes;
        self.received_hashes = store.received_hashes;

        Ok(())
    }

    fn save(&self) -> anyhow::Result<Vec<u8>> {
        let store = Ikev1SessionStore {
            initiator: self.initiator.clone(),
            responder: self.responder.clone(),
            session_keys: self.session_keys.clone(),
            iv: self.iv.clone(),
            sa_bytes: self.sa_bytes.clone(),
            received_hashes: self.received_hashes.clone(),
        };

        Ok(rmp_serde::to_vec(&store)?)
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
            key_length,
            auth_algorithm,
        })
    }

    pub fn retrieve_iv(&mut self, message_id: u32) -> Bytes {
        let zero_iv = self.iv[&0].clone();
        self.iv
            .entry(message_id)
            .or_insert_with(|| {
                let mut hash = self.crypto.hash([zero_iv.as_ref(), &message_id.to_be_bytes()]).unwrap();
                hash.truncate(self.crypto.block_size());
                hash
            })
            .clone()
    }
}

impl IsakmpSession for Ikev1SessionImpl {
    fn init_from_sa(
        &mut self,
        cookie_r: u64,
        sa_bytes: Bytes,
        hash_alg: IkeHashAlgorithm,
        key_len: usize,
        group: IkeGroupDescription,
    ) -> anyhow::Result<()> {
        self.sa_bytes = sa_bytes;

        let digest = match hash_alg {
            IkeHashAlgorithm::Sha => DigestType::Sha1,
            IkeHashAlgorithm::Sha256 => DigestType::Sha256,
            _ => return Err(anyhow!("Unsupported hash algorithm: {:?}", hash_alg)),
        };

        let cipher = key_len.try_into()?;

        let group = match group {
            IkeGroupDescription::Oakley2 => GroupType::Oakley2,
            IkeGroupDescription::Oakley14 => GroupType::Oakley14,
            IkeGroupDescription::Other(_) => return Err(anyhow!("Unsupported group: {:?}", group)),
        };

        self.crypto = Crypto::with_parameters(digest, cipher, group)?;

        self.responder = Arc::new(EndpointData {
            cookie: cookie_r,
            ..(*self.responder).clone()
        });

        self.initiator = Arc::new(EndpointData {
            public_key: self.crypto.public_key(),
            ..(*self.initiator).clone()
        });

        Ok(())
    }

    fn init_from_ke(&mut self, public_key_r: Bytes, nonce_r: Bytes) -> anyhow::Result<()> {
        self.responder = Arc::new(EndpointData {
            public_key: public_key_r,
            nonce: nonce_r,
            ..(*self.responder).clone()
        });

        self.session_keys = Arc::new(SessionKeys {
            shared_secret: self.crypto.shared_secret(&self.responder.public_key)?,
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
        let iv = self.retrieve_iv(id);

        let encrypted = self.crypto.encrypt(&self.session_keys.skeyid_e, data, &iv)?;

        self.iv.insert(
            id,
            Bytes::copy_from_slice(&encrypted[encrypted.len() - self.crypto.block_size()..]),
        );

        Ok(encrypted)
    }

    fn decrypt_and_set_iv(&mut self, data: &[u8], id: u32) -> anyhow::Result<Bytes> {
        let iv = self.retrieve_iv(id);

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

    fn validate_message(&mut self, data: &[u8]) -> bool {
        let hash = self.hash([data]).expect("Hash computation should not fail");
        if self.received_hashes.contains(&hash) {
            false
        } else {
            self.received_hashes.push(hash);
            true
        }
    }

    fn hash<T, I>(&self, data: I) -> anyhow::Result<Bytes>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
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

    fn prf<T, I>(&self, key: &[u8], data: I) -> anyhow::Result<Bytes>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
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
}
