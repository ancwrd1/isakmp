use std::{collections::HashMap, sync::Arc};

use anyhow::anyhow;
use bytes::Bytes;
use parking_lot::RwLock;
use rand::random;

use crate::model::{EspProposal, TransformId};
use crate::{
    certs::ClientCertificate,
    crypto::{CipherType, Crypto, DigestType, GroupType},
    model::{EspAuthAlgorithm, EspCryptMaterial, Identity, IkeGroupDescription, IkeHashAlgorithm},
    session::{EndpointData, IsakmpSession, SessionKeys},
};

type Ikev1SessionRef = Arc<RwLock<Ikev1Session>>;

#[derive(Clone)]
pub struct Ikev1SyncedSession(Ikev1SessionRef);

impl Ikev1SyncedSession {
    pub fn new(identity: Identity) -> anyhow::Result<Self> {
        Ok(Self(Arc::new(RwLock::new(Ikev1Session::new(identity)?))))
    }

    pub fn init_from_sa(
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

    pub fn init_from_ke(&mut self, public_key_r: Bytes, nonce_r: Bytes) -> anyhow::Result<()> {
        self.0.write().init_from_ke(public_key_r, nonce_r)
    }

    pub fn init_from_qm(&mut self, proposal: EspProposal) -> anyhow::Result<()> {
        self.0.write().init_from_qm(proposal)
    }
}

impl IsakmpSession for Ikev1SyncedSession {
    fn encrypt_and_set_iv(&mut self, data: &[u8], id: u32) -> anyhow::Result<Bytes> {
        self.0.write().encrypt_and_set_iv(data, id)
    }

    fn decrypt_and_set_iv(&mut self, data: &[u8], id: u32) -> anyhow::Result<Bytes> {
        self.0.write().decrypt_and_set_iv(data, id)
    }

    fn cipher_block_size(&self) -> usize {
        self.0.read().cipher_block_size()
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

    fn verify(&self, hash: &[u8], signature: &[u8], cert: &[u8]) -> anyhow::Result<()> {
        self.0.read().verify(hash, signature, cert)
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

struct Ikev1Session {
    identity: Identity,
    crypto: Crypto,
    initiator: Arc<EndpointData>,
    responder: Arc<EndpointData>,
    session_keys: Arc<SessionKeys>,
    iv: HashMap<u32, Bytes>,
    sa_bytes: Bytes,
    esp_in: Arc<EspCryptMaterial>,
    esp_out: Arc<EspCryptMaterial>,
}

impl IsakmpSession for Ikev1Session {
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

    fn verify(&self, hash: &[u8], signature: &[u8], cert: &[u8]) -> anyhow::Result<()> {
        self.crypto.verify(hash, signature, cert)
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
        self.crypto.client_certificate()
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

impl Ikev1Session {
    fn new(identity: Identity) -> anyhow::Result<Self> {
        let crypto = Crypto::with_parameters(
            identity.clone(),
            DigestType::Sha256,
            CipherType::Aes256Cbc,
            GroupType::Oakley2,
        )?;
        let nonce: [u8; 32] = random();
        Ok(Self {
            identity,
            crypto,
            initiator: Arc::new(EndpointData {
                cookie: random(),
                nonce: Bytes::copy_from_slice(&nonce),
                ..Default::default()
            }),
            responder: Default::default(),
            session_keys: Default::default(),
            iv: Default::default(),
            sa_bytes: Default::default(),
            esp_in: Default::default(),
            esp_out: Default::default(),
        })
    }

    pub fn init_from_sa(
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

        self.crypto = Crypto::with_parameters(self.identity.clone(), digest, cipher, group)?;

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

    pub fn init_from_ke(&mut self, public_key_r: Bytes, nonce_r: Bytes) -> anyhow::Result<()> {
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
            key_length,
        })
    }

    pub fn init_from_qm(&mut self, proposal: EspProposal) -> anyhow::Result<()> {
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
