use std::{collections::HashMap, sync::Arc};

use anyhow::anyhow;
use bytes::Bytes;
use parking_lot::RwLock;
use rand::random;

use crate::{
    crypto::{ClientCertificate, Crypto},
    model::{EspAuthAlgorithm, EspCryptMaterial, Identity, IkeHashAlgorithm},
    session::{EndpointData, IsakmpSession, SessionKeys},
};

pub(crate) type Ikev1SessionRef = Arc<RwLock<Ikev1Session>>;

#[derive(Clone)]
pub struct Ikev1SyncedSession(pub(crate) Ikev1SessionRef);

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
    ) -> anyhow::Result<()> {
        self.0.write().init_from_sa(cookie_r, sa_bytes, hash_alg, key_len)
    }

    pub fn init_from_ke(&mut self, public_key_r: Bytes, nonce_r: Bytes) -> anyhow::Result<()> {
        self.0.write().init_from_ke(public_key_r, nonce_r)
    }

    pub fn init_from_qm(
        &mut self,
        spi_i: u32,
        nonce_i: Bytes,
        spi_r: u32,
        nonce_r: Bytes,
        auth_alg: EspAuthAlgorithm,
        key_len: usize,
    ) -> anyhow::Result<()> {
        self.0
            .write()
            .init_from_qm(spi_i, nonce_i, spi_r, nonce_r, auth_alg, key_len)
    }
}

impl IsakmpSession for Ikev1SyncedSession {
    fn cookie_i(&self) -> u64 {
        self.0.read().cookie_i()
    }

    fn cookie_r(&self) -> u64 {
        self.0.read().cookie_r()
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

    fn hash<T, I>(&self, data: I) -> anyhow::Result<Bytes>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        self.0.read().hash(data)
    }

    fn esp_in(&self) -> Arc<EspCryptMaterial> {
        self.0.read().esp_in()
    }

    fn esp_out(&self) -> Arc<EspCryptMaterial> {
        self.0.read().esp_out()
    }

    fn client_certificate(&self) -> Option<Arc<ClientCertificate>> {
        self.0.read().client_certificate()
    }
}

pub(crate) struct Ikev1Session {
    pub(crate) crypto: Crypto,
    pub(crate) initiator: EndpointData,
    pub(crate) responder: EndpointData,
    pub(crate) session_keys: SessionKeys,
    pub(crate) iv: HashMap<u32, Bytes>,
    pub(crate) sa_bytes: Bytes,
    pub(crate) esp_in: Arc<EspCryptMaterial>,
    pub(crate) esp_out: Arc<EspCryptMaterial>,
}

impl IsakmpSession for Ikev1Session {
    fn cookie_i(&self) -> u64 {
        self.initiator.cookie
    }

    fn cookie_r(&self) -> u64 {
        self.responder.cookie
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

    fn hash<T, I>(&self, data: I) -> anyhow::Result<Bytes>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        self.crypto.hash(data)
    }

    fn esp_in(&self) -> Arc<EspCryptMaterial> {
        self.esp_in.clone()
    }

    fn esp_out(&self) -> Arc<EspCryptMaterial> {
        self.esp_out.clone()
    }

    fn client_certificate(&self) -> Option<Arc<ClientCertificate>> {
        self.crypto.client_certificate()
    }
}

impl Ikev1Session {
    fn new(identity: Identity) -> anyhow::Result<Self> {
        let crypto = Crypto::new(identity)?;
        let public_key = crypto.public_key();
        let nonce: [u8; 32] = random();
        Ok(Self {
            crypto,
            initiator: EndpointData {
                cookie: random(),
                public_key,
                nonce: Bytes::copy_from_slice(&nonce),
                ..Default::default()
            },
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
    ) -> anyhow::Result<()> {
        self.responder.cookie = cookie_r;
        self.sa_bytes = sa_bytes;

        self.crypto.init_cipher(key_len);

        match hash_alg {
            IkeHashAlgorithm::Sha => self.crypto.init_sha1(),
            IkeHashAlgorithm::Sha256 => self.crypto.init_sha256(),
            _ => return Err(anyhow!("Unsupported hash algorithm: {:?}", hash_alg)),
        }
        Ok(())
    }

    pub fn init_from_ke(&mut self, public_key_r: Bytes, nonce_r: Bytes) -> anyhow::Result<()> {
        self.responder.public_key = public_key_r;
        self.responder.nonce = nonce_r;
        self.session_keys.shared_secret = self.crypto.shared_secret(&self.responder.public_key)?;

        let key = self
            .initiator
            .nonce
            .iter()
            .chain(self.responder.nonce.iter())
            .copied()
            .collect::<Bytes>();

        // RFC2409: SKEYID = prf(Ni_b | Nr_b, g^xy)
        self.session_keys.skeyid = self.crypto.prf(&key, [&self.session_keys.shared_secret])?;

        let mut data = Vec::new();
        let mut seed = Bytes::new();

        // SKEYID_{d,a,e}
        for i in 0..3 {
            seed = self.crypto.prf(
                &self.session_keys.skeyid,
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
        self.session_keys.skeyid_d = Bytes::copy_from_slice(&data[0..hash_len]);
        self.session_keys.skeyid_a = Bytes::copy_from_slice(&data[hash_len..hash_len * 2]);
        self.session_keys.skeyid_e = Bytes::copy_from_slice(&data[hash_len * 2..]);

        if self.session_keys.skeyid_e.len() < self.crypto.key_len() {
            let mut data = Vec::new();
            let mut seed = Bytes::from_static(&[0]);
            while data.len() < self.crypto.key_len() {
                seed = self.crypto.prf(&self.session_keys.skeyid_e, [seed.as_ref()])?;
                data.extend(&seed);
            }
            data.truncate(self.crypto.key_len());
            self.session_keys.skeyid_e = data.into();
        } else {
            self.session_keys.skeyid_e.truncate(self.crypto.key_len());
        }

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
        auth_algorithm: EspAuthAlgorithm,
        key_length: usize,
    ) -> anyhow::Result<EspCryptMaterial> {
        let keymat_len = key_length + auth_algorithm.hash_len();

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
            auth_algorithm,
        })
    }

    pub fn init_from_qm(
        &mut self,
        spi_i: u32,
        nonce_i: Bytes,
        spi_r: u32,
        nonce_r: Bytes,
        auth_alg: EspAuthAlgorithm,
        key_len: usize,
    ) -> anyhow::Result<()> {
        self.initiator.esp_spi = spi_i;
        self.responder.esp_spi = spi_r;
        self.initiator.esp_nonce = nonce_i;
        self.responder.esp_nonce = nonce_r;
        self.esp_in = Arc::new(self.gen_esp_material(self.initiator.esp_spi, auth_alg, key_len)?);
        self.esp_out = Arc::new(self.gen_esp_material(self.responder.esp_spi, auth_alg, key_len)?);

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

    pub fn hash_i(&self, id_bytes: &[u8]) -> anyhow::Result<Bytes> {
        // RFC2409: HASH_I = prf(SKEYID, g^xi | g^xr | CKY-I | CKY-R | SAi_b | IDii_b )
        self.crypto.prf(
            &self.session_keys.skeyid,
            [
                self.initiator.public_key.as_ref(),
                self.responder.public_key.as_ref(),
                &self.initiator.cookie.to_be_bytes(),
                &self.responder.cookie.to_be_bytes(),
                self.sa_bytes.as_ref(),
                id_bytes,
            ],
        )
    }
}
