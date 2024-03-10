use std::{collections::HashMap, sync::Arc};

use anyhow::anyhow;
use bytes::Bytes;
use parking_lot::RwLock;
use rand::{random, RngCore};

use crate::{
    crypto::{CertData, Crypto},
    model::{EspAuthAlgorithm, EspCryptMaterial, Identity, IkeHashAlgorithm},
    session::IsakmpSession,
};

pub type Ikev1SessionRef = Arc<RwLock<Ikev1Session>>;

pub struct Ikev1Session {
    pub crypto: Crypto,
    pub cookie_i: u64,
    pub cookie_r: u64,
    pub public_key_i: Bytes,
    pub public_key_r: Bytes,
    pub nonce_i: Bytes,
    pub nonce_r: Bytes,
    pub shared_secret: Bytes,
    pub s_key_id: Bytes,
    pub s_key_id_d: Bytes,
    pub s_key_id_a: Bytes,
    pub s_key_id_e: Bytes,
    pub iv: HashMap<u32, Bytes>,
    pub sa_bytes: Bytes,
    pub esp_nonce_i: Bytes,
    pub esp_nonce_r: Bytes,
    pub esp_spi_i: u32,
    pub esp_spi_r: u32,
    pub esp_in: EspCryptMaterial,
    pub esp_out: EspCryptMaterial,
}

impl IsakmpSession for Ikev1Session {
    fn encrypt_and_set_iv(&mut self, data: &[u8], id: u32) -> anyhow::Result<Bytes> {
        let iv = self.retrieve_iv(id);

        let encrypted = self.crypto.encrypt(&self.s_key_id_e, data, &iv)?;

        self.iv.insert(
            id,
            Bytes::copy_from_slice(&encrypted[encrypted.len() - self.crypto.block_size()..]),
        );

        Ok(encrypted)
    }

    fn decrypt_and_set_iv(&mut self, data: &[u8], id: u32) -> anyhow::Result<Bytes> {
        let iv = self.retrieve_iv(id);

        let decrypted = self.crypto.decrypt(&self.s_key_id_e, data, &iv)?;

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
}

impl Ikev1Session {
    pub fn new(identity: Identity) -> anyhow::Result<Ikev1SessionRef> {
        let crypto = Crypto::new(identity)?;
        let public_key_i = crypto.public_key();
        let nonce_i: [u8; 32] = random();
        Ok(Arc::new(RwLock::new(Self {
            crypto,
            cookie_i: rand::thread_rng().next_u64(),
            cookie_r: 0,
            public_key_i,
            public_key_r: Default::default(),
            nonce_i: Bytes::copy_from_slice(&nonce_i),
            nonce_r: Default::default(),
            shared_secret: Default::default(),
            s_key_id: Default::default(),
            s_key_id_d: Default::default(),
            s_key_id_a: Default::default(),
            s_key_id_e: Default::default(),
            iv: Default::default(),
            sa_bytes: Default::default(),
            esp_nonce_i: Bytes::copy_from_slice(&nonce_i),
            esp_nonce_r: Default::default(),
            esp_spi_i: 0,
            esp_spi_r: 0,
            esp_in: Default::default(),
            esp_out: Default::default(),
        })))
    }

    pub fn init_from_sa(
        &mut self,
        cookie_r: u64,
        sa_bytes: Bytes,
        hash_alg: IkeHashAlgorithm,
        key_len: usize,
    ) -> anyhow::Result<()> {
        self.cookie_r = cookie_r;
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
        self.public_key_r = public_key_r;
        self.nonce_r = nonce_r;
        self.shared_secret = self.crypto.shared_secret(&self.public_key_r)?;

        let key = self
            .nonce_i
            .iter()
            .chain(self.nonce_r.iter())
            .copied()
            .collect::<Bytes>();

        // RFC2409: SKEYID = prf(Ni_b | Nr_b, g^xy)
        self.s_key_id = self.crypto.prf(&key, [&self.shared_secret])?;

        let mut data = Vec::new();
        let mut seed = Bytes::new();

        // SKEYID_{d,a,e}
        for i in 0..3 {
            seed = self.crypto.prf(
                &self.s_key_id,
                [
                    seed.as_ref(),
                    self.shared_secret.as_ref(),
                    &self.cookie_i.to_be_bytes(),
                    &self.cookie_r.to_be_bytes(),
                    &[i],
                ],
            )?;
            data.extend(&seed);
        }

        let hash_len = self.crypto.hash_len();
        self.s_key_id_d = Bytes::copy_from_slice(&data[0..hash_len]);
        self.s_key_id_a = Bytes::copy_from_slice(&data[hash_len..hash_len * 2]);
        self.s_key_id_e = Bytes::copy_from_slice(&data[hash_len * 2..]);

        if self.s_key_id_e.len() < self.crypto.key_len() {
            let mut data = Vec::new();
            let mut seed = Bytes::from_static(&[0]);
            while data.len() < self.crypto.key_len() {
                seed = self.crypto.prf(&self.s_key_id_e, [seed.as_ref()])?;
                data.extend(&seed);
            }
            data.truncate(self.crypto.key_len());
            self.s_key_id_e = data.into();
        } else {
            self.s_key_id_e.truncate(self.crypto.key_len());
        }

        let mut iv = self.crypto.hash([&self.public_key_i, &self.public_key_r])?;
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
                &self.s_key_id_d,
                [
                    seed.as_ref(),
                    &[3],
                    spi.to_be_bytes().as_slice(),
                    &self.esp_nonce_i,
                    &self.esp_nonce_r,
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
        self.esp_spi_i = spi_i;
        self.esp_spi_r = spi_r;
        self.esp_nonce_i = nonce_i;
        self.esp_nonce_r = nonce_r;
        self.esp_in = self.gen_esp_material(self.esp_spi_i, auth_alg, key_len)?;
        self.esp_out = self.gen_esp_material(self.esp_spi_r, auth_alg, key_len)?;

        Ok(())
    }

    pub fn retrieve_iv(&mut self, message_id: u32) -> Bytes {
        let zero_iv = self.iv[&0].clone();
        self.iv
            .entry(message_id)
            .or_insert_with(|| {
                let mut hash = self
                    .crypto
                    .hash([zero_iv.as_ref(), &message_id.to_be_bytes()])
                    .unwrap();
                hash.truncate(self.crypto.block_size());
                hash
            })
            .clone()
    }

    pub fn hash_i(&self, id_bytes: &[u8]) -> anyhow::Result<Bytes> {
        // RFC2409: HASH_I = prf(SKEYID, g^xi | g^xr | CKY-I | CKY-R | SAi_b | IDii_b )
        self.crypto.prf(
            &self.s_key_id,
            [
                self.public_key_i.as_ref(),
                self.public_key_r.as_ref(),
                &self.cookie_i.to_be_bytes(),
                &self.cookie_r.to_be_bytes(),
                self.sa_bytes.as_ref(),
                id_bytes,
            ],
        )
    }

    pub fn cert_data(&self) -> Option<&CertData> {
        self.crypto.cert_data()
    }
}
