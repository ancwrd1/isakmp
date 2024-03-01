use std::collections::HashMap;

use bytes::Bytes;
use rand::{random, RngCore};

use crate::crypto::Crypto;

#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct EspCryptMaterial {
    pub spi: u32,
    pub sk_e: Bytes,
    pub sk_a: Bytes,
}

pub struct Ikev1Session {
    pub crypto: Crypto,
    pub cookie_i: u64,
    pub cookie_r: u64,
    pub public_key_i: Bytes,
    pub public_key_r: Bytes,
    pub nonce_i: Bytes,
    pub nonce_r: Bytes,
    shared_secret: Bytes,
    s_key_id: Bytes,
    s_key_id_d: Bytes,
    pub s_key_id_a: Bytes,
    pub s_key_id_e: Bytes,
    iv: HashMap<u32, Bytes>,
    sa_bytes: Bytes,
    esp_nonce_i: Bytes,
    esp_nonce_r: Bytes,
    esp_spi_i: u32,
    esp_spi_r: u32,
    pub esp_in: EspCryptMaterial,
    pub esp_out: EspCryptMaterial,
}

impl Ikev1Session {
    pub fn new() -> anyhow::Result<Self> {
        let crypto = Crypto::new()?;
        let public_key_i = crypto.public_key();
        let nonce_i: [u8; 32] = random();
        Ok(Self {
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
        })
    }

    pub fn init_from_sa(&mut self, cookie_r: u64, sa_bytes: Bytes) {
        self.cookie_r = cookie_r;
        self.sa_bytes = sa_bytes;
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

        // RFC2409: SKEYID_d = prf(SKEYID, g^xy | CKY-I | CKY-R | 0)
        self.s_key_id_d = self.crypto.prf(
            &self.s_key_id,
            [
                self.shared_secret.as_ref(),
                &self.cookie_i.to_be_bytes(),
                &self.cookie_r.to_be_bytes(),
                &[0],
            ],
        )?;

        // RFC2409: SKEYID_a = prf(SKEYID, SKEYID_d | g^xy | CKY-I | CKY-R | 1)
        self.s_key_id_a = self.crypto.prf(
            &self.s_key_id,
            [
                self.s_key_id_d.as_ref(),
                self.shared_secret.as_ref(),
                &self.cookie_i.to_be_bytes(),
                &self.cookie_r.to_be_bytes(),
                &[1],
            ],
        )?;

        // RFC2409: SKEYID_e = prf(SKEYID, SKEYID_a | g^xy | CKY-I | CKY-R | 2)
        self.s_key_id_e = self.crypto.prf(
            &self.s_key_id,
            [
                self.s_key_id_a.as_ref(),
                self.shared_secret.as_ref(),
                &self.cookie_i.to_be_bytes(),
                &self.cookie_r.to_be_bytes(),
                &[2],
            ],
        )?;

        let mut iv = self.crypto.hash([&self.public_key_i, &self.public_key_r])?;
        iv.truncate(self.crypto.block_size());

        self.iv.insert(0, iv);

        Ok(())
    }

    fn gen_esp_material(&mut self, spi: u32) -> anyhow::Result<EspCryptMaterial> {
        // SK_e = prf(SKEYID_d, [ g(qm)^xy | ] protocol | SPI | Ni_b | Nr_b)
        let sk_e = self.crypto.prf(
            &self.s_key_id_d,
            [
                &[3],
                spi.to_be_bytes().as_slice(),
                &self.esp_nonce_i,
                &self.esp_nonce_r,
            ],
        )?;

        // SK_a = prf(SKEYID_d, SK_e | [ g(qm)^xy | ] protocol | SPI | Ni_b | Nr_b)
        let sk_a = self.crypto.prf(
            &self.s_key_id_d,
            [
                sk_e.as_ref(),
                &[3],
                spi.to_be_bytes().as_slice(),
                &self.esp_nonce_i,
                &self.esp_nonce_r,
            ],
        )?;

        Ok(EspCryptMaterial { spi, sk_e, sk_a })
    }

    pub fn init_from_qm(
        &mut self,
        spi_i: u32,
        nonce_i: Bytes,
        spi_r: u32,
        nonce_r: Bytes,
    ) -> anyhow::Result<()> {
        self.esp_spi_i = spi_i;
        self.esp_spi_r = spi_r;
        self.esp_nonce_i = nonce_i;
        self.esp_nonce_r = nonce_r;
        self.esp_in = self.gen_esp_material(self.esp_spi_i)?;
        self.esp_out = self.gen_esp_material(self.esp_spi_r)?;

        Ok(())
    }

    fn retrieve_iv(&mut self, message_id: u32) -> Bytes {
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

    pub fn encrypt_and_set_iv(&mut self, data: &[u8], message_id: u32) -> anyhow::Result<Bytes> {
        let iv = self.retrieve_iv(message_id);

        let encrypted = self.crypto.encrypt(&self.s_key_id_e, data, &iv)?;

        self.iv.insert(
            message_id,
            Bytes::copy_from_slice(&encrypted[encrypted.len() - self.crypto.block_size()..]),
        );

        Ok(encrypted)
    }

    pub fn decrypt_and_set_iv(&mut self, data: &[u8], message_id: u32) -> anyhow::Result<Bytes> {
        let iv = self.retrieve_iv(message_id);

        let decrypted = self.crypto.decrypt(&self.s_key_id_e, data, &iv)?;

        self.iv.insert(
            message_id,
            Bytes::copy_from_slice(&data[data.len() - self.crypto.block_size()..]),
        );

        Ok(decrypted)
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
}
