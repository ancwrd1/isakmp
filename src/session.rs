use crate::crypto::ClientCertificate;
use bytes::Bytes;
use std::sync::Arc;

use crate::model::EspCryptMaterial;

#[derive(Default)]
pub struct SessionKeys {
    pub shared_secret: Bytes,
    pub skeyid: Bytes,
    pub skeyid_d: Bytes,
    pub skeyid_a: Bytes,
    pub skeyid_e: Bytes,
}

#[derive(Default)]
pub struct EndpointData {
    pub cookie: u64,
    pub public_key: Bytes,
    pub nonce: Bytes,
    pub esp_nonce: Bytes,
    pub esp_spi: u32,
}

pub trait IsakmpSession {
    fn cookie_i(&self) -> u64;
    fn cookie_r(&self) -> u64;
    fn encrypt_and_set_iv(&mut self, data: &[u8], id: u32) -> anyhow::Result<Bytes>;
    fn decrypt_and_set_iv(&mut self, data: &[u8], id: u32) -> anyhow::Result<Bytes>;
    fn cipher_block_size(&self) -> usize;
    fn hash<T, I>(&self, data: I) -> anyhow::Result<Bytes>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>;
    fn esp_in(&self) -> Arc<EspCryptMaterial>;
    fn esp_out(&self) -> Arc<EspCryptMaterial>;
    fn client_certificate(&self) -> Option<Arc<ClientCertificate>>;
}
