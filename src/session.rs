use std::sync::Arc;

use crate::{
    certs::ClientCertificate,
    model::{EspCryptMaterial, EspProposal, IkeGroupDescription, IkeHashAlgorithm},
};
use bytes::Bytes;
use serde::{Deserialize, Serialize};

#[derive(Default, Clone, Serialize, Deserialize)]
pub struct SessionKeys {
    pub shared_secret: Bytes,
    pub skeyid: Bytes,
    pub skeyid_d: Bytes,
    pub skeyid_a: Bytes,
    pub skeyid_e: Bytes,
}

#[derive(Default, Clone, Serialize, Deserialize)]
pub struct EndpointData {
    pub cookie: u64,
    pub public_key: Bytes,
    pub nonce: Bytes,
    pub esp_nonce: Bytes,
    pub esp_spi: u32,
}

pub trait IsakmpSession {
    fn init_from_sa(
        &mut self,
        cookie_r: u64,
        sa_bytes: Bytes,
        hash_alg: IkeHashAlgorithm,
        key_len: usize,
        group: IkeGroupDescription,
    ) -> anyhow::Result<()>;

    fn init_from_ke(&mut self, public_key_r: Bytes, nonce_r: Bytes) -> anyhow::Result<()>;

    fn init_from_qm(&mut self, proposal: EspProposal) -> anyhow::Result<()>;

    fn cookie_i(&self) -> u64 {
        self.initiator().cookie
    }

    fn cookie_r(&self) -> u64 {
        self.responder().cookie
    }

    fn encrypt_and_set_iv(&mut self, data: &[u8], id: u32) -> anyhow::Result<Bytes>;

    fn decrypt_and_set_iv(&mut self, data: &[u8], id: u32) -> anyhow::Result<Bytes>;

    fn cipher_block_size(&self) -> usize;

    fn validate_message(&mut self, data: &[u8]) -> bool;

    fn hash(&self, data: &[&[u8]]) -> anyhow::Result<Bytes>;

    fn hash_id_i(&self, data: &[u8]) -> anyhow::Result<Bytes>;

    fn hash_id_r(&self, data: &[u8]) -> anyhow::Result<Bytes>;

    fn verify_signature(&self, hash: &[u8], signature: &[u8], cert: &[u8]) -> anyhow::Result<()>;

    fn prf(&self, key: &[u8], data: &[&[u8]]) -> anyhow::Result<Bytes>;

    fn esp_in(&self) -> Arc<EspCryptMaterial>;

    fn esp_out(&self) -> Arc<EspCryptMaterial>;

    fn client_certificate(&self) -> Option<Arc<dyn ClientCertificate + Send + Sync>>;

    fn initiator(&self) -> Arc<EndpointData>;

    fn responder(&self) -> Arc<EndpointData>;

    fn session_keys(&self) -> Arc<SessionKeys>;

    fn load(&mut self, data: &[u8]) -> anyhow::Result<()>;

    fn save(&self) -> anyhow::Result<Vec<u8>>;
}
