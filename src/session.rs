use std::{net::Ipv4Addr, sync::Arc};

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::{
    certs::ClientCertificate,
    message::IsakmpMessageCodec,
    model::{EspCryptMaterial, EspProposal, SaProposal},
};

#[derive(Default, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum SessionType {
    #[default]
    Initiator,
    Responder,
}

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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OfficeMode {
    pub ccc_session: String,
    pub username: String,
    pub ip_address: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub dns: Vec<Ipv4Addr>,
    pub domains: Vec<String>,
}

pub trait IsakmpSession {
    fn init_from_sa(&mut self, proposal: SaProposal) -> anyhow::Result<()>;

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

    fn load(&mut self, data: &[u8]) -> anyhow::Result<OfficeMode>;

    fn save(&self, office_mode: &OfficeMode) -> anyhow::Result<Vec<u8>>;

    fn new_codec(&self) -> Box<dyn IsakmpMessageCodec + Send + Sync>;
}
