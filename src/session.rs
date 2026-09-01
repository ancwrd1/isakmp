use std::{net::Ipv4Addr, sync::Arc};

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::{certs::ClientCertificate, message::IsakmpMessageCodec, model::EspCryptMaterial};

#[derive(Default, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum SessionType {
    #[default]
    Initiator,
    Responder,
}

#[derive(Default, Clone, Serialize, Deserialize)]
pub struct EndpointData {
    pub spi: u64,
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

/// Surface shared by every IKE version. Anything specific to a version's key
/// schedule, message framing or exchange structure belongs on the concrete
/// session type instead (see `Ikev1Session`).
pub trait IsakmpSession {
    fn initiator(&self) -> Arc<EndpointData>;

    fn responder(&self) -> Arc<EndpointData>;

    fn initiator_spi(&self) -> u64 {
        self.initiator().spi
    }

    fn responder_spi(&self) -> u64 {
        self.responder().spi
    }

    fn esp_in(&self) -> Arc<EspCryptMaterial>;

    fn esp_out(&self) -> Arc<EspCryptMaterial>;

    fn client_certificate(&self) -> Option<Arc<dyn ClientCertificate + Send + Sync>>;

    fn load(&self, data: &[u8]) -> anyhow::Result<OfficeMode>;

    fn save(&self, office_mode: &OfficeMode) -> anyhow::Result<Vec<u8>>;

    fn new_codec(&self) -> Box<dyn IsakmpMessageCodec + Send + Sync>;
    fn timestamp(&self) -> u64;
}
