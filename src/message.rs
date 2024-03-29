use std::io::Read;

use bytes::Bytes;

use crate::{
    model::{ExchangeType, IsakmpFlags},
    payload::Payload,
};

pub trait IsakmpMessageCodec {
    fn encode(&mut self, message: &IsakmpMessage) -> Bytes;
    fn decode<R: Read>(&mut self, reader: &mut R) -> anyhow::Result<IsakmpMessage>;
    fn compute_hash(&self, data: &[u8]) -> Bytes;
}

#[derive(Debug, Clone)]
pub struct IsakmpMessage {
    pub cookie_i: u64,
    pub cookie_r: u64,
    pub version: u8,
    pub exchange_type: ExchangeType,
    pub flags: IsakmpFlags,
    pub message_id: u32,
    pub payloads: Vec<Payload>,
}

impl IsakmpMessage {
    pub fn next_payload(&self, index: usize) -> u8 {
        self.payloads
            .get(index)
            .map(|p| p.as_payload_type().into())
            .unwrap_or(0u8)
    }
}
