use bytes::Bytes;

use crate::{
    model::{ExchangeType, IsakmpFlags},
    payload::Payload,
};

pub trait IsakmpMessageCodec {
    fn encode(&mut self, message: &IsakmpMessage) -> Bytes;

    fn decode(&mut self, data: &[u8]) -> anyhow::Result<Option<IsakmpMessage>>;
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
        self.payloads.get(index).map_or(0, |p| p.as_payload_type().into())
    }
}
