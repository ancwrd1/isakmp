use std::io::{Cursor, Read};

use byteorder::{BigEndian, ReadBytesExt};
use bytes::{BufMut, Bytes, BytesMut};
use tracing::trace;

use crate::{
    message::{IsakmpMessage, IsakmpMessageCodec},
    model::{ExchangeType, IsakmpFlags, PayloadType},
    payload::Payload,
    session::IsakmpSession,
};

pub struct Ikev1Codec {
    session: Box<dyn IsakmpSession + Send + Sync>,
}

impl Ikev1Codec {
    pub fn new(session: Box<dyn IsakmpSession + Send + Sync>) -> Self {
        Self { session }
    }
}

impl IsakmpMessageCodec for Ikev1Codec {
    fn encode(&mut self, message: &IsakmpMessage) -> Bytes {
        let mut payload_buf = BytesMut::new();
        for (i, payload) in message.payloads.iter().enumerate() {
            payload_buf.put_u8(message.next_payload(i + 1));
            payload_buf.put_u8(0);
            let data = payload.to_bytes();
            payload_buf.put_u16(4 + data.len() as u16);
            payload_buf.put_slice(&data);
        }

        let payload = if message.flags.contains(IsakmpFlags::ENCRYPTION) {
            let block_size = self.session.cipher_block_size();
            let pad_len = block_size - ((payload_buf.len() + 1) % block_size);
            payload_buf.extend(std::iter::repeat_n(0, pad_len));
            payload_buf.put_u8(pad_len as u8);

            self.session
                .encrypt_and_set_iv(&payload_buf.freeze(), message.message_id)
                .unwrap_or_default()
        } else {
            payload_buf.freeze()
        };

        let mut buf = BytesMut::new();
        buf.put_u64(message.cookie_i);
        buf.put_u64(message.cookie_r);

        buf.put_u8(message.next_payload(0));
        buf.put_u8(0x10);
        buf.put_u8(message.exchange_type.into());
        buf.put_u8(message.flags.bits());
        buf.put_u32(message.message_id);
        buf.put_u32(28 + payload.len() as u32);
        buf.put_slice(&payload);

        buf.freeze()
    }

    fn decode(&mut self, data: &[u8]) -> anyhow::Result<Option<IsakmpMessage>> {
        if !self.session.validate_message(data) {
            trace!("Discarding duplicate message");
            return Ok(None);
        }

        let mut reader = Cursor::new(data);

        let cookie_i = reader.read_u64::<BigEndian>()?;
        let cookie_r = reader.read_u64::<BigEndian>()?;

        let next_payload: PayloadType = reader.read_u8()?.into();
        let version = reader.read_u8()?;
        let exchange_type: ExchangeType = reader.read_u8()?.into();
        let flags: IsakmpFlags = IsakmpFlags::from_bits_retain(reader.read_u8()?);
        let message_id = reader.read_u32::<BigEndian>()?;
        let length = reader.read_u32::<BigEndian>()?;

        let mut data = vec![0u8; length as usize - 28];
        reader.read_exact(&mut data)?;

        if flags.contains(IsakmpFlags::ENCRYPTION) {
            data = self.session.decrypt_and_set_iv(&data, message_id)?.to_vec();
        }

        let mut cursor = Cursor::new(data);

        let payloads = Payload::parse_all(next_payload, &mut cursor)?;

        Ok(Some(IsakmpMessage {
            cookie_i,
            cookie_r,
            version,
            exchange_type,
            flags,
            message_id,
            payloads,
        }))
    }
}
