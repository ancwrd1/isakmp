use std::io::{Cursor, Read};

use byteorder::{BigEndian, ReadBytesExt};
use bytes::{BufMut, Bytes, BytesMut};
use tracing::trace;

use crate::{
    ikev1::session::Ikev1Session,
    message::{IsakmpMessage, IsakmpMessageCodec},
    model::{ExchangeType, IsakmpFlags, PayloadType},
    payload::Payload,
};

pub struct Ikev1Codec {
    session: Ikev1Session,
}

impl Ikev1Codec {
    pub fn new(session: Ikev1Session) -> Self {
        Self { session }
    }
}

impl IsakmpMessageCodec for Ikev1Codec {
    fn encode(&mut self, message: &IsakmpMessage) -> anyhow::Result<Bytes> {
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
            let pad_len = (block_size - ((payload_buf.len() + 1) % block_size)) % block_size;
            payload_buf.extend(1..=pad_len as u8);
            payload_buf.put_u8(pad_len as u8);

            self.session
                .encrypt_and_set_iv(&payload_buf.freeze(), message.message_id)?
        } else {
            payload_buf.freeze()
        };

        let mut buf = BytesMut::new();
        buf.put_u64(message.initiator_spi);
        buf.put_u64(message.responder_spi);

        buf.put_u8(message.next_payload(0));
        buf.put_u8(0x10);
        buf.put_u8(message.exchange_type.into());
        buf.put_u8(message.flags.bits());
        buf.put_u32(message.message_id);
        buf.put_u32(28 + payload.len() as u32);
        buf.put_slice(&payload);

        Ok(buf.freeze())
    }

    fn decode(&mut self, data: &[u8]) -> anyhow::Result<Option<IsakmpMessage>> {
        if !self.session.validate_message(data)? {
            trace!("Discarding duplicate message");
            return Ok(None);
        }

        let mut reader = Cursor::new(data);

        let spi_i = reader.read_u64::<BigEndian>()?;
        let spi_r = reader.read_u64::<BigEndian>()?;

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
            initiator_spi: spi_i,
            responder_spi: spi_r,
            version,
            exchange_type,
            flags,
            message_id,
            payloads,
        }))
    }
}
