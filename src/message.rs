use std::io::{Cursor, Read};

use byteorder::{BigEndian, ReadBytesExt};
use bytes::{BufMut, Bytes, BytesMut};

use crate::{
    model::{ExchangeType, IsakmpFlags, PayloadType},
    payload::Payload,
    session::Ikev1Session,
};

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
    fn next_payload(&self, index: usize) -> u8 {
        self.payloads
            .get(index)
            .map(|p| p.as_payload_type().into())
            .unwrap_or(0u8)
    }

    pub fn to_bytes(&self, session: &mut Ikev1Session) -> Bytes {
        let mut payload_buf = BytesMut::new();
        for (i, payload) in self.payloads.iter().enumerate() {
            payload_buf.put_u8(self.next_payload(i + 1));
            payload_buf.put_u8(0);
            let data = payload.to_bytes();
            payload_buf.put_u16(4 + data.len() as u16);
            payload_buf.put_slice(&data);
        }

        let payload = if self.flags.contains(IsakmpFlags::ENCRYPTION) {
            let n = payload_buf.len();
            let m = session.crypto.block_size();
            let padlen = m - ((n + 1) % m);
            for _ in 0..padlen {
                payload_buf.put_u8(0);
            }
            payload_buf.put_u8(padlen as u8);
            session
                .encrypt_and_set_iv(&payload_buf.freeze(), self.message_id)
                .unwrap_or_default()
        } else {
            payload_buf.freeze()
        };

        let mut buf = BytesMut::new();
        buf.put_u64(self.cookie_i);
        buf.put_u64(self.cookie_r);

        buf.put_u8(self.next_payload(0));
        buf.put_u8(0x10);
        buf.put_u8(self.exchange_type.into());
        buf.put_u8(self.flags.bits());
        buf.put_u32(self.message_id);
        buf.put_u32(28 + payload.len() as u32);
        buf.put_slice(&payload);

        buf.freeze()
    }

    pub fn parse<R: Read>(reader: &mut R, session: &mut Ikev1Session) -> anyhow::Result<Self> {
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
            data = session.decrypt_and_set_iv(&data, message_id)?.to_vec();
        }

        let mut cursor = Cursor::new(data);

        let payloads = Payload::parse_all(next_payload, &mut cursor)?;

        Ok(Self {
            cookie_i,
            cookie_r,
            version,
            exchange_type,
            flags,
            message_id,
            payloads,
        })
    }
}
